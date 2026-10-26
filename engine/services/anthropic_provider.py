"""Native Anthropic Messages API adapter for Arbalest BYOK deployments."""

from __future__ import annotations

import asyncio
import json
import os
import re
from collections.abc import Sequence
from typing import Any

import httpx

from engine.services.ai_provider import (
    AIModelInfo,
    AIProvider,
    AIProviderError,
    AIProviderRefusal,
    AIProviderSettings,
    StructuredOutputRequest,
    ToolDefinition,
    ToolExecutor,
    _effective_max_output_tokens,
    _request_timeout,
    _safe_error,
)
from engine.services.provider_catalog import ProviderCatalogError, ProviderProtocol, get_provider_spec

_ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1/"
_API_VERSION = "2023-06-01"
_FINAL_TOOL = "arbalest_submit_result"
_REFUSAL = re.compile(r"(?i)\b(?:cannot|can't|unable to|won't)\s+(?:assist|comply|help|provide)\b")


class AnthropicMessagesProvider(AIProvider):
    """Use forced tool output for schemas and bounded client-tool loops."""

    def __init__(self, settings: AIProviderSettings) -> None:
        try:
            spec = get_provider_spec(settings.provider)
        except ProviderCatalogError as exc:
            raise ValueError(str(exc)) from exc
        if spec.protocol is not ProviderProtocol.ANTHROPIC:
            raise ValueError(f"AnthropicMessagesProvider does not support provider='{settings.provider}'")
        self._settings = settings
        env_url = os.environ.get(spec.base_url_env, "").strip() if spec.base_url_env else ""
        base_url = settings.base_url or env_url or spec.base_url or _ANTHROPIC_BASE_URL
        if spec.base_url_required and not (settings.base_url or env_url):
            raise ValueError(f"{settings.provider} provider requires {spec.base_url_env or 'an api_url'}")
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={
                "x-api-key": settings.api_key.get_secret_value(),
                "anthropic-version": _API_VERSION,
                "content-type": "application/json",
            },
            timeout=httpx.Timeout(_request_timeout()),
            follow_redirects=False,
        )

    @property
    def name(self) -> str:
        return self._settings.provider

    @property
    def settings(self) -> AIProviderSettings:
        return self._settings

    async def list_models(self) -> list[AIModelInfo]:
        payload = await self._request("GET", "models")
        rows = payload.get("data", [])
        if not isinstance(rows, list):
            raise AIProviderError("Anthropic model discovery returned an invalid response")
        models: list[AIModelInfo] = []
        for row in rows[:1_000]:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                continue
            model_id = row["id"]
            display = row.get("display_name") if isinstance(row.get("display_name"), str) else model_id
            models.append(AIModelInfo(
                id=model_id,
                display_name=display,
                supports_structured_output=None,
                supports_function_calling=True,
                default_temperature=0.2,
                max_output_tokens=None,
            ))
        return sorted(models, key=lambda model: model.id)

    async def generate_structured(self, request: StructuredOutputRequest) -> str:
        result_tool = {
            "name": _FINAL_TOOL,
            "description": "Submit the final JSON object matching the required schema.",
            "input_schema": request.json_schema,
        }
        payload = await self._request("POST", "messages", json={
            "model": self._selected_model(),
            "max_tokens": _effective_max_output_tokens(request.max_output_tokens, self._settings.max_output_tokens),
            "temperature": self._settings.temperature,
            "system": request.instructions,
            "messages": [{"role": "user", "content": request.input_text}],
            "tools": [result_tool],
            "tool_choice": {"type": "tool", "name": _FINAL_TOOL},
        })
        return self._extract_final_tool(payload)

    async def run_with_tools(
        self,
        request: StructuredOutputRequest,
        *,
        tools: Sequence[ToolDefinition],
        execute_tool: ToolExecutor,
        max_turns: int,
        require_initial_tool_call: bool,
    ) -> str:
        if max_turns < 1:
            raise ValueError("max_turns must be positive")
        anthropic_tools = [
            {"name": tool.name, "description": tool.description, "input_schema": tool.parameters}
            for tool in tools
        ]
        anthropic_tools.append({
            "name": _FINAL_TOOL,
            "description": "Submit the final JSON object after all required tool calls.",
            "input_schema": request.json_schema,
        })
        messages: list[dict[str, Any]] = [{"role": "user", "content": request.input_text}]
        called_regular_tool = False
        total_calls = 0

        for turn in range(max_turns):
            body: dict[str, Any] = {
                "model": self._selected_model(),
                "max_tokens": _effective_max_output_tokens(request.max_output_tokens, self._settings.max_output_tokens),
                "temperature": self._settings.temperature,
                "system": request.instructions + "\nFinish by calling arbalest_submit_result with the required JSON object.",
                "messages": messages,
                "tools": anthropic_tools,
                "tool_choice": {"type": "any"} if require_initial_tool_call and turn == 0 else {"type": "auto"},
            }
            response = await self._request("POST", "messages", json=body)
            content = response.get("content", [])
            if not isinstance(content, list):
                raise AIProviderError("Anthropic returned invalid message content")
            tool_calls = [block for block in content if isinstance(block, dict) and block.get("type") == "tool_use"]
            final_calls = [block for block in tool_calls if block.get("name") == _FINAL_TOOL]
            regular_calls = [block for block in tool_calls if block.get("name") != _FINAL_TOOL]
            if final_calls:
                if regular_calls or len(final_calls) != 1:
                    raise AIProviderError("Anthropic mixed final output with executable tool calls")
                if require_initial_tool_call and not called_regular_tool:
                    raise AIProviderError("Anthropic did not issue the required initial external tool call")
                return self._validate_final_input(final_calls[0])
            if not regular_calls:
                stop_reason = str(response.get("stop_reason", ""))
                text = "\n".join(
                    str(block.get("text", "")) for block in content
                    if isinstance(block, dict) and block.get("type") == "text"
                ).strip()
                if stop_reason == "max_tokens":
                    raise AIProviderError("Anthropic response reached its output-token limit")
                if _REFUSAL.search(text):
                    raise AIProviderRefusal("The Anthropic model declined the request")
                if text:
                    return text
                raise AIProviderError("Anthropic returned no final structured output")
            if turn == max_turns - 1:
                raise AIProviderError("Anthropic model exceeded the configured tool-call turn limit")
            total_calls += len(regular_calls)
            if total_calls > 64:
                raise AIProviderError("Anthropic model exceeded the local tool-call limit")

            tool_results: list[dict[str, Any]] = []
            for call in regular_calls:
                call_id = call.get("id")
                name = call.get("name")
                arguments = call.get("input")
                if not isinstance(call_id, str) or not isinstance(name, str) or not isinstance(arguments, dict):
                    raise AIProviderError("Anthropic returned an invalid tool-use block")
                called_regular_tool = True
                try:
                    result = await execute_tool(name, arguments)
                    content_text = json.dumps(result, separators=(",", ":"), default=str)
                    is_error = False
                except Exception as exc:
                    content_text = json.dumps({"ok": False, "error": _safe_error(exc)}, separators=(",", ":"))
                    is_error = True
                tool_results.append({
                    "type": "tool_result", "tool_use_id": call_id,
                    "content": content_text[:64_000], "is_error": is_error,
                })
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": tool_results})
        raise AssertionError("unreachable")

    def _extract_final_tool(self, payload: dict[str, Any]) -> str:
        content = payload.get("content", [])
        if not isinstance(content, list):
            raise AIProviderError("Anthropic returned invalid message content")
        matches = [
            block for block in content
            if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == _FINAL_TOOL
        ]
        if len(matches) != 1:
            text = " ".join(
                str(block.get("text", "")) for block in content if isinstance(block, dict) and block.get("type") == "text"
            )
            if _REFUSAL.search(text):
                raise AIProviderRefusal("The Anthropic model declined the request")
            raise AIProviderError("Anthropic did not return the required structured result tool")
        return self._validate_final_input(matches[0])

    @staticmethod
    def _validate_final_input(block: dict[str, Any]) -> str:
        value = block.get("input")
        if not isinstance(value, dict):
            raise AIProviderError("Anthropic structured result was not a JSON object")
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        last_error = "request failed"
        for attempt in range(5):
            try:
                response = await self._client.request(method, path, **kwargs)
            except httpx.TransportError as exc:
                last_error = _safe_error(exc)
            else:
                if response.status_code < 400:
                    try:
                        payload = response.json()
                    except ValueError as exc:
                        raise AIProviderError("Anthropic returned invalid JSON") from exc
                    if not isinstance(payload, dict):
                        raise AIProviderError("Anthropic returned an invalid response object")
                    return payload
                if response.status_code in (401, 403):
                    raise AIProviderError("Anthropic rejected the configured API key")
                if response.status_code == 429 or response.status_code >= 500:
                    last_error = f"HTTP {response.status_code}"
                else:
                    request_id = response.headers.get("request-id", "")[:128]
                    raise AIProviderError(f"Anthropic request was rejected (HTTP {response.status_code}, request {request_id or 'unknown'})")
            if attempt < 4:
                await asyncio.sleep(min(2.0 * (2**attempt), 16.0))
        raise AIProviderError(f"Anthropic request exhausted retries ({last_error})")

    def _selected_model(self) -> str:
        if not self._settings.selected_model:
            raise AIProviderError("No Anthropic model is selected for this workspace")
        return self._settings.selected_model

    async def aclose(self) -> None:
        await self._client.aclose()


__all__ = ["AnthropicMessagesProvider"]
