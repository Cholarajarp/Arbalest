"""Provider-neutral AI boundary for Arbalest agents.

Only this module knows provider SDKs or REST APIs.  Agents use ``AIProvider``
and are therefore independent of the underlying inference endpoint.
"""

from __future__ import annotations

import abc
import asyncio
import json
import os
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from enum import StrEnum
from typing import Any

from openai import APIConnectionError, APIError, APITimeoutError, AsyncOpenAI, InternalServerError, RateLimitError
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class AIProviderName(StrEnum):
    CUSTOM = "custom"
    NEBIUS = "nebius"


class AIProviderError(RuntimeError):
    """A provider request failed without exposing credentials or raw vendor data."""


class AIModelInfo(BaseModel):
    """A model currently visible to the caller's API key."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=256)
    display_name: str = Field(min_length=1, max_length=256)
    supports_structured_output: bool | None = None
    supports_function_calling: bool | None = None
    reasoning_efforts: tuple[str, ...] = ()
    default_temperature: float | None = None
    max_output_tokens: int | None = None


class AIProviderSettings(BaseModel):
    """Workspace-scoped BYOK configuration; secrets are never logged or returned."""

    model_config = ConfigDict(extra="forbid")

    provider: str = AIProviderName.CUSTOM.value
    api_key: SecretStr = Field(min_length=8, max_length=512)
    selected_model: str | None = Field(default=None, min_length=1, max_length=256)
    reasoning_effort: str | None = Field(default=None, min_length=1, max_length=32)
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    max_output_tokens: int = Field(default=16_000, ge=256, le=65_536)
    streaming: bool = False

    @field_validator("reasoning_effort")
    @classmethod
    def normalize_reasoning_effort(cls, value: str | None) -> str | None:
        return value.strip().lower() if value else None

    @field_validator("provider")
    @classmethod
    def normalize_provider(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", normalized):
            raise ValueError("provider must be a lowercase provider identifier")
        return normalized


class StructuredOutputRequest(BaseModel):
    """Provider-neutral request for one JSON object matching a JSON Schema."""

    model_config = ConfigDict(extra="forbid")

    instructions: str = Field(min_length=1, max_length=32_000)
    input_text: str = Field(min_length=1, max_length=512_000)
    schema_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
    json_schema: dict[str, Any]
    max_output_tokens: int | None = Field(default=None, ge=256, le=65_536)


class ToolDefinition(BaseModel):
    """Portable function declaration. Parameters must be an object schema."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
    description: str = Field(min_length=1, max_length=2_000)
    parameters: dict[str, Any]


ToolExecutor = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


class AIProvider(abc.ABC):
    """Stable abstraction implemented once per supported AI provider."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Provider identifier used in workspace configuration."""

    @property
    @abc.abstractmethod
    def settings(self) -> AIProviderSettings:
        """Effective provider settings (the API key remains a SecretStr)."""

    @abc.abstractmethod
    async def list_models(self) -> list[AIModelInfo]:
        """Retrieve models available to the workspace's API key."""

    @abc.abstractmethod
    async def generate_structured(self, request: StructuredOutputRequest) -> str:
        """Generate a JSON string constrained by ``request.json_schema``."""

    @abc.abstractmethod
    async def run_with_tools(
        self,
        request: StructuredOutputRequest,
        *,
        tools: Sequence[ToolDefinition],
        execute_tool: ToolExecutor,
        max_turns: int,
        require_initial_tool_call: bool,
    ) -> str:
        """Execute a bounded function-calling loop and return final JSON text."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Release provider network resources."""

    def recommended_model_id(self, models: Sequence[AIModelInfo]) -> str | None:
        """Return a recommendation only when it exists in the dynamic model list."""
        return None


class CustomOpenAICompatibleProvider(AIProvider):
    """OpenAI-compatible adapter with a Chat Completions path.

    Nebius Token Factory exposes an OpenAI-compatible endpoint that does not
    implement the Responses API. Keeping that transport choice inside this
    adapter lets agents retain the same provider-neutral contract. The
    ``custom`` provider targets any user-supplied OpenAI-compatible endpoint
    via ``AI_BASE_URL``.
    """

    def __init__(self, settings: AIProviderSettings) -> None:
        self._settings = settings
        if settings.provider == AIProviderName.NEBIUS.value:
            base_url = "https://api.studio.nebius.ai/v1"
        elif settings.provider == AIProviderName.CUSTOM.value:
            base_url = None  # Requires AI_BASE_URL to be set by the user
        else:
            raise ValueError(f"CustomOpenAICompatibleProvider does not support provider='{settings.provider}'")
        self._client = AsyncOpenAI(
            base_url=os.environ.get("AI_BASE_URL", base_url),
            api_key=settings.api_key.get_secret_value(),
            timeout=60.0,
            max_retries=0,
        )

    @property
    def name(self) -> str:
        return self._settings.provider

    @property
    def settings(self) -> AIProviderSettings:
        return self._settings

    async def list_models(self) -> list[AIModelInfo]:
        try:
            page = await self._client.models.list()
        except (APIError, Exception) as exc:
            raise AIProviderError(f"{self.name} model discovery failed: {_safe_error(exc)}") from exc
        models: list[AIModelInfo] = []
        for item in page.data:
            model_id = str(item.id)
            model_lower = model_id.lower()
            if _is_ineligible_compatible_model(self.name, model_lower):
                continue
            # The OpenAI-compatible model-list API does not disclose output
            # limits, so expose conservative defaults for the Control Center.
            tokens = 16_384 if "gpt-4o" in model_lower or "gpt-5" in model_lower else 8_192
            if "llama" in model_lower or "mixtral" in model_lower:
                tokens = 8_192
            models.append(
                AIModelInfo(
                    id=model_id,
                    display_name=model_id,
                    # The list endpoint does not advertise these capabilities.
                    # Reasoning options are exposed conservatively by model family.
                    reasoning_efforts=_openai_reasoning_efforts(model_id),
                    default_temperature=0.2,
                    max_output_tokens=tokens,
                )
            )
        return sorted(models, key=lambda model: model.id)

    def recommended_model_id(self, models: Sequence[AIModelInfo]) -> str | None:
        # This is a recommendation, not a fixed agent model. It is selected only
        # when the workspace API key's live model list contains it.
        return "gpt-5.6" if any(model.id == "gpt-5.6" for model in models) else None

    async def generate_structured(self, request: StructuredOutputRequest) -> str:
        if not self._uses_responses_api:
            return await self._generate_structured_with_chat_completions(request)
        response = await self._create_response(
            instructions=request.instructions,
            input=request.input_text,
            text=_openai_response_format(request),
            max_output_tokens=_effective_max_output_tokens(request.max_output_tokens, self._settings.max_output_tokens),
        )
        return response.output_text

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
        if not self._uses_responses_api:
            return await self._run_with_chat_completions(
                request,
                tools=tools,
                execute_tool=execute_tool,
                max_turns=max_turns,
                require_initial_tool_call=require_initial_tool_call,
            )
        max_output_tokens = _effective_max_output_tokens(request.max_output_tokens, self._settings.max_output_tokens)
        use_strict_tools = self._settings.provider == AIProviderName.CUSTOM.value
        openai_tools: list[dict[str, Any]] = []
        for tool in tools:
            function_definition: dict[str, Any] = {
                "type": "function",
                "name": tool.name,
                "description": tool.description,
                "parameters": _compatible_tool_parameters(tool.parameters, use_strict_tools=use_strict_tools),
            }
            if use_strict_tools:
                function_definition["strict"] = True
            openai_tools.append(function_definition)
        response = await self._create_response(
            instructions=request.instructions,
            input=request.input_text,
            tools=openai_tools,
            tool_choice="required" if require_initial_tool_call else "auto",
            text=_openai_response_format(request),
            max_tool_calls=64,
            max_output_tokens=max_output_tokens,
        )
        for turn in range(max_turns):
            calls = [item for item in response.output if getattr(item, "type", None) == "function_call"]
            if not calls:
                return response.output_text
            tool_outputs: list[dict[str, str]] = []
            for call in calls:
                try:
                    arguments = json.loads(call.arguments)
                    if not isinstance(arguments, dict):
                        raise ValueError("tool arguments must be an object")
                    result = await execute_tool(str(call.name), arguments)
                except Exception as exc:  # Tool errors are reported to the model, not raised into its loop.
                    result = {"ok": False, "error": _safe_error(exc)}
                tool_outputs.append(
                    {
                        "type": "function_call_output",
                        "call_id": str(call.call_id),
                        "output": json.dumps(result, separators=(",", ":")),
                    }
                )
            if turn == max_turns - 1:
                raise AIProviderError("OpenAI model exceeded the configured tool-call turn limit")
            response = await self._create_response(
                instructions=request.instructions,
                input=tool_outputs,
                previous_response_id=response.id,
                tools=openai_tools,
                tool_choice="auto",
                text=_openai_response_format(request),
                max_tool_calls=64,
                max_output_tokens=max_output_tokens,
            )
        raise AssertionError("unreachable")

    @property
    def _uses_responses_api(self) -> bool:
        """Use native Responses API only for the Custom provider."""
        return self._settings.provider == AIProviderName.CUSTOM.value

    async def _generate_structured_with_chat_completions(self, request: StructuredOutputRequest) -> str:
        """Generate JSON through the broadly supported Chat Completions API.

        The compatible providers do not implement one identical structured-output
        parameter.  Supplying the schema in the system instruction works across
        their documented chat endpoints, while the calling agent remains
        responsible for Pydantic validation and its existing retry path.
        """
        completion = await self._create_chat_completion(
            messages=[
                {"role": "system", "content": _chat_structured_instruction(request)},
                {"role": "user", "content": request.input_text},
            ],
            max_tokens=_effective_max_output_tokens(request.max_output_tokens, self._settings.max_output_tokens),
        )
        return _chat_completion_text(completion)

    async def _run_with_chat_completions(
        self,
        request: StructuredOutputRequest,
        *,
        tools: Sequence[ToolDefinition],
        execute_tool: ToolExecutor,
        max_turns: int,
        require_initial_tool_call: bool,
    ) -> str:
        """Run the portable tool loop through ``/v1/chat/completions``."""
        tool_instruction = _chat_structured_instruction(request)
        if require_initial_tool_call:
            tool_instruction += "\n\nBefore producing the final JSON, you must call an available tool."
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": tool_instruction},
            {"role": "user", "content": request.input_text},
        ]
        use_strict_tools = self._settings.provider == AIProviderName.CUSTOM.value
        chat_tools = [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": _compatible_tool_parameters(tool.parameters, use_strict_tools=use_strict_tools),
                },
            }
            for tool in tools
        ]
        max_output_tokens = _effective_max_output_tokens(request.max_output_tokens, self._settings.max_output_tokens)

        for turn in range(max_turns):
            completion_options: dict[str, Any] = {
                "messages": messages,
                "tools": chat_tools,
                "max_tokens": max_output_tokens,
            }
            if require_initial_tool_call and turn == 0:
                completion_options["tool_choice"] = "required"
            completion = await self._create_chat_completion(**completion_options)
            message = _chat_completion_message(completion)
            calls = list(getattr(message, "tool_calls", None) or [])
            if not calls:
                if require_initial_tool_call and turn == 0:
                    raise AIProviderError(f"{self.name} model did not issue the required initial tool call")
                return _chat_message_text(message)
            if turn == max_turns - 1:
                raise AIProviderError(f"{self.name} model exceeded the configured tool-call turn limit")

            assistant_calls: list[dict[str, Any]] = []
            tool_messages: list[dict[str, Any]] = []
            for call in calls:
                call_id = str(getattr(call, "id", ""))
                function = getattr(call, "function", None)
                tool_name = getattr(function, "name", None)
                arguments_json = getattr(function, "arguments", "")
                if not call_id or not isinstance(tool_name, str) or not isinstance(arguments_json, str):
                    raise AIProviderError(f"{self.name} returned an invalid function call")
                assistant_calls.append(
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {"name": tool_name, "arguments": arguments_json},
                    }
                )
                try:
                    arguments = json.loads(arguments_json)
                    if not isinstance(arguments, dict):
                        raise ValueError("tool arguments must be an object")
                    result = await execute_tool(tool_name, arguments)
                except Exception as exc:  # Tool failures stay within the model loop.
                    result = {"ok": False, "error": _safe_error(exc)}
                tool_messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": json.dumps(result, separators=(",", ":"), default=str),
                    }
                )
            assistant_message: dict[str, Any] = {"role": "assistant", "tool_calls": assistant_calls}
            content = getattr(message, "content", None)
            if isinstance(content, str) and content:
                assistant_message["content"] = content
            messages.append(assistant_message)
            messages.extend(tool_messages)
        raise AssertionError("unreachable")

    async def _create_response(self, **kwargs: Any) -> Any:
        retryable = (APITimeoutError, APIConnectionError, RateLimitError, InternalServerError)
        parameters: dict[str, Any] = {
            "model": self._selected_model(),
            "store": False,
            **kwargs,
        }
        if self._settings.reasoning_effort:
            parameters["reasoning"] = {"effort": self._settings.reasoning_effort}
        # Some reasoning models do not allow temperature. Do not send a default
        # value when an effort level has been explicitly selected.
        elif self._settings.temperature is not None:
            parameters["temperature"] = self._settings.temperature
        for attempt in range(5):
            try:
                return await self._client.responses.create(**parameters)
            except retryable as exc:
                if attempt == 4:
                    raise AIProviderError("OpenAI request exhausted retries") from exc
                await asyncio.sleep(2.0 * (2**attempt))
            except APIError as exc:
                raise AIProviderError(f"OpenAI request failed: {_safe_error(exc)}") from exc
        raise AssertionError("unreachable")

    async def _create_chat_completion(self, **kwargs: Any) -> Any:
        """Call the OpenAI-compatible Chat Completions endpoint with retries."""
        retryable = (APITimeoutError, APIConnectionError, RateLimitError, InternalServerError)
        parameters: dict[str, Any] = {
            "model": self._selected_model(),
            **kwargs,
        }
        if self._settings.temperature is not None:
            parameters["temperature"] = self._settings.temperature
        for attempt in range(5):
            try:
                return await self._client.chat.completions.create(**parameters)
            except retryable as exc:
                if attempt == 4:
                    raise AIProviderError(f"{self.name} request exhausted retries") from exc
                await asyncio.sleep(2.0 * (2**attempt))
            except APIError as exc:
                raise AIProviderError(f"{self.name} request failed: {_safe_error(exc)}") from exc
        raise AssertionError("unreachable")

    def _selected_model(self) -> str:
        if not self._settings.selected_model:
            raise AIProviderError(f"No {self.name} model is selected for this workspace")
        return self._settings.selected_model

    async def aclose(self) -> None:
        await self._client.close()


ProviderFactory = Callable[[AIProviderSettings], AIProvider]
_PROVIDER_FACTORIES: dict[str, ProviderFactory] = {}


def register_ai_provider(provider_id: str) -> Callable[[ProviderFactory], ProviderFactory]:
    """Register an adapter without changing any agent or orchestration code."""
    normalized = provider_id.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", normalized):
        raise ValueError("provider_id must be a lowercase provider identifier")

    def decorator(factory: ProviderFactory) -> ProviderFactory:
        if normalized in _PROVIDER_FACTORIES:
            raise RuntimeError(f"AI provider {normalized!r} is already registered")
        _PROVIDER_FACTORIES[normalized] = factory
        return factory

    return decorator


# Built-in adapters use the same public registration path as future providers.
register_ai_provider(AIProviderName.CUSTOM.value)(CustomOpenAICompatibleProvider)
register_ai_provider(AIProviderName.NEBIUS.value)(CustomOpenAICompatibleProvider)


def create_ai_provider(settings: AIProviderSettings) -> AIProvider:
    """Build an adapter from the registry; third parties register their own."""
    factory = _PROVIDER_FACTORIES.get(settings.provider)
    if factory is None:
        raise ValueError(f"Unsupported AI provider: {settings.provider}")
    return factory(settings)


def _effective_max_output_tokens(requested: int | None, configured: int) -> int:
    """Return a request budget that cannot exceed the workspace configuration."""
    return min(requested if requested is not None else configured, configured)


def _is_ineligible_compatible_model(provider: str, model_id: str) -> bool:
    """Exclude models that cannot safely satisfy the text/tool agent contract.

    Compatible ``/models`` endpoints do not expose one reliable capability
    schema. This small deny-list removes obvious non-text/legacy products.
    """
    generic_markers = (
        "embedding",
        "embed",
        "bge-",
        "tts",
        "whisper",
        "dall-e",
        "babbage",
        "davinci",
        "moderation",
        "vision",
        "image",
        "audio",
        "video",
        "rerank",
    )
    if any(marker in model_id for marker in generic_markers):
        return True
    if provider == AIProviderName.CUSTOM.value and model_id == "gpt-3.5-turbo-instruct":
        return True



def _openai_response_format(request: StructuredOutputRequest) -> dict[str, Any]:
    return {
        "format": {
            "type": "json_schema",
            "name": request.schema_name,
            "strict": True,
            "schema": request.json_schema,
        }
    }


def _compatible_tool_parameters(parameters: Mapping[str, Any], *, use_strict_tools: bool) -> dict[str, Any]:
    """Return an isolated schema accepted by the selected tool-calling API.

    OpenAI's native strict mode uses ``additionalProperties: false`` as part of
    its schema contract. Several compatible APIs reject that keyword despite
    accepting OpenAI-shaped tool declarations, so omit it recursively for
    every non-OpenAI provider without mutating the agent-owned definition.
    """
    if use_strict_tools:
        return dict(parameters)
    converted = _strip_additional_properties(parameters)
    return converted if isinstance(converted, dict) else {}


def _strip_additional_properties(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _strip_additional_properties(item)
            for key, item in value.items()
            if key != "additionalProperties"
        }
    if isinstance(value, list):
        return [_strip_additional_properties(item) for item in value]
    return value


def _chat_structured_instruction(request: StructuredOutputRequest) -> str:
    """Express the portable structured-output contract without vendor flags."""
    schema = json.dumps(request.json_schema, separators=(",", ":"), ensure_ascii=False)
    return (
        f"{request.instructions}\n\n"
        "Return only a JSON object that conforms exactly to the following JSON Schema. "
        "Do not wrap the JSON in Markdown fences or include any commentary.\n"
        f"JSON Schema:\n{schema}"
    )


def _chat_completion_message(completion: Any) -> Any:
    choices = getattr(completion, "choices", None)
    if not isinstance(choices, list) or not choices:
        raise AIProviderError("OpenAI-compatible provider returned no completion choices")
    message = getattr(choices[0], "message", None)
    if message is None:
        raise AIProviderError("OpenAI-compatible provider returned a completion without a message")
    return message


def _chat_message_text(message: Any) -> str:
    content = getattr(message, "content", None)
    if not isinstance(content, str) or not content.strip():
        raise AIProviderError("OpenAI-compatible provider returned no structured output text")
    return content


def _chat_completion_text(completion: Any) -> str:
    return _chat_message_text(_chat_completion_message(completion))


def _openai_reasoning_efforts(model_id: str) -> tuple[str, ...]:
    # OpenAI's list endpoint does not publish capability metadata. This is a
    # family-level compatibility hint, not a fixed model allow-list; options are
    # presented only for model IDs returned for the workspace API key.
    if model_id.startswith(("gpt-5", "o1", "o3", "o4")):
        return ("low", "medium", "high")
    return ()


def _safe_error(error: Exception) -> str:
    return re.sub(r"\s+", " ", str(error)).strip()[:500] or error.__class__.__name__


__all__ = [
    "AIModelInfo",
    "AIProvider",
    "AIProviderError",
    "AIProviderName",
    "AIProviderSettings",
    "CustomOpenAICompatibleProvider",
    "StructuredOutputRequest",
    "ToolDefinition",
    "create_ai_provider",
    "register_ai_provider",
]
