"""Official authenticated local CLI adapters for Codex and Claude.

The adapters delegate authentication and model defaults to the installed CLI.
They never inspect vendor config, token, account, or authentication files.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from engine.services.ai_provider import (
    AIModelInfo,
    AIProvider,
    AIProviderError,
    AIProviderName,
    AIProviderSettings,
    StructuredOutputRequest,
    ToolDefinition,
    ToolExecutor,
    _request_timeout,
)

_MAX_CAPTURE_BYTES = 4 * 1024 * 1024
_MAX_TOOL_CALLS = 64
_MAX_TOOL_RESULT_CHARS = 32 * 1024
_MAX_TRANSCRIPT_CHARS = 128 * 1024
_LOCAL_CLI_COMMANDS = {
    AIProviderName.CODEX_CLI.value: "codex",
    AIProviderName.CLAUDE_CLI.value: "claude",
}


class _OutputLimitError(RuntimeError):
    pass


def _resolve_cli_executable(provider: str) -> str:
    """Resolve only a fixed official executable name through the system PATH."""
    command = _LOCAL_CLI_COMMANDS.get(provider)
    if command is None:
        raise ValueError(f"LocalCLIProvider does not support provider='{provider}'")
    executable = shutil.which(command)
    if not executable:
        raise ValueError(f"Required authenticated local CLI executable '{command}' was not found on PATH")
    return executable


class LocalCLIProvider(AIProvider):
    """Subprocess-backed provider using an official CLI's existing login session."""

    def __init__(self, settings: AIProviderSettings) -> None:
        if settings.provider not in _LOCAL_CLI_COMMANDS:
            raise ValueError(f"LocalCLIProvider does not support provider='{settings.provider}'")
        self._settings = settings
        self._command = _LOCAL_CLI_COMMANDS[settings.provider]
        self._executable = _resolve_cli_executable(settings.provider)
        self._processes: set[asyncio.subprocess.Process] = set()
        self._closed = False

    @property
    def name(self) -> str:
        return self._settings.provider

    @property
    def settings(self) -> AIProviderSettings:
        return self._settings

    async def list_models(self) -> list[AIModelInfo]:
        model_id = self._settings.selected_model or "cli-default"
        cli_name = "Codex" if self.name == AIProviderName.CODEX_CLI.value else "Claude"
        if self._settings.selected_model:
            display_name = f"{cli_name} authenticated CLI model: {model_id}"
        else:
            display_name = f"{cli_name} authenticated CLI-selected default"
        return [
            AIModelInfo(
                id=model_id,
                display_name=display_name,
                supports_structured_output=True,
                supports_function_calling=False,
            )
        ]

    async def generate_structured(self, request: StructuredOutputRequest) -> str:
        prompt = _structured_prompt(request)
        if self.name == AIProviderName.CODEX_CLI.value:
            output = await self._run_codex(prompt, request.json_schema)
            return _parse_codex_output(output)
        output = await self._run_claude(prompt, request.json_schema)
        return _parse_claude_output(output)

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
        tools_by_name = {tool.name: tool for tool in tools}
        if len(tools_by_name) != len(tools):
            raise ValueError("tool names must be unique")

        envelope_schema = _tool_envelope_schema(tuple(tools_by_name))
        protocol = _tool_protocol_instruction(request, tools)
        transcript: list[dict[str, Any]] = []
        total_calls = 0

        for turn in range(max_turns):
            turn_input = _tool_turn_input(request.input_text, transcript)
            turn_request = request.model_copy(
                update={
                    "instructions": protocol,
                    "input_text": turn_input,
                    "schema_name": "ArbalestToolTurn",
                    "json_schema": envelope_schema,
                }
            )
            raw = await self.generate_structured(turn_request)
            envelope = _parse_tool_envelope(raw)
            action = envelope["action"]

            if action == "final":
                if require_initial_tool_call and turn == 0:
                    raise AIProviderError(f"{self.name} model did not issue the required initial tool call")
                return json.dumps(envelope["final"], separators=(",", ":"), ensure_ascii=False)

            calls = cast(list[dict[str, Any]], envelope["tool_calls"])
            if turn == max_turns - 1:
                raise AIProviderError(f"{self.name} model exceeded the configured tool-call turn limit")
            total_calls += len(calls)
            if total_calls > _MAX_TOOL_CALLS:
                raise AIProviderError(f"{self.name} model exceeded the local tool-call limit")

            turn_results: list[dict[str, Any]] = []
            for call in calls:
                tool_name = cast(str, call["name"])
                arguments = cast(dict[str, Any], call["arguments"])
                if tool_name not in tools_by_name:
                    raise AIProviderError(f"{self.name} model requested an unavailable tool")
                try:
                    result = await execute_tool(tool_name, arguments)
                    if not isinstance(result, dict):
                        raise TypeError("tool result must be an object")
                except Exception as exc:  # Tool errors remain inside the bounded model loop.
                    result = {"ok": False, "error": f"{exc.__class__.__name__}: tool execution failed"}
                turn_results.append(
                    {
                        "name": tool_name,
                        "arguments": _bounded_json_value(arguments),
                        "result": _bounded_json_value(result),
                    }
                )
            transcript.append({"turn": turn + 1, "tool_results": turn_results})
            _bound_transcript(transcript)

        raise AssertionError("unreachable")

    async def _run_codex(self, prompt: str, schema: dict[str, Any]) -> bytes:
        with tempfile.TemporaryDirectory(prefix="arbalest-codex-cwd-") as cwd:
            with tempfile.TemporaryDirectory(prefix="arbalest-codex-schema-") as schema_dir:
                schema_path = Path(schema_dir) / "output-schema.json"
                schema_path.write_text(json.dumps(schema, separators=(",", ":")), encoding="utf-8")
                argv = [
                    self._executable,
                    "exec",
                    "--ephemeral",
                    "--sandbox",
                    "read-only",
                    "--skip-git-repo-check",
                    "--output-schema",
                    str(schema_path),
                ]
                if self._settings.selected_model:
                    argv.extend(("--model", self._settings.selected_model))
                argv.append("-")
                return await self._run_process(argv, prompt, cwd)

    async def _run_claude(self, prompt: str, schema: dict[str, Any]) -> bytes:
        with tempfile.TemporaryDirectory(prefix="arbalest-claude-cwd-") as cwd:
            argv = [
                self._executable,
                "-p",
                "--output-format",
                "json",
                "--json-schema",
                json.dumps(schema, separators=(",", ":")),
                "--no-session-persistence",
                "--safe-mode",
                "--strict-mcp-config",
                "--mcp-config",
                '{"mcpServers":{}}',
                "--tools",
                "",
                "--permission-mode",
                "plan",
                "--permission-prompts",
                "none",
            ]
            if self._settings.selected_model:
                argv.extend(("--model", self._settings.selected_model))
            return await self._run_process(argv, prompt, cwd)

    async def _run_process(self, argv: list[str], prompt: str, cwd: str) -> bytes:
        if self._closed:
            raise AIProviderError(f"{self.name} provider is closed")
        process_options: dict[str, Any] = {}
        if os.name == "nt":
            process_options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            process_options["start_new_session"] = True
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                **process_options,
            )
        except (OSError, ValueError) as exc:
            raise AIProviderError(f"{self.name} CLI process could not be started") from exc

        self._processes.add(process)
        if self._closed:
            await _terminate_process(process)
            self._processes.discard(process)
            raise AIProviderError(f"{self.name} provider is closed")
        if process.stdin is None or process.stdout is None or process.stderr is None:
            await _terminate_process(process)
            self._processes.discard(process)
            raise AIProviderError(f"{self.name} CLI process pipes were unavailable")

        tasks: list[asyncio.Task[Any]] = [
            asyncio.create_task(_write_stdin(process.stdin, prompt)),
            asyncio.create_task(_read_bounded(process.stdout)),
            asyncio.create_task(_read_bounded(process.stderr)),
            asyncio.create_task(process.wait()),
        ]
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=_request_timeout())
            stdout = cast(bytes, results[1])
            returncode = cast(int, results[3])
            if returncode != 0:
                raise AIProviderError(f"{self.name} CLI exited unsuccessfully (code {returncode})")
            return stdout
        except TimeoutError as exc:
            await _terminate_process(process)
            raise AIProviderError(f"{self.name} CLI request timed out") from exc
        except asyncio.CancelledError:
            await _terminate_process(process)
            raise
        except _OutputLimitError as exc:
            await _terminate_process(process)
            raise AIProviderError(f"{self.name} CLI output exceeded the local safety limit") from exc
        except AIProviderError:
            await _terminate_process(process)
            raise
        except Exception as exc:
            await _terminate_process(process)
            raise AIProviderError(f"{self.name} CLI request failed") from exc
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self._processes.discard(process)

    async def aclose(self) -> None:
        self._closed = True
        processes = tuple(self._processes)
        if processes:
            await asyncio.gather(*(_terminate_process(process) for process in processes))
        self._processes.clear()


async def _write_stdin(stream: asyncio.StreamWriter, prompt: str) -> None:
    try:
        stream.write(prompt.encode("utf-8"))
        await stream.drain()
    finally:
        stream.close()
        try:
            await stream.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass


async def _read_bounded(stream: asyncio.StreamReader) -> bytes:
    captured = bytearray()
    while True:
        chunk = await stream.read(64 * 1024)
        if not chunk:
            return bytes(captured)
        captured.extend(chunk)
        if len(captured) > _MAX_CAPTURE_BYTES:
            raise _OutputLimitError


async def _terminate_process(process: asyncio.subprocess.Process) -> None:
    """Terminate, kill, and reap a CLI process and its tree on a best-effort basis."""
    if process.returncode is not None:
        await process.wait()
        return

    if os.name == "nt" and getattr(process, "pid", None):
        tree_kill: asyncio.subprocess.Process | None = None
        try:
            tree_kill = await asyncio.create_subprocess_exec(
                "taskkill",
                "/PID",
                str(process.pid),
                "/T",
                "/F",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(tree_kill.wait(), timeout=5.0)
        except TimeoutError:
            if tree_kill is not None and tree_kill.returncode is None:
                try:
                    tree_kill.kill()
                except ProcessLookupError:
                    pass
                await tree_kill.wait()
        except OSError:
            pass
    elif getattr(process, "pid", None):
        try:
            kill_process_group = getattr(os, "killpg", None)
            if kill_process_group is None:
                raise OSError
            kill_process_group(process.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            try:
                process.terminate()
            except ProcessLookupError:
                pass

    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
        return
    except TimeoutError:
        pass
    try:
        if os.name != "nt" and getattr(process, "pid", None):
            kill_process_group = getattr(os, "killpg", None)
            if kill_process_group is not None:
                kill_process_group(process.pid, getattr(signal, "SIGKILL", 9))
            else:
                process.kill()
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        pass
    await process.wait()


def _structured_prompt(request: StructuredOutputRequest) -> str:
    return (
        f"{request.instructions}\n\n"
        "Return only the requested JSON object. Do not use CLI-native tools, inspect repositories, "
        "or access files for this request.\n\n"
        f"INPUT:\n{request.input_text}"
    )


def _parse_json_object(raw: bytes, provider: str) -> dict[str, Any]:
    try:
        decoded = raw.decode("utf-8")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AIProviderError(f"{provider} CLI returned invalid structured output") from exc
    if not isinstance(value, dict):
        raise AIProviderError(f"{provider} CLI returned a non-object structured output")
    return value


def _parse_codex_output(raw: bytes) -> str:
    value = _parse_json_object(raw, AIProviderName.CODEX_CLI.value)
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _parse_claude_output(raw: bytes) -> str:
    envelope = _parse_json_object(raw, AIProviderName.CLAUDE_CLI.value)
    if envelope.get("subtype") != "success" or envelope.get("is_error") is True:
        raise AIProviderError("claude-cli returned an unsuccessful structured response")
    structured_output = envelope.get("structured_output")
    if not isinstance(structured_output, dict):
        raise AIProviderError("claude-cli response contained no structured output object")
    return json.dumps(structured_output, separators=(",", ":"), ensure_ascii=False)


def _tool_envelope_schema(tool_names: tuple[str, ...]) -> dict[str, Any]:
    name_schema: dict[str, Any] = {"type": "string"}
    if tool_names:
        name_schema["enum"] = list(tool_names)
    call_schema = {
        "type": "object",
        "properties": {
            "name": name_schema,
            "arguments": {"type": "object"},
        },
        "required": ["name", "arguments"],
        "additionalProperties": False,
    }
    return {
        "oneOf": [
            {
                "type": "object",
                "properties": {"action": {"const": "final"}, "final": {"type": "object"}},
                "required": ["action", "final"],
                "additionalProperties": False,
            },
            {
                "type": "object",
                "properties": {
                    "action": {"const": "tool_calls"},
                    "tool_calls": {"type": "array", "items": call_schema, "minItems": 1, "maxItems": 64},
                },
                "required": ["action", "tool_calls"],
                "additionalProperties": False,
            },
        ]
    }


def _tool_protocol_instruction(request: StructuredOutputRequest, tools: Sequence[ToolDefinition]) -> str:
    definitions = [
        {"name": tool.name, "description": tool.description, "parameters": tool.parameters}
        for tool in tools
    ]
    return (
        f"{request.instructions}\n\n"
        "Use only the JSON turn protocol. Native CLI tools are disabled and must not be used. "
        "Choose action=tool_calls to request one or more listed callbacks, or action=final to return the final object. "
        "Tool arguments must be JSON objects. The final object must conform to the caller's schema.\n"
        f"CALLER FINAL SCHEMA: {json.dumps(request.json_schema, separators=(',', ':'), ensure_ascii=False)}\n"
        f"AVAILABLE CALLBACKS: {json.dumps(definitions, separators=(',', ':'), ensure_ascii=False)}"
    )


def _tool_turn_input(original_input: str, transcript: list[dict[str, Any]]) -> str:
    history = json.dumps(transcript, separators=(",", ":"), ensure_ascii=False)
    return f"ORIGINAL INPUT:\n{original_input}\n\nCALLBACK TRANSCRIPT:\n{history}"


def _parse_tool_envelope(raw: str) -> dict[str, Any]:
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AIProviderError("Local CLI returned an invalid tool-turn envelope") from exc
    if not isinstance(envelope, dict):
        raise AIProviderError("Local CLI returned a non-object tool-turn envelope")
    action = envelope.get("action")
    if action == "final":
        if set(envelope) != {"action", "final"} or not isinstance(envelope.get("final"), dict):
            raise AIProviderError("Local CLI returned an invalid final tool-turn envelope")
        return envelope
    if action != "tool_calls" or set(envelope) != {"action", "tool_calls"}:
        raise AIProviderError("Local CLI returned an invalid tool-call envelope")
    calls = envelope.get("tool_calls")
    if not isinstance(calls, list) or not calls:
        raise AIProviderError("Local CLI returned an empty tool-call envelope")
    for call in calls:
        if (
            not isinstance(call, dict)
            or set(call) != {"name", "arguments"}
            or not isinstance(call.get("name"), str)
            or not isinstance(call.get("arguments"), dict)
        ):
            raise AIProviderError("Local CLI returned an invalid tool call")
    return envelope


def _bounded_json_value(value: Any) -> Any:
    try:
        serialized = json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return {"truncated": True, "reason": "non-serializable tool value"}
    if len(serialized) > _MAX_TOOL_RESULT_CHARS:
        return {"truncated": True, "reason": "tool value exceeded transcript limit"}
    return json.loads(serialized)


def _bound_transcript(transcript: list[dict[str, Any]]) -> None:
    while len(transcript) > 1:
        serialized = json.dumps(transcript, separators=(",", ":"), ensure_ascii=False)
        if len(serialized) <= _MAX_TRANSCRIPT_CHARS:
            return
        transcript.pop(0)
    if transcript and len(json.dumps(transcript, separators=(",", ":"), ensure_ascii=False)) > _MAX_TRANSCRIPT_CHARS:
        transcript[0] = {"truncated": True, "reason": "turn transcript exceeded limit"}


__all__ = ["LocalCLIProvider"]
