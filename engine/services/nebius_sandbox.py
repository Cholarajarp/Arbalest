"""Nebius Token Factory Sandboxes backend (the ConTree service, in beta).

Runs untrusted, model-generated code in a Nebius microVM instead of a local
Docker container. It speaks the documented REST API directly with ``httpx``
(no extra dependency) because the high-level ``contree-sdk`` ``run()`` cannot
turn networking off, and an adversarial harness must run offline.

Contract used (https://docs.tokenfactory.nebius.com/api-reference/sandboxes):

* ``POST /files``            upload one file, returns ``{uuid, sha256, size}``
* ``POST /instances``        spawn a command on an image, returns an operation
* ``GET  /operations/{id}``  poll until ``SUCCESS`` / ``FAILED`` / ``CANCELLED``
* ``DELETE /operations/{id}`` cancel
* ``GET  /whoami``           token permissions and limits

Authentication is ``Authorization: Bearer <NEBIUS_API_KEY>`` plus a ``Project``
header carrying ``NEBIUS_PROJECT_ID``.

Security posture, stated honestly:

* Every instance is spawned ``disposable`` (no state kept) with
  ``networking.enabled = false`` and is cancelled if we stop waiting for it.
* The isolation boundary is Nebius's microVM, not this process. Memory, CPU and
  pid limits are not exposed by the API, so only the wall-clock timeout, output
  cap and writable-layer size are enforced from our side.
* The offline setting is requested and the echoed value is checked as a
  tripwire; it cannot be proven from here. ``arbalest sandbox-check`` runs a
  live probe that does prove it for your project.
* The Sandboxes product is in beta. Do not send personal or sensitive data.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import logging
import math
import os
import re
import shlex
import time
from dataclasses import dataclass
from typing import Any

import httpx

from engine.services.docker_manager import (
    _CONTAINER_CARGO_TARGET_DIR,
    _CONTAINER_GO_CACHE_DIR,
    _CONTAINER_GO_MOD_CACHE_DIR,
    _CONTAINER_GO_TMP_DIR,
    _CONTAINER_TMP_DIR,
    _CONTAINER_WORKSPACE_DIR,
    LogSink,
    SandboxLimits,
    SandboxResult,
    SandboxRunSpec,
    SandboxRuntime,
    SandboxStatus,
    _decode_bounded,
    _emit_logs,
)

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.tokenfactory.nebius.com/sandboxes/v1"
BETA_ACCESS_URL = "https://tokenfactory.nebius.com/sandboxes/about"

# Plain registry tags; the service imports them on first use. Override per
# runtime with ARBALEST_NEBIUS_<PYTHON|RUST|GO|NODE>_IMAGE (a tag or image UUID).
DEFAULT_IMAGES: dict[SandboxRuntime, str] = {
    SandboxRuntime.PYTHON: "python:3.12-slim",
    SandboxRuntime.TYPESCRIPT: "node:20-alpine",
    SandboxRuntime.RUST: "rust:1.77-slim",
    SandboxRuntime.GO: "golang:1.22-alpine",
}
_IMAGE_ENV: dict[SandboxRuntime, str] = {
    SandboxRuntime.PYTHON: "ARBALEST_NEBIUS_PYTHON_IMAGE",
    SandboxRuntime.RUST: "ARBALEST_NEBIUS_RUST_IMAGE",
    SandboxRuntime.GO: "ARBALEST_NEBIUS_GO_IMAGE",
    SandboxRuntime.TYPESCRIPT: "ARBALEST_NEBIUS_NODE_IMAGE",
}

_TERMINAL_STATES = frozenset({"SUCCESS", "FAILED", "CANCELLED"})
_RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
_MAX_ATTEMPTS = 4
_UPLOAD_CONCURRENCY = 8
_MAX_LAYER_BYTES = 1024 * 1024 * 1024
_API_MAX_TRUNCATE = 10 * 1024 * 1024
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_IMAGE_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*(?:[:/.][A-Za-z0-9_-]+)*$")

_SANDBOX_DIRS = (
    _CONTAINER_CARGO_TARGET_DIR,
    _CONTAINER_GO_CACHE_DIR,
    _CONTAINER_GO_MOD_CACHE_DIR,
    _CONTAINER_GO_TMP_DIR,
)
_SANDBOX_ENV = {
    "HOME": _CONTAINER_TMP_DIR,
    "TMPDIR": _CONTAINER_TMP_DIR,
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
    "CARGO_TARGET_DIR": _CONTAINER_CARGO_TARGET_DIR,
    "GOCACHE": _CONTAINER_GO_CACHE_DIR,
    "GOMODCACHE": _CONTAINER_GO_MOD_CACHE_DIR,
    "GOTMPDIR": _CONTAINER_GO_TMP_DIR,
}


class NebiusSandboxError(RuntimeError):
    """The Nebius Sandboxes service could not run, or could not be trusted to run, a request."""


@dataclass(frozen=True, slots=True)
class _Outcome:
    status: SandboxStatus
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    error: str | None


class NebiusSandboxManager:
    """Run bounded, offline, disposable commands on Nebius Token Factory Sandboxes."""

    backend_name = "Nebius Token Factory Sandboxes"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        project_id: str | None = None,
        base_url: str | None = None,
        images: dict[SandboxRuntime, str] | None = None,
        max_concurrent_runs: int = 2,
        poll_interval: float = 0.5,
        timeout_grace: float = 60.0,
        http_timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        key = (api_key or os.environ.get("NEBIUS_API_KEY", "")).strip()
        project = (project_id or os.environ.get("NEBIUS_PROJECT_ID", "")).strip()
        if not key:
            raise ValueError("NEBIUS_API_KEY is required for the Nebius Sandboxes backend")
        if not project:
            raise ValueError(
                "NEBIUS_PROJECT_ID is required for the Nebius Sandboxes backend "
                "(find it in the Token Factory console)"
            )
        if not 1 <= max_concurrent_runs <= 8:
            raise ValueError("max_concurrent_runs must be between 1 and 8")
        self._key = key
        self._project = project
        self._base_url = (base_url or os.environ.get("ARBALEST_NEBIUS_SANDBOX_URL") or DEFAULT_BASE_URL).rstrip("/")
        self._images = {runtime: self._resolve_image(runtime, images) for runtime in SandboxRuntime}
        self._semaphore = asyncio.Semaphore(max_concurrent_runs)
        self._poll_interval = max(poll_interval, 0.01)
        self._timeout_grace = timeout_grace
        self._http_timeout = http_timeout
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self._client_lock = asyncio.Lock()
        self._max_timeout: int | None = None
        self._warned_no_network_echo = False

    @property
    def project_id(self) -> str:
        return self._project

    # -- lifecycle ------------------------------------------------------------
    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def healthcheck(self) -> None:
        """Confirm the credentials work and the project is allowed to spawn instances."""
        response = await self._request("GET", "/whoami", expected=(200,))
        info = _json_object(response)
        permissions = info.get("permissions")
        granted = sorted(name for name, ok in (permissions or {}).items() if ok) if isinstance(permissions, dict) else []
        if not ({"spawn", "spawn_disposable"} & set(granted)):
            raise NebiusSandboxError(
                "This token cannot spawn sandbox instances "
                f"(granted permissions: {', '.join(granted) or 'none'}). "
                f"Check that the Sandboxes beta is enabled for project {self._project}: {BETA_ACCESS_URL}"
            )
        limits = info.get("limits")
        if isinstance(limits, dict) and isinstance(limits.get("instance_max_timeout"), int):
            self._max_timeout = int(limits["instance_max_timeout"])

    # -- public run -------------------------------------------------------------
    async def run(self, spec: SandboxRunSpec, *, log_sink: LogSink | None = None) -> SandboxResult:
        """Run one validated spec. Every failure path returns a non-succeeded result."""
        spec.validate()
        async with self._semaphore:
            return await self._run_one(spec, log_sink=log_sink)

    async def _run_one(self, spec: SandboxRunSpec, *, log_sink: LogSink | None) -> SandboxResult:
        started = time.monotonic()
        operation_id: str | None = None
        terminal = False
        outcome = _Outcome(SandboxStatus.ENGINE_ERROR, None, "", "", False, False, None)
        try:
            file_ids = await self._upload_files(spec.files)
            timeout = self._effective_timeout(spec.limits)
            body = self._spawn_body(spec, file_ids, timeout)
            created = _json_object(await self._request("POST", "/instances", expected=(200, 201, 202), json=body))
            operation_id = _require_str(created, "uuid")
            self._assert_offline(created)
            data = await self._wait(operation_id, timeout)
            terminal = True
            outcome = self._interpret(data, spec.limits)
        except asyncio.CancelledError:
            outcome = _Outcome(SandboxStatus.CANCELLED, None, "", "", False, False, "Sandbox task was cancelled")
            raise
        except NebiusSandboxError as exc:
            outcome = _Outcome(SandboxStatus.ENGINE_ERROR, None, "", "", False, False, str(exc))
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            outcome = _Outcome(
                SandboxStatus.ENGINE_ERROR, None, "", "", False, False, f"Nebius Sandboxes error: {_safe(exc)}"
            )
        finally:
            if operation_id is not None and not terminal:
                # Never leave untrusted code running because we stopped waiting.
                with contextlib.suppress(Exception):
                    await asyncio.shield(self._cancel(operation_id))

        result = SandboxResult(
            status=outcome.status,
            exit_code=outcome.exit_code,
            stdout=outcome.stdout,
            stderr=outcome.stderr,
            duration_ms=int((time.monotonic() - started) * 1_000),
            stdout_truncated=outcome.stdout_truncated,
            stderr_truncated=outcome.stderr_truncated,
            container_id=operation_id,
            error=outcome.error,
        )
        await _emit_logs(result, log_sink)
        return result

    # -- request construction -----------------------------------------------------
    def _resolve_image(self, runtime: SandboxRuntime, overrides: dict[SandboxRuntime, str] | None) -> str:
        value = (overrides or {}).get(runtime) or os.environ.get(_IMAGE_ENV[runtime], "") or DEFAULT_IMAGES[runtime]
        value = value.strip()
        if value.startswith("tag:"):
            value = value[4:]
        if not (_UUID.fullmatch(value) or _IMAGE_TAG.fullmatch(value)):
            raise ValueError(f"Invalid sandbox image reference for {runtime.value}: {value!r}")
        return value

    def _image_source(self, runtime: SandboxRuntime) -> str:
        image = self._images[runtime]
        return image if _UUID.fullmatch(image) else f"tag:{image}"

    def _effective_timeout(self, limits: SandboxLimits) -> int:
        timeout = max(1, math.ceil(limits.timeout_seconds))
        return min(timeout, self._max_timeout) if self._max_timeout else timeout

    def _spawn_body(self, spec: SandboxRunSpec, file_ids: dict[str, str], timeout: int) -> dict[str, Any]:
        # The argv was validated (approved executable, no `sh -c`); quoting it
        # makes the shell expression equivalent to the argv, with no injection.
        # shell=true is used so the image's PATH (cargo, go) is inherited.
        setup = "mkdir -p " + " ".join(shlex.quote(path) for path in _SANDBOX_DIRS)
        command = f"{setup} && {shlex.join(spec.command)}"
        return {
            "image": self._image_source(spec.runtime),
            "command": command,
            "shell": True,
            "cwd": _CONTAINER_WORKSPACE_DIR,
            "env": dict(_SANDBOX_ENV),
            "hostname": "arbalest-sandbox",
            "disposable": True,
            "timeout": timeout,
            "truncate_output_at": min(spec.limits.max_output_bytes, _API_MAX_TRUNCATE),
            "networking": {"enabled": False},
            "resources_limits": {"max_layer_bytes": _MAX_LAYER_BYTES},
            "files": {
                f"{_CONTAINER_WORKSPACE_DIR}/{relative}": {"uuid": file_ids[relative], "uid": 0, "gid": 0, "mode": "0644"}
                for relative in spec.files
            },
        }

    async def _upload_files(self, files: dict[str, str | bytes] | Any) -> dict[str, str]:
        """Upload each distinct file once; return relative path to file uuid."""
        payloads: dict[str, bytes] = {
            relative: content.encode("utf-8") if isinstance(content, str) else bytes(content)
            for relative, content in files.items()
        }
        by_digest: dict[str, bytes] = {hashlib.sha256(data).hexdigest(): data for data in payloads.values()}
        gate = asyncio.Semaphore(_UPLOAD_CONCURRENCY)

        async def upload(digest: str, data: bytes) -> tuple[str, str]:
            async with gate:
                response = await self._request(
                    "POST",
                    "/files",
                    expected=(200, 201),
                    content=data,
                    headers={"Content-Type": "application/octet-stream"},
                )
            return digest, _require_str(_json_object(response), "uuid")

        uploaded = dict(await asyncio.gather(*(upload(digest, data) for digest, data in by_digest.items())))
        return {relative: uploaded[hashlib.sha256(data).hexdigest()] for relative, data in payloads.items()}

    def _assert_offline(self, created: dict[str, Any]) -> None:
        networking = created.get("networking")
        if isinstance(networking, dict) and networking.get("enabled") is True:
            raise NebiusSandboxError(
                "The sandbox reported networking ENABLED although it was spawned offline; "
                "refusing to trust it with untrusted code"
            )
        if not isinstance(networking, dict) and not self._warned_no_network_echo:
            self._warned_no_network_echo = True
            logger.warning(
                "Sandbox response did not echo the networking setting; offline mode was requested but "
                "not confirmed. Run `arbalest sandbox-check` to prove isolation for this project."
            )

    # -- waiting and results ------------------------------------------------------
    async def _wait(self, operation_id: str, timeout: int) -> dict[str, Any]:
        deadline = time.monotonic() + timeout + self._timeout_grace
        delay = self._poll_interval
        while True:
            response = await self._request("GET", f"/operations/{operation_id}", expected=(200,))
            data = _json_object(response)
            if str(data.get("status", "")).upper() in _TERMINAL_STATES:
                return data
            if time.monotonic() >= deadline:
                raise NebiusSandboxError(
                    f"Sandbox operation did not finish within {timeout}s plus {self._timeout_grace:g}s grace"
                )
            hinted = _retry_after(response)
            await asyncio.sleep(hinted if hinted is not None else delay)
            delay = min(delay * 1.5, 3.0)

    async def _cancel(self, operation_id: str) -> None:
        client = await self._get_client()
        await client.delete(f"/operations/{operation_id}")

    def _interpret(self, data: dict[str, Any], limits: SandboxLimits) -> _Outcome:
        state_name = str(data.get("status", "")).upper()
        metadata = data.get("metadata")
        # Current Sandboxes responses can include a top-level ``result`` that
        # describes the resulting image (``{image, tag}``) while the command's
        # exit state and streams live in ``metadata.result``.  Prefer a result
        # object that actually has execution fields; truthiness alone is not
        # enough here because the image result is also a non-empty mapping.
        top_level_result = data.get("result")
        metadata_result = metadata.get("result") if isinstance(metadata, dict) else None
        execution_keys = {"state", "stdout", "stderr"}
        if isinstance(top_level_result, dict) and execution_keys.intersection(top_level_result):
            result = top_level_result
        elif isinstance(metadata_result, dict):
            result = metadata_result
        else:
            result = top_level_result if isinstance(top_level_result, dict) else {}
        state = result.get("state") if isinstance(result, dict) else None
        state = state if isinstance(state, dict) else {}
        out_bytes, out_trunc = _stream_bytes(result.get("stdout") if isinstance(result, dict) else None)
        err_bytes, err_trunc = _stream_bytes(result.get("stderr") if isinstance(result, dict) else None)
        stdout, stdout_cut = _decode_bounded(out_bytes, limits.max_output_bytes)
        stderr, stderr_cut = _decode_bounded(err_bytes, limits.max_output_bytes)
        stdout_truncated, stderr_truncated = stdout_cut or out_trunc, stderr_cut or err_trunc

        def outcome(status: SandboxStatus, code: int | None, error: str | None) -> _Outcome:
            return _Outcome(status, code, stdout, stderr, stdout_truncated, stderr_truncated, error)

        if state_name == "CANCELLED":
            return outcome(SandboxStatus.CANCELLED, None, "Sandbox operation was cancelled")
        if state_name == "FAILED":
            return outcome(SandboxStatus.ENGINE_ERROR, None, str(data.get("error") or "Sandbox operation failed"))
        if state.get("timed_out"):
            return outcome(SandboxStatus.TIMED_OUT, 124, "Execution exceeded the sandbox timeout")
        code = state.get("exit_code")
        if not isinstance(code, int) or isinstance(code, bool):
            return outcome(SandboxStatus.ENGINE_ERROR, None, "Sandbox finished without reporting an exit code")
        return outcome(SandboxStatus.COMPLETED, code, None)

    # -- HTTP -----------------------------------------------------------------------
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        async with self._client_lock:
            if self._client is None:
                self._client = httpx.AsyncClient(
                    base_url=self._base_url,
                    headers={"Authorization": f"Bearer {self._key}", "Project": self._project},
                    timeout=self._http_timeout,
                    transport=self._transport,
                )
            return self._client

    async def _request(self, method: str, path: str, *, expected: tuple[int, ...], **kwargs: Any) -> httpx.Response:
        client = await self._get_client()
        last_error = "no response"
        for attempt in range(_MAX_ATTEMPTS):
            try:
                response = await client.request(method, path, **kwargs)
            except httpx.TransportError as exc:
                last_error = _safe(exc)
            else:
                if response.status_code in expected:
                    return response
                if response.status_code not in _RETRYABLE_STATUS:
                    raise self._status_error(response, method=method, path=path)
                last_error = f"{method} {path}: HTTP {response.status_code} ({_error_detail(response)})"
            if attempt < _MAX_ATTEMPTS - 1:
                await asyncio.sleep(min(self._poll_interval * (2**attempt), 8.0))
        raise NebiusSandboxError(f"Nebius Sandboxes API unavailable after {_MAX_ATTEMPTS} attempts ({last_error})")

    def _status_error(self, response: httpx.Response, *, method: str = "request", path: str = "resource") -> NebiusSandboxError:
        detail = _error_detail(response)
        operation = f"{method} {path}"
        code = response.status_code
        if code in (401, 403):
            return NebiusSandboxError(
                f"Nebius Sandboxes rejected the credentials (HTTP {code}). Check NEBIUS_API_KEY and "
                f"NEBIUS_PROJECT_ID, and that the Sandboxes beta is enabled for project {self._project} "
                f"(request access: {BETA_ACCESS_URL})."
            )
        if code == 404:
            return NebiusSandboxError(
                f"Nebius Sandboxes could not find the resource ({detail}). "
                "If this names an image, set ARBALEST_NEBIUS_<PYTHON|RUST|GO|NODE>_IMAGE to an available tag."
            )
        return NebiusSandboxError(f"Nebius Sandboxes {operation} returned HTTP {code}: {detail}")


# -- helpers --------------------------------------------------------------------------
def _json_object(response: httpx.Response) -> dict[str, Any]:
    data = response.json()
    if not isinstance(data, dict):
        raise NebiusSandboxError("Nebius Sandboxes returned an unexpected response shape")
    return data


def _require_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise NebiusSandboxError(f"Nebius Sandboxes response is missing '{key}'")
    return value


def _stream_bytes(stream: Any) -> tuple[bytes, bool]:
    if not isinstance(stream, dict):
        return b"", False
    value = stream.get("value")
    text = value if isinstance(value, str) else ""
    truncated = bool(stream.get("truncated"))
    if stream.get("encoding") == "base64":
        try:
            return base64.b64decode(text, validate=False), truncated
        except (binascii.Error, ValueError):
            return text.encode("utf-8", errors="replace"), truncated
    return text.encode("utf-8", errors="replace"), truncated


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    try:
        return min(max(float(raw), 0.05), 10.0) if raw is not None else None
    except ValueError:
        return None


def _error_detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:200].replace("\n", " ") or "no detail"
    detail = body.get("error") if isinstance(body, dict) else body
    return str(detail)[:300].replace("\n", " ") or "no detail"


def _safe(exc: BaseException) -> str:
    # Never include request headers: they carry the bearer token.
    return (str(exc).replace("\n", " ")[:300]) or exc.__class__.__name__
