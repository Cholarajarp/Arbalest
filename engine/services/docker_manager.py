"""Hardened, ephemeral Docker execution for untrusted generated code.

The Docker daemon is a high-privilege dependency.  In production this service
must run on a dedicated, disposable runner node (not on the public API host),
with a rootless Docker daemon and an egress-deny network policy.  This module
adds defense in depth at the container boundary; it is not a substitute for
that runner isolation.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import os
import re
import shutil
import tempfile
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

import docker
from docker.errors import APIError, DockerException, ImageNotFound, NotFound
from docker.types import LogConfig, Ulimit

logger = logging.getLogger(__name__)

from engine.harness.injection_defense import sanitize_for_terminal  # noqa: E402

LogSink = Callable[[str, str], Awaitable[None] | None]

_MEBIBYTE = 1024 * 1024
_ALLOWED_EXECUTABLES: dict["SandboxRuntime", frozenset[str]] = {}
_IMAGE_DIGEST = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
# This path exists only inside a per-container tmpfs mounted with noexec,
# nosuid, and nodev.  It is intentionally not a host temporary directory.
_CONTAINER_TMP_DIR = "/tmp"  # nosec B108
_CONTAINER_BUILD_DIR = "/run/arbalest-build"
_CONTAINER_WORKSPACE_DIR = f"{_CONTAINER_BUILD_DIR}/workspace"
_CONTAINER_BOOTSTRAP_PATH = "/workspace/.arbalest-bootstrap.sh"
_CONTAINER_CARGO_TARGET_DIR = f"{_CONTAINER_BUILD_DIR}/cargo-target"
_CONTAINER_GO_CACHE_DIR = f"{_CONTAINER_BUILD_DIR}/go-cache"
_CONTAINER_GO_MOD_CACHE_DIR = f"{_CONTAINER_BUILD_DIR}/go-mod-cache"
_CONTAINER_GO_TMP_DIR = f"{_CONTAINER_BUILD_DIR}/go-tmp"
_BOOTSTRAP_FILENAME = ".arbalest-bootstrap.sh"
_BOOTSTRAP_SCRIPT = """#!/bin/sh
set -eu
umask 077
mkdir -p /run/arbalest-build/workspace \\
  /run/arbalest-build/cargo-target \\
  /run/arbalest-build/go-cache \\
  /run/arbalest-build/go-mod-cache \\
  /run/arbalest-build/go-tmp
cp -R /workspace/. /run/arbalest-build/workspace/
cd /run/arbalest-build/workspace
exec \"$@\"
"""


class SandboxRuntime(StrEnum):
    """Pre-approved runtime aliases; callers cannot choose arbitrary images."""

    PYTHON = "python"
    RUST = "rust"
    GO = "go"
    TYPESCRIPT = "typescript"


_ALLOWED_EXECUTABLES = {
    SandboxRuntime.PYTHON: frozenset({"python", "python3", "sh", "bash"}),
    SandboxRuntime.RUST: frozenset({"cargo", "rustc", "sh", "bash"}),
    SandboxRuntime.GO: frozenset({"go", "sh", "bash"}),
    SandboxRuntime.TYPESCRIPT: frozenset({"node", "npm", "npx", "ts-node", "sh", "bash"}),
}


class SandboxStatus(StrEnum):
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    ENGINE_ERROR = "engine_error"
    CANCELLED = "cancelled"


class SandboxValidationError(ValueError):
    """Raised before a container is created for an unsafe sandbox request."""


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    """Non-negotiable per-container resource and output ceilings."""

    timeout_seconds: float = 120.0
    memory_bytes: int = 512 * _MEBIBYTE
    cpu_nano: int = 1_000_000_000  # one vCPU
    pids_limit: int = 64
    tmpfs_bytes: int = 64 * _MEBIBYTE
    max_output_bytes: int = 512 * 1024
    max_source_bytes: int = 4 * _MEBIBYTE
    max_source_files: int = 64

    def validate(self) -> None:
        if not 1 <= self.timeout_seconds <= 300:
            raise SandboxValidationError("timeout_seconds must be between 1 and 300")
        if not 64 * _MEBIBYTE <= self.memory_bytes <= 2 * 1024 * _MEBIBYTE:
            raise SandboxValidationError("memory_bytes must be between 64 MiB and 2 GiB")
        if not 100_000_000 <= self.cpu_nano <= 2_000_000_000:
            raise SandboxValidationError("cpu_nano must be between 0.1 and 2 CPU")
        if not 16 <= self.pids_limit <= 256:
            raise SandboxValidationError("pids_limit must be between 16 and 256")
        if not 8 * _MEBIBYTE <= self.tmpfs_bytes <= 256 * _MEBIBYTE:
            raise SandboxValidationError("tmpfs_bytes must be between 8 and 256 MiB")
        if not 4 * 1024 <= self.max_output_bytes <= 2 * _MEBIBYTE:
            raise SandboxValidationError("max_output_bytes must be between 4 KiB and 2 MiB")


@dataclass(frozen=True, slots=True)
class SandboxRunSpec:
    """A validated request to execute generated source or an attack script.

    ``command`` is passed directly to Docker as an argv list, never through a
    host shell.  Source files are mounted read-only at ``/workspace``.
    """

    runtime: SandboxRuntime
    command: tuple[str, ...]
    files: Mapping[str, str | bytes]
    limits: SandboxLimits = field(default_factory=SandboxLimits)
    name_hint: str = "run"

    def validate(self) -> None:
        self.limits.validate()
        if not self.command:
            raise SandboxValidationError("command cannot be empty")
        if len(self.command) > 32 or any(not part or len(part) > 2_048 for part in self.command):
            raise SandboxValidationError("command has too many or oversized arguments")
        if self.command[0] not in _ALLOWED_EXECUTABLES[self.runtime]:
            raise SandboxValidationError(
                f"{self.command[0]!r} is not an approved executable for {self.runtime.value}"
            )
        if self.command[0] in {"sh", "bash"} and "-c" in self.command[1:]:
            raise SandboxValidationError("shell -c is prohibited; mount and execute a script file instead")
        if not self.files or len(self.files) > self.limits.max_source_files:
            raise SandboxValidationError("files must contain 1 to max_source_files entries")
        _validate_source_files(self.files, self.limits.max_source_bytes)


@dataclass(frozen=True, slots=True)
class SandboxResult:
    """Terminal result, including bounded stdout and stderr for the UI."""

    status: SandboxStatus
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    container_id: str | None = None
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status is SandboxStatus.COMPLETED and self.exit_code == 0


class DockerSandboxManager:
    """Create, run, kill, and remove strongly constrained Docker containers.

    Images are aliases owned by deployment configuration.  They should be
    pre-pulled by CI and pinned by digest in production.  This manager never
    pulls an image on demand, avoiding an untrusted workload choosing images or
    causing an unbounded registry pull.
    """

    def __init__(
        self,
        *,
        client: docker.DockerClient | None = None,
        images: Mapping[SandboxRuntime, str] | None = None,
        max_concurrent_runs: int = 2,
        seccomp_profile: str | None = None,
    ) -> None:
        if not 1 <= max_concurrent_runs <= 8:
            raise ValueError("max_concurrent_runs must be between 1 and 8")
        # Docker's default API-version negotiation performs I/O.  Defer that
        # operation to ``_get_client`` so constructing this service never
        # blocks an asyncio event loop.
        self._client = client
        self._owns_client = client is None
        self._images = dict(
            images
            or {
                SandboxRuntime.PYTHON: os.getenv("ARBALEST_SANDBOX_PYTHON_IMAGE", ""),
                SandboxRuntime.RUST: os.getenv("ARBALEST_SANDBOX_RUST_IMAGE", ""),
                SandboxRuntime.GO: os.getenv("ARBALEST_SANDBOX_GO_IMAGE", ""),
                SandboxRuntime.TYPESCRIPT: os.getenv("ARBALEST_SANDBOX_NODE_IMAGE", ""),
            }
        )
        missing_images = set(SandboxRuntime) - self._images.keys()
        invalid_images = [runtime for runtime, image in self._images.items() if not image.strip()]
        if missing_images or invalid_images:
            missing = ", ".join(sorted(runtime.value for runtime in missing_images))
            invalid = ", ".join(sorted(runtime.value for runtime in invalid_images))
            details = ", ".join(part for part in (f"missing: {missing}" if missing else "", f"blank: {invalid}" if invalid else "") if part)
            raise ValueError(f"Sandbox image configuration is incomplete ({details})")
        mutable_images = [runtime for runtime, image in self._images.items() if _IMAGE_DIGEST.fullmatch(image) is None]
        if mutable_images and os.getenv("ARBALEST_ENVIRONMENT") != "staging":
            runtimes = ", ".join(sorted(runtime.value for runtime in mutable_images))
            raise ValueError(f"Sandbox images must be pinned by digest (mutable: {runtimes})")
        self._semaphore = asyncio.Semaphore(max_concurrent_runs)
        self._client_lock = asyncio.Lock()
        self._seccomp_profile = seccomp_profile or os.getenv("ARBALEST_SANDBOX_SECCOMP_PROFILE")

    async def aclose(self) -> None:
        """Close the Docker API client when this manager owns it."""
        if self._owns_client and self._client is not None:
            await asyncio.to_thread(self._client.close)
            self._client = None

    async def healthcheck(self) -> None:
        """Verify the Docker daemon is reachable without creating a container."""
        client = await self._get_client()
        await asyncio.to_thread(client.ping)

    async def run(self, spec: SandboxRunSpec, *, log_sink: LogSink | None = None) -> SandboxResult:
        """Run untrusted code and guarantee a forceful container cleanup.

        ``log_sink`` receives output while the process is running and is
        async-compatible, so an orchestrator can forward stdout/stderr to a
        WebSocket without coupling this service to FastAPI. Returned output
        remains bounded by ``max_output_bytes``.
        """
        spec.validate()
        async with self._semaphore:
            return await self._run_one(spec, log_sink=log_sink)

    async def _run_one(self, spec: SandboxRunSpec, *, log_sink: LogSink | None) -> SandboxResult:
        started = time.monotonic()
        source_dir: Path | None = None
        container: Any | None = None
        container_id: str | None = None
        timed_out = False
        exit_code: int | None = None
        stdout = ""
        stderr = ""
        stdout_truncated = False
        stderr_truncated = False
        error: str | None = None
        status = SandboxStatus.ENGINE_ERROR
        live_log_task: asyncio.Task[None] | None = None

        try:
            source_dir = await asyncio.to_thread(_materialize_source, spec.files)
            image = self._images.get(spec.runtime)
            if image is None:
                raise SandboxValidationError(f"No configured image for runtime {spec.runtime.value!r}")
            client = await self._get_client()
            await asyncio.to_thread(client.images.get, image)
            container = await asyncio.to_thread(self._create_container, client, image, source_dir, spec)
            if container is None:
                raise DockerException("Docker returned no container for a validated sandbox request")
            container_id = getattr(container, "short_id", None) or getattr(container, "id", None)
            await asyncio.to_thread(container.start)
            if log_sink is not None:
                live_log_task = asyncio.create_task(
                    _stream_live_logs(container, log_sink), name=f"sandbox-log-{container_id or 'unknown'}"
                )

            try:
                wait_result = await asyncio.wait_for(
                    asyncio.to_thread(container.wait), timeout=spec.limits.timeout_seconds
                )
                exit_code = int(wait_result.get("StatusCode"))
                status = SandboxStatus.COMPLETED
            except TimeoutError:
                timed_out = True
                status = SandboxStatus.TIMED_OUT
                error = f"Execution exceeded the {spec.limits.timeout_seconds:g}s sandbox timeout"
                await self._force_kill(container)
                with contextlib.suppress(DockerException, asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.to_thread(container.wait), timeout=5)

            stdout_bytes, stderr_bytes = await self._read_logs(container)
            stdout, stdout_truncated = _decode_bounded(stdout_bytes, spec.limits.max_output_bytes)
            stderr, stderr_truncated = _decode_bounded(stderr_bytes, spec.limits.max_output_bytes)
            if timed_out:
                exit_code = 124

        except ImageNotFound:
            error = "Sandbox runtime image is not pre-pulled on this runner"
            logger.warning("Sandbox image is missing", extra={"runtime": spec.runtime.value})
        except (APIError, DockerException, OSError, TypeError, ValueError) as exc:
            if not timed_out:
                status = SandboxStatus.ENGINE_ERROR
            error = _safe_error(exc)
            logger.exception("Docker sandbox operation failed")
        except asyncio.CancelledError:
            status = SandboxStatus.CANCELLED
            error = "Sandbox task was cancelled"
            raise
        finally:
            # The cleanup runs for success, errors, timeouts, and cancellation.
            # `force=True` covers workloads that ignored their own termination.
            await self._cleanup(container, source_dir)
            if live_log_task is not None:
                await _finish_log_stream(live_log_task)

        duration_ms = int((time.monotonic() - started) * 1_000)
        result = SandboxResult(
            status=status,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            container_id=container_id,
            error=error,
        )
        if log_sink is not None and live_log_task is None:
            await _emit_logs(result, log_sink)
        return result

    async def _get_client(self) -> docker.DockerClient:
        if self._client is not None:
            return self._client
        async with self._client_lock:
            if self._client is None:
                self._client = await asyncio.to_thread(docker.from_env)
            return self._client

    def _create_container(
        self,
        client: docker.DockerClient,
        image: str,
        source_dir: Path,
        spec: SandboxRunSpec,
    ) -> Any:
        limits = spec.limits
        security_options = ["no-new-privileges:true"]
        if self._seccomp_profile:
            security_options.append(f"seccomp={self._seccomp_profile}")

        return client.containers.create(
            image=image,
            command=list(spec.command),
            # The trusted bootstrap copies the read-only input tree into a
            # bounded executable tmpfs before invoking the already-validated
            # argv.  This allows Rust/Go build artifacts to run without making
            # the original model-generated source mount writable.
            entrypoint=["/bin/sh", _CONTAINER_BOOTSTRAP_PATH],
            name=f"arbalest-{_safe_name(spec.name_hint)}-{os.urandom(4).hex()}",
            detach=True,
            privileged=False,
            working_dir="/workspace",
            user="65534:65534",  # nobody:nogroup
            network_disabled=True,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=security_options,
            pids_limit=limits.pids_limit,
            mem_limit=limits.memory_bytes,
            memswap_limit=limits.memory_bytes,  # prohibit swap amplification
            nano_cpus=limits.cpu_nano,
            ulimits=[Ulimit(name="nofile", soft=128, hard=128)],
            init=True,  # reaps descendants; prevents zombie accumulation
            environment={
                "HOME": _CONTAINER_TMP_DIR,
                "TMPDIR": _CONTAINER_TMP_DIR,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
                "CARGO_TARGET_DIR": _CONTAINER_CARGO_TARGET_DIR,
                "GOCACHE": _CONTAINER_GO_CACHE_DIR,
                "GOMODCACHE": _CONTAINER_GO_MOD_CACHE_DIR,
                "GOTMPDIR": _CONTAINER_GO_TMP_DIR,
                "PATH": "/usr/local/cargo/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            },
            volumes={str(source_dir): {"bind": "/workspace", "mode": "ro"}},
            tmpfs={
                _CONTAINER_TMP_DIR: f"rw,noexec,nosuid,nodev,mode=1777,size={limits.tmpfs_bytes}",
                _CONTAINER_BUILD_DIR: f"rw,exec,nosuid,nodev,mode=1777,size={limits.tmpfs_bytes}",
            },
            log_config=LogConfig(type=LogConfig.types.JSON, config={"max-size": "1m", "max-file": "1"}),
        )

    async def _read_logs(self, container: Any) -> tuple[bytes, bytes]:
        """Read separate bounded daemon logs after the container has stopped."""
        stdout, stderr = await asyncio.gather(
            asyncio.to_thread(container.logs, stdout=True, stderr=False, timestamps=False),
            asyncio.to_thread(container.logs, stdout=False, stderr=True, timestamps=False),
        )
        return bytes(stdout), bytes(stderr)

    async def _force_kill(self, container: Any) -> None:
        with contextlib.suppress(NotFound, APIError, DockerException):
            await asyncio.to_thread(container.kill)

    async def _cleanup(self, container: Any | None, source_dir: Path | None) -> None:
        """Best-effort cleanup must never conceal the primary run result."""
        if container is not None:
            with contextlib.suppress(NotFound, APIError, DockerException):
                await asyncio.to_thread(container.kill)
            with contextlib.suppress(NotFound, APIError, DockerException):
                await asyncio.to_thread(container.remove, force=True, v=True)
        if source_dir is not None:
            with contextlib.suppress(OSError):
                await asyncio.to_thread(shutil.rmtree, source_dir, True)


def _validate_source_files(files: Mapping[str, str | bytes], max_source_bytes: int) -> None:
    total_bytes = 0
    for relative_path, content in files.items():
        _safe_relative_path(relative_path)
        if not isinstance(content, (str, bytes)):
            raise SandboxValidationError(f"Unsupported content type for {relative_path!r}")
        byte_count = len(content.encode("utf-8")) if isinstance(content, str) else len(content)
        if byte_count > max_source_bytes:
            raise SandboxValidationError(f"Source file {relative_path!r} exceeds max_source_bytes")
        total_bytes += byte_count
    if total_bytes > max_source_bytes:
        raise SandboxValidationError("Combined source files exceed max_source_bytes")


def _materialize_source(files: Mapping[str, str | bytes]) -> Path:
    """Create a short-lived, symlink-free source tree with non-secret mode bits."""
    root = Path(tempfile.mkdtemp(prefix="arbalest-sandbox-"))
    try:
        root.chmod(0o755)
        for relative_path, content in files.items():
            safe_path = _safe_relative_path(relative_path)
            destination = root.joinpath(*safe_path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.parent.chmod(0o755)
            if isinstance(content, str):
                destination.write_text(content, encoding="utf-8", newline="\n")
            else:
                destination.write_bytes(content)
            destination.chmod(0o644)
        # Write after model-provided files so an artifact cannot replace the
        # fixed bootstrap that enforces the copy-on-write sandbox workspace.
        bootstrap = root / _BOOTSTRAP_FILENAME
        bootstrap.write_text(_BOOTSTRAP_SCRIPT, encoding="utf-8", newline="\n")
        bootstrap.chmod(0o555)
        return root
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def _safe_relative_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or ":" in value or value.startswith("/"):
        raise SandboxValidationError(f"Unsafe source path {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SandboxValidationError(f"Unsafe source path {value!r}")
    return path


def _decode_bounded(data: bytes, max_bytes: int) -> tuple[str, bool]:
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes] + b"\n[Arbalest output truncated]\n"
    decoded = data.decode("utf-8", errors="replace")
    # Sandbox output is untrusted: strip ANSI/control sequences so hostile code
    # cannot drive the operator's terminal or smuggle control bytes downstream.
    return sanitize_for_terminal(decoded), truncated


def _safe_name(value: str) -> str:
    normalized = "".join(character.lower() if character.isalnum() else "-" for character in value)
    return normalized.strip("-")[:32] or "run"


def _safe_error(exc: Exception) -> str:
    # Docker errors may include daemon implementation details. Keep the result
    # actionable but avoid passing an unbounded daemon response to the UI.
    message = str(exc).replace("\n", " ")[:512]
    return f"Docker sandbox error: {message or exc.__class__.__name__}"


async def _emit_logs(result: SandboxResult, sink: LogSink | None) -> None:
    if sink is None:
        return
    for stream, payload in (("stdout", result.stdout), ("stderr", result.stderr)):
        if not payload:
            continue
        emitted = sink(stream, payload)
        if inspect.isawaitable(emitted):
            await emitted


async def _stream_live_logs(container: Any, sink: LogSink) -> None:
    """Forward Docker's multiplexed attach stream without blocking asyncio.

    Docker's Python SDK exposes a blocking iterator.  A worker thread reads it
    and an asyncio consumer invokes the caller's sink, so an orchestrator can
    safely turn each chunk into a WebSocket event while the container runs.
    """
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[tuple[str, bytes] | None] = asyncio.Queue(maxsize=256)

    def enqueue(item: tuple[str, bytes] | None) -> None:
        with contextlib.suppress(asyncio.QueueFull):
            queue.put_nowait(item)

    def read_stream() -> None:
        try:
            stream = container.attach(stream=True, logs=True, stdout=True, stderr=True, demux=True)
            for stdout, stderr in stream:
                if stdout:
                    loop.call_soon_threadsafe(enqueue, ("stdout", bytes(stdout)))
                if stderr:
                    loop.call_soon_threadsafe(enqueue, ("stderr", bytes(stderr)))
        except (APIError, DockerException, OSError):
            logger.debug("Live sandbox log stream ended unexpectedly", exc_info=True)
        finally:
            loop.call_soon_threadsafe(enqueue, None)

    reader = asyncio.create_task(asyncio.to_thread(read_stream), name="docker-log-reader")
    try:
        while True:
            item = await queue.get()
            if item is None:
                return
            stream, payload = item
            emitted = sink(stream, payload.decode("utf-8", errors="replace"))
            if inspect.isawaitable(emitted):
                await emitted
    finally:
        if not reader.done():
            reader.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await reader


async def _finish_log_stream(task: asyncio.Task[None]) -> None:
    """Drain a completed container's log task without leaking it on shutdown."""
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=5)
    except TimeoutError:
        logger.debug("Timed out draining live sandbox logs; cancelling log task")
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
    except asyncio.CancelledError:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
        raise
    except Exception:
        # A caller-provided log sink must not turn a completed sandbox run into
        # an engine failure. The final bounded stdout/stderr is still returned.
        logger.debug("Live sandbox log task failed", exc_info=True)
