"""Durable scan scheduling and conservative provider-call reservations.

Cost figures are operator-supplied upper-bound assumptions, NOT actual billing.
Reservations are never refunded, including on errors/cancellation. Tool loops reserve
``max_turns`` calls up front; SDK-internal HTTP retries are not observable here.
The deadline includes time spent between checkpoint creation and resume.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import math
import os
import re
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from engine.agents.architect_agent import ThreatFinding
from engine.agents.secret_scanner import redact_secrets
from engine.services.ai_provider import AIModelInfo, AIProvider, AIProviderSettings, StructuredOutputRequest


class CheckpointError(RuntimeError):
    """A checkpoint is incompatible, corrupt, busy, or cannot be persisted."""


class ScanBudgetExceeded(RuntimeError):
    """A deadline or conservative reservation limit prevented more work."""


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Strict workflow configuration; unknown fields and coercions are rejected.

    ``per_call_model_calls`` reserves a caller-assumed number of model attempts
    per adapter invocation (increase it to cover SDK-internal retries).
    ``per_call_reserve_usd`` is a caller-provided worst-case cost assumption per
    reserved model attempt. A cost cap requires
    this assumption. Neither reservations nor call counts are vendor usage data.
    ``max_retries`` applies only to failed/interrupted phases, never partial ones.
    """

    concurrency: int = 4
    max_seconds: float = 300.0
    max_model_calls: int = 100
    per_call_model_calls: int = 1
    max_cost_usd: float | None = None
    per_call_reserve_usd: float | None = None
    call_timeout_seconds: float = 60.0
    max_retries: int = 1
    # Opt-in recon-driven review hypotheses: one extra model call that steers
    # the SAST reviewer with target-specific attack-surface priorities.
    review_hypotheses: bool = False
    # Opt-in adversarial self-verification: one extra model call that confirms
    # or challenges each SAST finding against the source. Findings are only
    # annotated, never deleted.
    sast_self_check: bool = False

    def __post_init__(self) -> None:
        for name, low, high in (
            ("concurrency", 1, 32),
            ("max_model_calls", 0, 1_000_000),
            ("per_call_model_calls", 1, 100),
            ("max_retries", 0, 10),
        ):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} must be an integer in [{low}, {high}]")
        for name in ("max_seconds", "call_timeout_seconds", "max_cost_usd", "per_call_reserve_usd"):
            value = getattr(self, name)
            if value is None and name in {"max_cost_usd", "per_call_reserve_usd"}:
                continue
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be a finite nonnegative number")
            if name in {"max_seconds", "call_timeout_seconds", "per_call_reserve_usd"} and value == 0:
                raise ValueError(f"{name} must be positive")
        if self.max_cost_usd is not None and self.per_call_reserve_usd is None:
            raise ValueError("max_cost_usd requires an explicit per_call_reserve_usd assumption")

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> ScanOptions:
        return cls(**dict(values))


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def provider_identity(provider: Any) -> dict[str, Any]:
    """Allowlisted, credential-free identity (never serialize provider objects)."""
    settings = getattr(provider, "settings", None)
    identity: dict[str, Any] = {
        "adapter": f"{type(provider).__module__}.{type(provider).__qualname__}",
        "name": str(getattr(provider, "name", "unknown")),
    }
    for name in ("provider", "selected_model", "reasoning_effort", "temperature", "max_output_tokens", "streaming"):
        value = getattr(settings, name, None)
        if value is None or type(value) in (str, int, float, bool):
            identity[name] = value
    endpoint = getattr(settings, "base_url", None)
    if endpoint:
        parsed = urlsplit(endpoint)
        key = getattr(settings, "api_key", None)
        credential = (
            getattr(key, "get_secret_value")()
            if hasattr(key, "get_secret_value")
            else (key if isinstance(key, str) else "")
        )
        path = parsed.path.replace(credential, "[credential]") if credential else parsed.path
        # Query, fragment and userinfo are excluded; deployment paths matter.
        identity["endpoint"] = (parsed.scheme, parsed.hostname, parsed.port, path)
    return identity


@dataclass
class PhaseResult:
    findings: list[ThreatFinding] = field(default_factory=list)
    status: str = "ok"
    detail: str = ""
    required: bool = True
    coverage: dict[str, Any] | None = None


class _Checkpoint:
    """One atomic manifest: phase completion and reservations share a transaction.

    OS advisory locks are released on process death, unlike stale PID/lock files.
    Checkpoints are local trusted artifacts, not authenticated interchange files.
    """

    def __init__(self, directory: Path):
        self.directory = directory
        self.path = directory / "scan-workflow.json"
        self.handle: Any = None
        try:
            directory.mkdir(parents=True, exist_ok=True)
            self.handle = (directory / "scan-workflow.lock").open("a+b")
            self.handle.seek(0)
            if sys.platform == "win32":
                import msvcrt

                if not self.handle.read(1):
                    self.handle.write(b"\0")
                    self.handle.flush()
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl = __import__("fcntl")
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.close()
            raise CheckpointError("checkpoint directory unavailable or already in use") from exc

    def read(self) -> dict[str, Any]:
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
            state = document["state"]
            if document["checksum"] != _digest(state):
                raise ValueError("checksum mismatch")
            return state
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise CheckpointError("checkpoint missing or corrupt") from exc

    def write(self, state: dict[str, Any]) -> None:
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=".scan-", suffix=".tmp", dir=self.directory)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"state": state, "checksum": _digest(state)}, stream, sort_keys=True, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name != "nt":
                directory_fd = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except (OSError, ValueError, TypeError) as exc:
            raise CheckpointError("atomic checkpoint write failed") from exc
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None


class ScanWorkflow:
    """Internal phase runner; create/close within one run_agent_swarm invocation."""

    def __init__(
        self,
        provider: Any,
        sources: Mapping[str, str],
        options: ScanOptions,
        checkpoint_dir: str | Path | None = None,
        resume: bool = False,
        *,
        context: Any = None,
    ):
        if not isinstance(options, ScanOptions):
            raise TypeError("options must be ScanOptions")
        if resume and checkpoint_dir is None:
            raise CheckpointError("resume requires checkpoint_dir")
        self.options = options
        self.semaphore = asyncio.Semaphore(options.concurrency)
        self.store: _Checkpoint | None = None
        # Keep raw source and credential material in memory ONLY for redaction.
        source_fragments = {line.strip() for text in sources.values() for line in text.splitlines() if line.strip()}
        # Findings can quote a literal without its surrounding assignment. Mask
        # literals too, even when they are not recognized credential formats.
        for text in sources.values():
            source_fragments.update(match[1] for match in re.findall(r"([\"'])([^\r\n\"']{4,})\1", text))
        self._source_lines = sorted(source_fragments, key=len, reverse=True)
        settings = getattr(provider, "settings", None)
        key = getattr(settings, "api_key", None)
        provider_key = (
            getattr(key, "get_secret_value")()
            if hasattr(key, "get_secret_value")
            else (key if isinstance(key, str) else "")
        )
        self._credentials = {provider_key} if provider_key else set()
        endpoint = getattr(settings, "base_url", None)
        if endpoint:
            parsed = urlsplit(endpoint)
            self._credentials.update(unquote(value) for value in (parsed.username, parsed.password) if value)
            self._credentials.update(value for _, value in parse_qsl(parsed.query) if value)
        identity = _digest(
            {
                "sources": sorted((path, hashlib.sha256(text.encode()).hexdigest()) for path, text in sources.items()),
                "options": asdict(options),
                "provider": provider_identity(provider),
                "context": context,
            }
        )
        try:
            self.store = _Checkpoint(Path(checkpoint_dir)) if checkpoint_dir is not None else None
            if resume:
                assert self.store is not None
                self.state = self.store.read()
                self._validate_state(identity)
            else:
                if self.store is not None and self.store.path.exists():
                    raise CheckpointError("checkpoint exists; use resume or a new directory")
                self.state = {
                    "version": 1,
                    "identity": identity,
                    "expires_at": time.time() + options.max_seconds,
                    "reserved_model_calls": 0,
                    "phases": {},
                }
                self.persist()
            self.deadline = time.monotonic() + max(0.0, self.state["expires_at"] - time.time())
        except BaseException:
            self.close()
            raise
        self.provider = BudgetedProvider(provider, self)

    def _validate_state(self, identity: str) -> None:
        try:
            state = self.state
            if state["version"] != 1 or state["identity"] != identity:
                raise CheckpointError("checkpoint source/options/provider/context fingerprint mismatch")
            calls = state["reserved_model_calls"]
            if type(calls) is not int or not 0 <= calls <= self.options.max_model_calls:
                raise ValueError("invalid call reservations")
            if type(state["expires_at"]) not in (int, float) or not math.isfinite(state["expires_at"]):
                raise ValueError("invalid deadline")
            if not isinstance(state["phases"], dict):
                raise ValueError("invalid phases")
            for record in state["phases"].values():
                if type(record["attempts"]) is not int or not 0 <= record["attempts"] <= self.options.max_retries + 1:
                    raise ValueError("invalid attempts")
                self._decode(record)
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckpointError("invalid checkpoint state") from exc

    def persist(self) -> None:
        if self.store is not None:
            self.store.write(self.state)

    def close(self) -> None:
        if self.store is not None:
            self.store.close()

    def remaining(self) -> float:
        remaining = min(self.deadline - time.monotonic(), self.state["expires_at"] - time.time())
        if remaining <= 0:
            raise ScanBudgetExceeded("scan deadline exhausted")
        return remaining

    def reserve(self, calls: int) -> None:
        self.remaining()
        total = self.state["reserved_model_calls"] + calls * self.options.per_call_model_calls
        if total > self.options.max_model_calls:
            raise ScanBudgetExceeded("model-call reservation limit exhausted")
        reserve = self.options.per_call_reserve_usd
        if self.options.max_cost_usd is not None and reserve is not None:
            # Decimal strings avoid allowing an extra call at a floating boundary.
            from decimal import Decimal

            if Decimal(str(reserve)) * total > Decimal(str(self.options.max_cost_usd)):
                raise ScanBudgetExceeded("assumed cost reservation limit exhausted (not actual billing)")
        self.state["reserved_model_calls"] = total
        self.persist()  # Synchronous transaction before any provider request can start.

    @property
    def budget_summary(self) -> dict[str, Any]:
        calls = self.state["reserved_model_calls"]
        reserve = self.options.per_call_reserve_usd
        return {
            "reserved_model_calls": calls,
            "assumed_cost_usd": calls * reserve if reserve is not None else None,
            "per_call_reserve_usd": reserve,
            "per_call_model_calls": self.options.per_call_model_calls,
            "actual_cost_usd": None,
            "accounting": "conservative reservations, not vendor usage or actual billing",
        }

    def _sanitize(self, value: Any, *, source: bool = True) -> Any:
        if isinstance(value, str):
            for credential in sorted(self._credentials, key=len, reverse=True):
                value = value.replace(credential, "[credential redacted]")
            if source:
                for line in self._source_lines:
                    if line in value:
                        value = value.replace(line, "[source redacted]")
            return redact_secrets(value)
        if isinstance(value, (list, tuple)):
            return [self._sanitize(item, source=source) for item in value]
        if isinstance(value, dict):
            return {
                self._sanitize(key, source=False): self._sanitize(item, source=source) for key, item in value.items()
            }
        return value

    @staticmethod
    def _decode(record: dict[str, Any]) -> PhaseResult:
        if record["status"] not in {"ok", "partial", "error", "skipped", "running"}:
            raise ValueError("invalid phase status")
        if not isinstance(record["detail"], str) or type(record["required"]) is not bool:
            raise ValueError("invalid phase metadata")
        if record["coverage"] is not None and not isinstance(record["coverage"], dict):
            raise ValueError("invalid coverage")
        return PhaseResult(
            findings=[ThreatFinding.model_validate(item) for item in record["findings"]],
            status=record["status"],
            detail=record["detail"],
            required=record["required"],
            coverage=record["coverage"],
        )

    def phase_fingerprint(self, names: list[str]) -> str:
        return _digest({name: self.state["phases"].get(name) for name in names})

    async def run_phase(
        self,
        name: str,
        operation: Callable[[], Awaitable[PhaseResult]],
        *,
        dependency: str | None = None,
        coverage_getter: Callable[[], dict[str, Any] | None] | None = None,
    ) -> PhaseResult:
        def failure_coverage() -> dict[str, Any] | None:
            if coverage_getter is None:
                return None
            try:
                return coverage_getter()
            except Exception:
                # Coverage collection must not hide the original phase failure.
                return {"complete": False, "detail": "coverage unavailable after specialist failure"}

        cached = self.state["phases"].get(name)
        if cached is not None and cached.get("dependency") != dependency:
            cached = None
        if cached is not None and cached["status"] in {"ok", "partial", "skipped"}:
            return self._decode(cached)
        attempts = cached["attempts"] if cached else 0
        outcome = self._decode(cached) if cached else PhaseResult(status="error", detail="phase not started")
        if outcome.status == "running":
            outcome.status, outcome.detail = "error", "phase interrupted before completion"
            if attempts > self.options.max_retries:
                return self._save_phase(name, outcome, attempts, dependency)
        async with self.semaphore:
            while attempts <= self.options.max_retries:
                attempts += 1
                self._save_phase(name, PhaseResult(status="running", coverage=outcome.coverage), attempts, dependency)
                try:
                    async with asyncio.timeout(self.remaining()):
                        outcome = await operation()
                    self.remaining()  # Also fail closed when synchronous work overran the deadline.
                except CheckpointError:
                    raise
                except asyncio.CancelledError:
                    self._save_phase(
                        name,
                        PhaseResult(
                            status="running", detail="phase interrupted before completion", coverage=failure_coverage()
                        ),
                        attempts,
                        dependency,
                    )
                    raise
                except (ScanBudgetExceeded, TimeoutError) as exc:
                    outcome = PhaseResult(
                        status="error",
                        detail=f"{type(exc).__name__}: budget/deadline exhausted",
                        coverage=failure_coverage(),
                    )
                    self._save_phase(name, outcome, attempts, dependency)
                    break  # Retrying an exhausted budget cannot improve coverage.
                except Exception as exc:
                    # Exception messages can contain entire requests, source or keys.
                    outcome = PhaseResult(
                        status="error",
                        detail=f"{type(exc).__name__}: specialist failed",
                        coverage=failure_coverage(),
                    )
                outcome = self._save_phase(name, outcome, attempts, dependency)
                if outcome.status != "error":
                    break
        return outcome

    def _save_phase(self, name: str, outcome: PhaseResult, attempts: int, dependency: str | None = None) -> PhaseResult:
        record: dict[str, Any] = {
            "dependency": dependency,
            "attempts": attempts,
            "status": outcome.status,
            "detail": outcome.detail,
            "required": outcome.required,
            "coverage": outcome.coverage,
            "findings": [finding.model_dump(mode="json") for finding in outcome.findings],
        }
        if self.store is not None:
            # Do not persist raw code evidence; use the same sanitized results in
            # fresh and resumed runs so downstream RAG sees identical inputs.
            record["detail"] = self._sanitize(record["detail"])
            # Coverage paths and normalized finding identifiers are metadata,
            # not source evidence, even when code contains the same literals.
            record["coverage"] = self._sanitize(record["coverage"], source=False)
            for finding in record["findings"]:
                for key in ("finding_id", "cwe", "summary", "evidence", "affected_nodes"):
                    finding[key] = self._sanitize(finding[key], source=key in {"summary", "evidence"})
                for key, limit in (("finding_id", 128), ("cwe", 64), ("summary", 4_000)):
                    finding[key] = finding[key][:limit]
        self.state["phases"][name] = record
        self.persist()
        return self._decode(record)


class BudgetedProvider(AIProvider):
    """Wrap generation, streaming and tools without leaking an unbudgeted method.

    Current agents use generate_structured. Explicit aliases support adapters
    exposing generate/stream variants. Tool-loop calls reserve max_turns, not one
    wrapper invocation. Other methods are intentionally NOT delegated.
    """

    def __init__(self, provider: AIProvider, workflow: ScanWorkflow):
        self._provider = provider
        self._workflow = workflow

    @property
    def name(self) -> str:
        return self._provider.name

    @property
    def settings(self) -> AIProviderSettings:
        return self._provider.settings

    async def _call(self, method: str, *args: Any, calls: int = 1, **kwargs: Any) -> Any:
        self._workflow.reserve(calls)
        timeout = min(self._workflow.remaining(), self._workflow.options.call_timeout_seconds)
        call_deadline = time.monotonic() + timeout
        async with asyncio.timeout(timeout) as call_timeout:
            result = await getattr(self._provider, method)(*args, **kwargs)
        if call_timeout.expired() or time.monotonic() >= call_deadline:
            raise ScanBudgetExceeded("provider call deadline exhausted")
        self._workflow.remaining()
        return result

    async def list_models(self) -> list[AIModelInfo]:
        # Discovery is deadline-bound but does not invoke model inference.
        return await self._call("list_models", calls=0)

    async def generate_structured(self, request: StructuredOutputRequest) -> str:
        return await self._call("generate_structured", request)

    async def generate(self, *args: Any, **kwargs: Any) -> Any:
        return await self._call("generate", *args, **kwargs)

    async def run_with_tools(self, *args: Any, **kwargs: Any) -> str:
        turns = kwargs.get("max_turns")
        if type(turns) is not int or turns < 1:
            raise ValueError("budgeted tool loops require explicit positive max_turns")
        return await self._call("run_with_tools", *args, calls=turns, **kwargs)

    async def _stream(self, method: str, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        self._workflow.reserve(1)
        timeout = min(self._workflow.remaining(), self._workflow.options.call_timeout_seconds)
        iterator = None
        call_deadline = time.monotonic() + timeout

        def remaining() -> float:
            available = min(self._workflow.remaining(), call_deadline - time.monotonic())
            if available <= 0:
                raise ScanBudgetExceeded("provider stream deadline exhausted")
            return available

        try:
            async with asyncio.timeout(remaining()):
                iterator = getattr(self._provider, method)(*args, **kwargs)
                if inspect.isawaitable(iterator):
                    iterator = await iterator
            iterator = aiter(iterator)
            while True:
                try:
                    # Never leave a timeout context active across yield: that
                    # would cancel consumer work while the stream is suspended.
                    async with asyncio.timeout(remaining()):
                        chunk = await anext(iterator)
                except StopAsyncIteration:
                    remaining()
                    break
                remaining()  # Detect a provider suppressing timeout cancellation.
                yield chunk
        finally:
            if iterator is not None and hasattr(iterator, "aclose"):
                async with asyncio.timeout(min(1.0, timeout)):
                    await iterator.aclose()

    def stream(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        return self._stream("stream", *args, **kwargs)

    def stream_structured(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        return self._stream("stream_structured", *args, **kwargs)

    async def aclose(self) -> None:
        # The caller, not an individual specialist, owns provider lifetime.
        return None
