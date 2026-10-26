"""`arbalest sandbox-check`: proves the verification sandbox runs code and is offline."""

from __future__ import annotations

import pytest

import arbalest_cli
from engine.services.docker_manager import SandboxResult, SandboxStatus


def _result(stdout: str = "", *, ok: bool = True) -> SandboxResult:
    return SandboxResult(
        status=SandboxStatus.COMPLETED if ok else SandboxStatus.ENGINE_ERROR,
        exit_code=0 if ok else None,
        stdout=stdout,
        stderr="",
        duration_ms=7,
        error=None if ok else "boom",
    )


class _Backend:
    def __init__(self, hello: SandboxResult, net: SandboxResult, *, healthy: bool = True) -> None:
        self._results = {"hello": hello, "net": net}
        self._healthy = healthy
        self.closed = False

    async def healthcheck(self) -> None:
        if not self._healthy:
            raise RuntimeError("beta access not enabled")

    async def run(self, spec, *, log_sink=None):
        return self._results["net" if "network" in spec.name_hint else "hello"]

    async def aclose(self) -> None:
        self.closed = True


async def _run(monkeypatch, backend: _Backend) -> int:
    monkeypatch.setattr(arbalest_cli, "_sandbox_manager", lambda: backend)
    monkeypatch.setattr(arbalest_cli, "sandbox_label", lambda: "TEST BACKEND")
    return await arbalest_cli._run_sandbox_check()


@pytest.mark.asyncio
async def test_working_offline_sandbox_passes(monkeypatch):
    backend = _Backend(_result("ARBALEST_SANDBOX_OK Linux x86_64 3.12.1"), _result("ARBALEST_NETWORK_BLOCKED OSError"))
    assert await _run(monkeypatch, backend) == 0
    assert backend.closed


@pytest.mark.asyncio
async def test_sandbox_that_reaches_the_internet_is_an_isolation_failure(monkeypatch):
    backend = _Backend(_result("ARBALEST_SANDBOX_OK Linux x86_64 3.12.1"), _result("ARBALEST_NETWORK_REACHABLE"))
    assert await _run(monkeypatch, backend) == 1


@pytest.mark.asyncio
async def test_unreachable_sandbox_is_a_mission_error_not_a_verdict(monkeypatch):
    backend = _Backend(_result(), _result(), healthy=False)
    assert await _run(monkeypatch, backend) == 2
    assert backend.closed


@pytest.mark.asyncio
async def test_failed_hello_probe_is_a_mission_error(monkeypatch):
    backend = _Backend(_result("", ok=False), _result("ARBALEST_NETWORK_BLOCKED OSError"))
    assert await _run(monkeypatch, backend) == 2


@pytest.mark.asyncio
async def test_inconclusive_network_probe_never_counts_as_offline(monkeypatch):
    backend = _Backend(_result("ARBALEST_SANDBOX_OK Linux x86_64 3.12.1"), _result("something else"))
    assert await _run(monkeypatch, backend) == 2


def test_misconfigured_sandbox_degrades_to_a_clean_failure_not_a_traceback(monkeypatch):
    monkeypatch.setenv("ARBALEST_SANDBOX_BACKEND", "nebius")
    monkeypatch.delenv("NEBIUS_PROJECT_ID", raising=False)
    monkeypatch.setenv("NEBIUS_API_KEY", "real-looking-key-123456")
    stub = arbalest_cli._sandbox_manager()
    import asyncio

    with pytest.raises(RuntimeError, match="NEBIUS_PROJECT_ID"):
        asyncio.run(stub.healthcheck())
