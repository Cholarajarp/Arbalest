"""Regression coverage for parallel SAST discovery, coverage, and parsing."""

from __future__ import annotations

import asyncio
import json

import pytest
from pydantic import ValidationError

from engine.agents import sast_agent
from engine.agents.sast_agent import SastAgent, _parse_sast_result


class _Provider:
    name = "test"
    settings = None

    async def generate_structured(self, request):
        return json.dumps(
            {
                "analysis_summary": "Model-added metadata must not break SAST.",
                "findings": [
                    {
                        "name": "Command injection",
                        "cwe_id": "CWE-78",
                        "severity": "CRITICAL",
                        "details": "Unsanitized input reaches a shell command.",
                        "file": "app/handler.py",
                        "snippet": "subprocess.run(user_value, shell=True)",
                        "line": 42,
                    }
                ],
            }
        )


@pytest.mark.asyncio
async def test_sast_recovers_valid_finding_from_common_provider_variations():
    findings = await SastAgent(_Provider()).analyze({"app/handler.py": "pass\n"})

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-78"
    assert findings[0].severity == "critical"
    assert findings[0].affected_nodes == ["app/handler.py"]


def test_sast_rejects_a_response_without_usable_findings():
    malformed = json.dumps({"vulnerabilities": [{"name": "Missing required fields"}]})

    with pytest.raises(ValidationError):
        _parse_sast_result(malformed)


def _batch_number(request):
    return int(request.input_text.split()[2].split("/")[0])


def _batch_response(number, path=None):
    return json.dumps(
        {
            "vulnerabilities": [
                {
                    "vulnerability_name": "Command injection",
                    "cwe": "CWE-78",
                    "severity": "high",
                    "description": "Untrusted input reaches a shell command.",
                    "affected_file": path or f"src/{number:02}.py",
                    "evidence": f"batch {number} evidence",
                }
            ]
        }
    )


def _sources(count):
    return {f"src/{number:02}.py": "pass #x\n" for number in range(1, count + 1)}


@pytest.mark.parametrize("concurrency", [True, 0, -1, 33, 1.5, "2", None])
def test_sast_rejects_invalid_concurrency(concurrency):
    with pytest.raises(ValueError, match="concurrency"):
        SastAgent(_Provider(), concurrency=concurrency)


@pytest.mark.asyncio
@pytest.mark.parametrize("concurrency", [None, 2, 3])
async def test_batch_discovery_is_bounded_and_default_constructor_is_serial(monkeypatch, concurrency):
    monkeypatch.setattr(sast_agent, "_DEFAULT_BATCH_CHARS", 8)

    class Provider(_Provider):
        active = 0
        peak = 0
        calls = 0

        async def generate_structured(self, request):
            self.calls += 1
            self.active += 1
            self.peak = max(self.peak, self.active)
            try:
                await asyncio.sleep(0)
                return _batch_response(_batch_number(request))
            finally:
                self.active -= 1

    provider = Provider()
    agent = SastAgent(provider) if concurrency is None else SastAgent(provider, concurrency=concurrency)
    findings = await agent.analyze(_sources(6))
    assert provider.peak == (concurrency or 1)
    assert provider.calls == 6
    assert provider.active == 0
    assert [item.affected_nodes for item in findings] == [[f"src/{i:02}.py"] for i in range(1, 7)]
    assert agent.coverage.complete
    assert agent.coverage.analyzed_files == 6
    assert agent.coverage.analyzed_chars == 48
    assert agent.coverage.batches == 6


@pytest.mark.asyncio
async def test_reverse_completion_keeps_findings_coverage_and_ids_deterministic(monkeypatch):
    monkeypatch.setattr(sast_agent, "_DEFAULT_BATCH_CHARS", 8)

    class Provider(_Provider):
        def __init__(self, reverse=False):
            self.reverse = reverse
            self.started = {i: asyncio.Event() for i in range(1, 4)}
            self.release = {i: asyncio.Event() for i in range(1, 4)}
            self.done = {i: asyncio.Event() for i in range(1, 4)}

        async def generate_structured(self, request):
            number = _batch_number(request)
            self.started[number].set()
            if self.reverse:
                await self.release[number].wait()
            self.done[number].set()
            return _batch_response(number)

    provider = Provider(reverse=True)
    agent = SastAgent(provider, concurrency=3)
    async with asyncio.timeout(2):
        task = asyncio.create_task(agent.analyze(_sources(3)))
        try:
            await asyncio.gather(*(event.wait() for event in provider.started.values()))
            assert not agent.coverage.complete
            assert agent.coverage.analyzed_chars == 0
            for number in (3, 2, 1):
                provider.release[number].set()
                await provider.done[number].wait()
            parallel = await task
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    serial_agent = SastAgent(Provider())
    # Input mapping insertion order must not affect planned batch order either.
    serial = await serial_agent.analyze(dict(reversed(list(_sources(3).items()))))
    assert parallel == serial
    assert agent.coverage == serial_agent.coverage
    assert [item.affected_nodes for item in parallel] == [["src/01.py"], ["src/02.py"], ["src/03.py"]]


@pytest.mark.asyncio
async def test_split_file_deduplication_uses_planned_not_completion_order(monkeypatch):
    monkeypatch.setattr(sast_agent, "_DEFAULT_BATCH_CHARS", 8)

    class Provider(_Provider):
        async def generate_structured(self, request):
            number = _batch_number(request)
            await asyncio.sleep((4 - number) * 0.005)
            return _batch_response(number, "app.py")

    agent = SastAgent(Provider(), concurrency=3)
    findings = await agent.analyze({"app.py": "pass #x\n" * 3})
    assert len(findings) == 1
    assert findings[0].evidence == ["batch 1 evidence"]
    assert agent.coverage.complete
    assert agent.coverage.analyzed_files == 1
    assert agent.coverage.analyzed_chars == 24
    assert agent.coverage.batches == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["provider", "malformed", "timeout"])
@pytest.mark.parametrize("split_file", [False, True])
async def test_failed_batches_are_omitted_and_siblings_joined(monkeypatch, failure, split_file):
    monkeypatch.setattr(sast_agent, "_DEFAULT_BATCH_CHARS", 8)

    class Provider(_Provider):
        def __init__(self):
            self.first_done = asyncio.Event()
            self.cancelled = set()
            self.active = 0

        async def generate_structured(self, request):
            number = _batch_number(request)
            self.active += 1
            try:
                if number == 1:
                    await asyncio.sleep(0)
                    self.first_done.set()
                    return _batch_response(number, "app.py" if split_file else None)
                if number == 2:
                    await self.first_done.wait()
                    if failure == "provider":
                        raise RuntimeError("provider offline")
                    if failure == "timeout":
                        raise TimeoutError("provider deadline")
                    return "not JSON"
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled.add(number)
                raise
            finally:
                self.active -= 1

    provider = Provider()
    agent = SastAgent(provider, concurrency=3)
    expected = {"provider": RuntimeError, "malformed": ValidationError, "timeout": TimeoutError}[failure]
    async with asyncio.timeout(2):
        with pytest.raises(expected):
            await agent.analyze({"app.py": "pass #x\n" * 3} if split_file else _sources(3))
    assert provider.active == 0
    assert provider.cancelled == {3}
    assert not agent.coverage.complete
    assert agent.coverage.analyzed_files == (0 if split_file else 1)
    assert agent.coverage.analyzed_chars == 8
    assert agent.coverage.batches == 1
    assert agent.coverage.omitted_files == (("app.py",) if split_file else ("src/02.py", "src/03.py"))


@pytest.mark.asyncio
async def test_scan_timeout_cancels_workers_and_never_credits_queued_batches(monkeypatch):
    monkeypatch.setattr(sast_agent, "_DEFAULT_BATCH_CHARS", 8)

    class Provider(_Provider):
        def __init__(self):
            self.started = set()
            self.cancelled = set()

        async def generate_structured(self, request):
            number = _batch_number(request)
            self.started.add(number)
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled.add(number)

    provider = Provider()
    agent = SastAgent(provider, concurrency=2)
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.02):
            await agent.analyze(_sources(6))
    assert provider.started == provider.cancelled == {1, 2}
    assert not agent.coverage.complete
    assert agent.coverage.analyzed_files == agent.coverage.analyzed_chars == agent.coverage.batches == 0
    assert agent.coverage.omitted_files == tuple(_sources(6))


@pytest.mark.asyncio
async def test_character_cap_omissions_remain_partial_with_parallel_batches(monkeypatch):
    monkeypatch.setattr(sast_agent, "_DEFAULT_BATCH_CHARS", 8)
    monkeypatch.setattr(sast_agent, "_bounded_total_chars", lambda: 12)

    class Provider(_Provider):
        async def generate_structured(self, request):
            await asyncio.sleep(0)
            return '{"vulnerabilities": []}'

    agent = SastAgent(Provider(), concurrency=3)
    assert await agent.analyze(_sources(3)) == []
    assert not agent.coverage.complete
    assert agent.coverage.analyzed_files == 1
    assert agent.coverage.analyzed_chars == 12
    assert agent.coverage.eligible_chars == 24
    assert agent.coverage.batches == 2
    assert agent.coverage.omitted_files == ("src/02.py", "src/03.py")
