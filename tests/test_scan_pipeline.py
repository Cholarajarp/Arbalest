"""Scan pipeline — real orchestration and per-agent degradation.

The failing provider below is a TEST-ONLY double that lives inside this file;
it exists to exercise the real error-path guarantees (one failed specialist
never aborts the mission). The shipped product contains no mocks.
"""

from __future__ import annotations

import asyncio

import pytest

from engine.agents import sast_agent
from engine.services import scan_pipeline
from engine.services.scan_pipeline import ScanOptions, run_agent_swarm


class _OfflineCore:
    """Simulates an AI core that is unreachable — for error-path testing only."""

    name = "offline-test-core"
    settings = None

    async def generate_structured(self, request):
        raise RuntimeError("core offline")

    async def list_models(self):
        return []

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_specialist_failure_never_aborts_mission():
    sources = {"app/main.py": "x = 1\n"}
    swarm = await run_agent_swarm(_OfflineCore(), sources, None)
    assert set(swarm.stats) == {"sast", "secrets", "semgrep", "sca", "taint", "threat_rag"}
    assert swarm.stats["taint"].status == "ok"
    assert swarm.stats["sast"].status == "error"  # core offline surfaced, not swallowed
    assert swarm.findings == []  # mission still completed


@pytest.mark.asyncio
async def test_swarm_result_severity_counts_empty():
    swarm = await run_agent_swarm(_OfflineCore(), {"app/main.py": "x = 1\n"}, None)
    assert swarm.severity_counts == {}


@pytest.mark.asyncio
async def test_buckets_populated_even_on_error():
    swarm = await run_agent_swarm(_OfflineCore(), {"app/main.py": "x = 1\n"}, None)
    assert set(swarm.buckets) == {"sast", "secrets", "semgrep", "sca", "taint", "threat_rag"}


@pytest.mark.asyncio
@pytest.mark.parametrize("concurrency", [1, 2, 3])
@pytest.mark.parametrize("max_model_calls", [100, 2])
async def test_workflow_concurrency_reaches_real_sast_batch_discovery(monkeypatch, concurrency, max_model_calls):
    monkeypatch.setattr(sast_agent, "_DEFAULT_BATCH_CHARS", 8)
    monkeypatch.setattr(scan_pipeline.SemgrepAgent, "available", property(lambda self: False))

    async def no_rag(self, **kwargs):
        return []

    monkeypatch.setattr(scan_pipeline.ThreatIntelRAG, "analyze", no_rag)
    monkeypatch.setattr(scan_pipeline, "get_vector_memory", lambda *args: None)

    class ParallelCore(_OfflineCore):
        def __init__(self):
            self.active = 0
            self.peak = 0
            self.calls = 0

        async def generate_structured(self, request):
            assert request.schema_name == "sast-analysis-result"
            self.active += 1
            self.calls += 1
            self.peak = max(self.peak, self.active)
            try:
                await asyncio.sleep(0)
                return '{"vulnerabilities": []}'
            finally:
                self.active -= 1

    provider = ParallelCore()
    result = await run_agent_swarm(
        provider,
        {f"src/{number}.py": "pass #x\n" for number in range(6)},
        options=ScanOptions(concurrency=concurrency, max_model_calls=max_model_calls, max_retries=0),
    )
    assert provider.peak == min(concurrency, max_model_calls)
    assert provider.calls == min(6, max_model_calls)
    assert provider.active == 0
    if max_model_calls < 6:
        assert result.stats["sast"].status == "error"
        assert not result.complete
    else:
        assert result.stats["sast"].status == "ok"
        assert result.stats["sast"].coverage["complete"]
        assert result.stats["sast"].coverage["batches"] == 6
    assert result.budget["reserved_model_calls"] == min(6, max_model_calls)


@pytest.mark.asyncio
async def test_parallel_sast_provider_timeouts_cannot_report_clean_scan(monkeypatch):
    monkeypatch.setattr(sast_agent, "_DEFAULT_BATCH_CHARS", 8)
    monkeypatch.setattr(scan_pipeline.SemgrepAgent, "available", property(lambda self: False))

    async def no_rag(self, **kwargs):
        return []

    monkeypatch.setattr(scan_pipeline.ThreatIntelRAG, "analyze", no_rag)

    class HangingCore(_OfflineCore):
        def __init__(self):
            self.active = 0
            self.started = 0

        async def generate_structured(self, request):
            self.active += 1
            self.started += 1
            try:
                await asyncio.Event().wait()
            finally:
                self.active -= 1

    provider = HangingCore()
    callbacks = []
    result = await run_agent_swarm(
        provider,
        {f"src/{number}.py": "pass #x\n" for number in range(6)},
        options=ScanOptions(concurrency=2, call_timeout_seconds=0.02, max_retries=0),
        on_phase=lambda name, findings: callbacks.append(name),
    )
    assert provider.started == 2
    assert provider.active == 0
    assert result.stats["sast"].status == "error"
    assert "sast" not in callbacks
    assert not result.complete
    assert result.budget["reserved_model_calls"] == 2
