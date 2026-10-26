"""Offline regression tests for budgets, durable phases, and public orchestration."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from engine.agents.architect_agent import ThreatFinding
from engine.services import scan_pipeline as pipeline
from engine.services import scan_workflow as workflow_module
from engine.services.scan_pipeline import ScanOptions, run_agent_swarm
from engine.services.scan_workflow import (
    CheckpointError,
    PhaseResult,
    ScanBudgetExceeded,
    ScanWorkflow,
    provider_identity,
)


class FakeProvider:
    name = "fake"

    def __init__(self, key="provider-sensitive-value", model="fake-model"):
        self.settings = SimpleNamespace(
            api_key=SecretStr(key),
            selected_model=model,
            base_url="https://user:password@example.com/v1?key=private#secret",
        )
        self.calls = []
        self.stream_closed = False

    async def generate_structured(self, request):
        self.calls.append("generate_structured")
        return "{}"

    async def generate(self, request):
        self.calls.append("generate")
        return "text"

    async def run_with_tools(self, request, **kwargs):
        self.calls.append("tools")
        return "{}"

    async def stream(self, request):
        self.calls.append("stream")
        try:
            yield "a"
            yield "b"
        finally:
            self.stream_closed = True

    async def stream_structured(self, request):
        async for part in self.stream(request):
            yield part


SOURCES = {"app.py": "dangerous_source = input()\n"}


def finding(evidence="verified location"):
    return ThreatFinding(
        finding_id="TEST-1",
        cwe="CWE-89",
        severity="high",
        summary="Unsafe data flow",
        affected_nodes=["app.py"],
        evidence=[evidence],
    )


@pytest.mark.parametrize(
    "config",
    [
        {"concurrency": True},
        {"concurrency": 0},
        {"concurrency": 33},
        {"concurrency": "4"},
        {"max_model_calls": 1.5},
        {"max_model_calls": -1},
        {"per_call_model_calls": 0},
        {"max_seconds": float("nan")},
        {"max_seconds": float("inf")},
        {"max_seconds": 0},
        {"call_timeout_seconds": False},
        {"max_cost_usd": 1},
        {"max_cost_usd": -1, "per_call_reserve_usd": 0.1},
        {"max_cost_usd": 1, "per_call_reserve_usd": 0},
        {"max_retries": 11},
    ],
)
def test_strict_options(config):
    with pytest.raises(ValueError):
        ScanOptions.from_mapping(config)


def test_options_reject_unknown_and_are_immutable():
    with pytest.raises(TypeError):
        ScanOptions.from_mapping({"unknown": 1})
    with pytest.raises(AttributeError):
        ScanOptions().concurrency = 9
    assert ScanOptions.from_mapping({"max_cost_usd": 0, "per_call_reserve_usd": 1}).max_cost_usd == 0


@pytest.mark.asyncio
async def test_all_provider_entrypoints_reserve_and_tools_reserve_turns(tmp_path):
    provider = FakeProvider()
    options = ScanOptions(max_model_calls=14, per_call_model_calls=2, per_call_reserve_usd=0.1, max_cost_usd=1.4)
    workflow = ScanWorkflow(provider, SOURCES, options, tmp_path)
    try:
        await workflow.provider.generate_structured(None)
        await workflow.provider.generate(None)
        assert [chunk async for chunk in workflow.provider.stream(None)] == ["a", "b"]
        assert [chunk async for chunk in workflow.provider.stream_structured(None)] == ["a", "b"]
        await workflow.provider.run_with_tools(None, max_turns=3)
        assert workflow.budget_summary["reserved_model_calls"] == 14
        assert workflow.budget_summary["actual_cost_usd"] is None
        assert provider.stream_closed
        with pytest.raises(ScanBudgetExceeded):
            await workflow.provider.generate_structured(None)
        with pytest.raises(ValueError):
            await workflow.provider.run_with_tools(None)
        assert len(provider.calls) == 5
        assert json.loads((tmp_path / "scan-workflow.json").read_text())["state"]["reserved_model_calls"] == 14
    finally:
        workflow.close()


@pytest.mark.asyncio
async def test_parallel_reservations_are_atomic_and_decimal_cost_is_conservative():
    provider = FakeProvider()
    workflow = ScanWorkflow(
        provider, SOURCES, ScanOptions(max_model_calls=100, max_cost_usd=0.3, per_call_reserve_usd=0.1)
    )
    try:
        results = await asyncio.gather(*(workflow.provider.generate(None) for _ in range(20)), return_exceptions=True)
        assert len(provider.calls) == 3
        assert sum(isinstance(item, ScanBudgetExceeded) for item in results) == 17
    finally:
        workflow.close()


@pytest.mark.asyncio
async def test_failed_and_cancelled_calls_keep_durable_reservations(tmp_path):
    class Broken(FakeProvider):
        async def generate_structured(self, request):
            raise RuntimeError("provider-sensitive-value")

    options = ScanOptions(max_model_calls=1)
    workflow = ScanWorkflow(Broken(), SOURCES, options, tmp_path)
    with pytest.raises(RuntimeError):
        await workflow.provider.generate_structured(None)
    workflow.close()
    resumed = ScanWorkflow(Broken(key="rotated-provider-value"), SOURCES, options, tmp_path, True)
    try:
        with pytest.raises(ScanBudgetExceeded):
            await resumed.provider.generate_structured(None)
        assert resumed.budget_summary["reserved_model_calls"] == 1
    finally:
        resumed.close()


@pytest.mark.asyncio
async def test_call_timeout_and_suppressed_cancellation_fail_closed():
    class Hanging(FakeProvider):
        async def generate_structured(self, request):
            await asyncio.Event().wait()

    class Suppressing(FakeProvider):
        async def generate_structured(self, request):
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                return "false clean"

    for provider in (Hanging(), Suppressing()):
        workflow = ScanWorkflow(provider, SOURCES, ScanOptions(call_timeout_seconds=0.01))
        try:
            with pytest.raises((TimeoutError, ScanBudgetExceeded)):
                await workflow.provider.generate_structured(None)
            assert workflow.budget_summary["reserved_model_calls"] == 1
        finally:
            workflow.close()


@pytest.mark.asyncio
async def test_stream_timeout_closes_iterator():
    class HangingStream(FakeProvider):
        async def stream(self, request):
            try:
                yield "first"
                await asyncio.Event().wait()
            finally:
                self.stream_closed = True

    provider = HangingStream()
    workflow = ScanWorkflow(provider, SOURCES, ScanOptions(call_timeout_seconds=0.01))
    try:
        with pytest.raises(TimeoutError):
            _ = [chunk async for chunk in workflow.provider.stream(None)]
        assert provider.stream_closed
    finally:
        workflow.close()


@pytest.mark.asyncio
async def test_partial_phases_are_not_retried_and_coverage_survives_resume(tmp_path):
    options = ScanOptions(max_retries=2)
    workflow = ScanWorkflow(FakeProvider(), SOURCES, options, tmp_path)
    calls = 0
    coverage = {"complete": False, "eligible_files": 2, "analyzed_files": 1, "omitted_files": ["other.py"]}

    async def partial():
        nonlocal calls
        calls += 1
        return PhaseResult([finding()], "partial", "one file omitted", coverage=coverage)

    first = await workflow.run_phase("sast", partial)
    workflow.close()
    resumed = ScanWorkflow(FakeProvider(), SOURCES, options, tmp_path, True)
    try:
        second = await resumed.run_phase("sast", partial)
        assert calls == 1
        assert first == second
        assert second.coverage == coverage
        assert second.status == "partial"
        assert second.findings == [finding()]
    finally:
        resumed.close()


@pytest.mark.asyncio
async def test_only_errors_are_retried_with_a_durable_attempt_limit(tmp_path):
    options = ScanOptions(max_retries=2)
    workflow = ScanWorkflow(FakeProvider(), SOURCES, options, tmp_path)
    calls = 0

    async def broken():
        nonlocal calls
        calls += 1
        raise RuntimeError("provider-sensitive-value dangerous_source = input()")

    assert (await workflow.run_phase("sast", broken)).status == "error"
    assert calls == 3
    workflow.close()
    resumed = ScanWorkflow(FakeProvider(), SOURCES, options, tmp_path, True)
    try:
        assert (await resumed.run_phase("sast", broken)).status == "error"
        assert calls == 3
        assert "provider-sensitive-value" not in (tmp_path / "scan-workflow.json").read_text()
    finally:
        resumed.close()


@pytest.mark.asyncio
async def test_transient_error_retries_then_succeeds():
    workflow = ScanWorkflow(FakeProvider(), SOURCES, ScanOptions(max_retries=1))
    calls = 0

    async def transient():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("transient")
        return PhaseResult([finding()])

    try:
        assert (await workflow.run_phase("sast", transient)).status == "ok"
        assert calls == 2
    finally:
        workflow.close()


@pytest.mark.asyncio
async def test_interrupted_phase_resumes_without_repeating_completed_phase(tmp_path):
    options = ScanOptions(max_retries=1)
    workflow = ScanWorkflow(FakeProvider(), SOURCES, options, tmp_path)
    started = asyncio.Event()

    async def done():
        return PhaseResult([finding()])

    async def interrupted():
        await workflow.provider.generate(None)
        started.set()
        await asyncio.Event().wait()

    await workflow.run_phase("secrets", done)
    task = asyncio.create_task(workflow.run_phase("sast", interrupted))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    workflow.close()

    resumed = ScanWorkflow(FakeProvider(), SOURCES, options, tmp_path, True)
    try:

        async def should_not_run():
            pytest.fail("completed phase was repeated")

        assert (await resumed.run_phase("secrets", should_not_run)).findings
        assert (await resumed.run_phase("sast", done)).status == "ok"
        assert resumed.state["phases"]["sast"]["attempts"] == 2
        assert resumed.budget_summary["reserved_model_calls"] == 1
    finally:
        resumed.close()


@pytest.mark.asyncio
async def test_expired_resumed_deadline_and_sync_overrun_are_errors(tmp_path, monkeypatch):
    options = ScanOptions(max_seconds=1)
    workflow = ScanWorkflow(FakeProvider(), SOURCES, options, tmp_path)
    workflow.close()
    wall_time = time.time()
    monkeypatch.setattr(workflow_module.time, "time", lambda: wall_time + 2)
    resumed = ScanWorkflow(FakeProvider(), SOURCES, options, tmp_path, True)
    called = False

    async def operation():
        nonlocal called
        called = True
        return PhaseResult()

    try:
        assert (await resumed.run_phase("sast", operation)).status == "error"
        assert not called
    finally:
        resumed.close()

    overrun = ScanWorkflow(FakeProvider(), SOURCES, ScanOptions(max_seconds=0.01))

    async def blocking():
        time.sleep(0.02)
        return PhaseResult()

    try:
        assert (await overrun.run_phase("sast", blocking)).status == "error"
    finally:
        overrun.close()


@pytest.mark.parametrize("change", ["source", "options", "model", "endpoint", "context"])
def test_resume_rejects_fingerprint_mismatch(tmp_path, change):
    provider = FakeProvider()
    options = ScanOptions()
    workflow = ScanWorkflow(provider, SOURCES, options, tmp_path, context={"entrypoints": []})
    workflow.close()
    sources = SOURCES
    context = {"entrypoints": []}
    if change == "source":
        sources = {"app.py": "changed = True"}
    elif change == "options":
        options = replace(options, concurrency=1)
    elif change == "model":
        provider.settings.selected_model = "different"
    elif change == "endpoint":
        provider.settings.base_url = "https://example.com/other-deployment"
    else:
        context = {"entrypoints": ["new"]}
    with pytest.raises(CheckpointError, match="fingerprint mismatch"):
        ScanWorkflow(provider, sources, options, tmp_path, True, context=context)


def test_identity_excludes_credentials_and_checkpoint_lock_is_released(tmp_path):
    first = FakeProvider()
    second = FakeProvider(key="rotated-provider-sensitive-value")
    second.settings.base_url = "https://different:credentials@example.com/v1?key=changed#changed"
    assert provider_identity(first) == provider_identity(second)
    workflow = ScanWorkflow(first, SOURCES, ScanOptions(), tmp_path)
    with pytest.raises(CheckpointError, match="already in use"):
        ScanWorkflow(first, SOURCES, ScanOptions(), tmp_path, True)
    workflow.close()
    resumed = ScanWorkflow(second, SOURCES, ScanOptions(), tmp_path, True)
    resumed.close()
    with pytest.raises(CheckpointError, match="exists"):
        ScanWorkflow(second, SOURCES, ScanOptions(), tmp_path)
    with pytest.raises(CheckpointError, match="requires"):
        ScanWorkflow(second, SOURCES, ScanOptions(), resume=True)


@pytest.mark.asyncio
async def test_checkpoint_contains_no_source_or_credentials(tmp_path):
    provider = FakeProvider()
    sources = {**SOURCES, "settings.py": 'service_secret = "unrecognized-literal-credential"'}
    workflow = ScanWorkflow(provider, sources, ScanOptions(), tmp_path)

    async def operation():
        item = finding("dangerous_source = input() provider-sensitive-value unrecognized-literal-credential")
        return PhaseResult([item], coverage={"complete": True, "files": 1})

    original = await workflow.run_phase("sast", operation)
    workflow.close()
    text = (tmp_path / "scan-workflow.json").read_text()
    assert "dangerous_source = input()" not in text
    assert "provider-sensitive-value" not in text
    assert "user:password" not in text
    assert "?key=private" not in text
    assert "unrecognized-literal-credential" not in text
    resumed = ScanWorkflow(FakeProvider(), sources, ScanOptions(), tmp_path, True)
    try:
        assert (await resumed.run_phase("sast", operation)) == original
    finally:
        resumed.close()


@pytest.mark.asyncio
async def test_failed_atomic_write_does_not_dispatch_provider_or_replace_checkpoint(tmp_path, monkeypatch):
    provider = FakeProvider()
    workflow = ScanWorkflow(provider, SOURCES, ScanOptions(), tmp_path)
    original = (tmp_path / "scan-workflow.json").read_bytes()

    def fail_replace(*args):
        raise OSError("disk failure")

    monkeypatch.setattr(workflow_module.os, "replace", fail_replace)
    try:
        with pytest.raises(CheckpointError):
            await workflow.provider.generate(None)
        assert not provider.calls
        assert (tmp_path / "scan-workflow.json").read_bytes() == original
        assert not list(tmp_path.glob(".scan-*.tmp"))
    finally:
        workflow.close()


def test_corrupt_checkpoint_is_rejected(tmp_path):
    workflow = ScanWorkflow(FakeProvider(), SOURCES, ScanOptions(), tmp_path)
    workflow.close()
    (tmp_path / "scan-workflow.json").write_text('{"state": {}}')
    with pytest.raises(CheckpointError, match="corrupt"):
        ScanWorkflow(FakeProvider(), SOURCES, ScanOptions(), tmp_path, True)


@pytest.fixture
def fake_phases(monkeypatch):
    state = SimpleNamespace(active=0, peak=0, calls=[], completed=[], rag_prior=None, closed=0)

    async def analyze(name):
        state.calls.append(name)
        state.active += 1
        state.peak = max(state.peak, state.active)
        await asyncio.sleep(0.01)
        state.active -= 1
        state.completed.append(name)
        return [finding()] if name == "sast" else []

    class Coverage:
        complete = True
        detail = "all inspected"

        def as_dict(self):
            return {"complete": self.complete, "files": 1}

    class Sast:
        def __init__(self, provider, *, concurrency=1, model_override=None):
            self.coverage = Coverage()

        async def analyze(self, sources):
            return await analyze("sast")

    class Sca(Sast):
        async def analyze(self, sources):
            return await analyze("sca")

        async def aclose(self):
            state.closed += 1

    class Secrets:
        async def analyze(self, sources):
            return await analyze("secrets")

    class Semgrep(Secrets):
        available = True

        async def analyze(self, sources):
            return await analyze("semgrep")

    class Rag:
        def __init__(self, **kwargs):
            pass

        async def analyze(self, **kwargs):
            assert set(state.completed) == {"sast", "secrets", "semgrep", "sca"}
            state.rag_prior = kwargs["prior_findings"]
            state.calls.append("threat_rag")
            return []

        async def aclose(self):
            state.closed += 1

    class Memory:
        async def ingest_finding(self, *args):
            return False

    monkeypatch.setattr(pipeline, "SastAgent", Sast)
    monkeypatch.setattr(pipeline, "ScaAgent", Sca)
    monkeypatch.setattr(pipeline, "SecretScannerAgent", Secrets)
    monkeypatch.setattr(pipeline, "SemgrepAgent", Semgrep)
    monkeypatch.setattr(pipeline, "ThreatIntelRAG", Rag)
    monkeypatch.setattr(pipeline, "get_vector_memory", lambda *args: Memory())
    monkeypatch.setitem(sys.modules, "engine.services.taint_analysis", None)
    return state


@pytest.mark.asyncio
@pytest.mark.parametrize("concurrency", [1, 2, 4])
async def test_public_pipeline_parallelism_then_rag_and_durable_resume(tmp_path, fake_phases, concurrency):
    options = ScanOptions(concurrency=concurrency)
    callback_calls = []
    first = await run_agent_swarm(
        FakeProvider(),
        SOURCES,
        options=options,
        checkpoint_dir=tmp_path,
        on_phase=lambda name, findings: callback_calls.append(name),
    )
    assert first.complete
    assert fake_phases.peak == concurrency
    assert fake_phases.rag_prior == (finding(),)
    assert fake_phases.closed == 2
    assert callback_calls == ["sast", "secrets", "semgrep", "sca", "threat_rag"]
    calls = fake_phases.calls.copy()
    resumed = await run_agent_swarm(FakeProvider(), SOURCES, options=options, checkpoint_dir=tmp_path, resume=True)
    assert fake_phases.calls == calls
    assert resumed.stats == first.stats
    assert resumed.findings == first.findings
    assert resumed.budget["actual_cost_usd"] is None
    assert fake_phases.closed == 2


@pytest.mark.asyncio
async def test_public_partial_coverage_and_optional_sync_taint_are_fail_closed(tmp_path, fake_phases, monkeypatch):
    calls = []

    def analyze_taint(sources):
        calls.append(sources)
        return SimpleNamespace(
            findings=[finding()], coverage={"complete": False, "detail": "unsupported language", "files": 1}
        )

    monkeypatch.setitem(sys.modules, "engine.services.taint_analysis", SimpleNamespace(analyze_taint=analyze_taint))
    options = ScanOptions(max_retries=2)
    first = await run_agent_swarm(FakeProvider(), SOURCES, options=options, checkpoint_dir=tmp_path)
    assert first.stats["taint"].status == "partial"
    assert first.agent_errors == {"taint": "unsupported language"}
    assert not first.complete
    resumed = await run_agent_swarm(FakeProvider(), SOURCES, options=options, checkpoint_dir=tmp_path, resume=True)
    assert len(calls) == 1
    assert resumed.stats["taint"].coverage == first.stats["taint"].coverage
    assert resumed.findings == first.findings


@pytest.mark.asyncio
async def test_public_budget_errors_do_not_abort_local_phases(fake_phases, monkeypatch):
    class BudgetSast:
        def __init__(self, provider, *, concurrency=1):
            self.provider = provider

        async def analyze(self, sources):
            fake_phases.completed.append("sast")
            await self.provider.generate_structured(None)

    monkeypatch.setattr(pipeline, "SastAgent", BudgetSast)
    provider = FakeProvider()
    result = await run_agent_swarm(provider, SOURCES, options=ScanOptions(max_model_calls=0, max_retries=2))
    assert result.stats["sast"].status == "error"
    assert result.stats["secrets"].status == "ok"
    assert result.stats["sca"].status == "ok"
    assert not result.complete
    assert not provider.calls


@pytest.mark.asyncio
async def test_dependent_phase_recomputed_if_interrupted_upstream_changes(tmp_path):
    options = ScanOptions(max_retries=1)
    workflow = ScanWorkflow(FakeProvider(), SOURCES, options, tmp_path)

    async def done():
        return PhaseResult()

    # Simulate a previous interrupted upstream attempt and a completed dependent.
    workflow._save_phase("sast", PhaseResult(status="running"), 1)
    first_dependency = workflow.phase_fingerprint(["sast"])
    await workflow.run_phase("threat_rag", done, dependency=first_dependency)
    workflow.close()
    resumed = ScanWorkflow(FakeProvider(), SOURCES, options, tmp_path, True)
    calls = 0

    async def dependent():
        nonlocal calls
        calls += 1
        return PhaseResult()

    try:
        await resumed.run_phase("sast", done)
        await resumed.run_phase("threat_rag", dependent, dependency=resumed.phase_fingerprint(["sast"]))
        assert calls == 1
    finally:
        resumed.close()


@pytest.mark.asyncio
async def test_source_literals_do_not_corrupt_finding_ids_or_coverage_paths(tmp_path):
    sources = {"app.py": 'print("app.py", "CWE-89", "TEST-1")'}
    workflow = ScanWorkflow(FakeProvider(), sources, ScanOptions(), tmp_path)
    coverage = {"complete": False, "omitted_files": ["app.py"]}

    async def operation():
        return PhaseResult([finding()], "partial", coverage=coverage)

    try:
        result = await workflow.run_phase("sast", operation)
        assert result.findings == [finding()]
        assert result.coverage == coverage
    finally:
        workflow.close()


@pytest.mark.asyncio
async def test_phase_timeout_is_not_retried_and_remains_incomplete():
    workflow = ScanWorkflow(FakeProvider(), SOURCES, ScanOptions(max_seconds=0.02, max_retries=3))
    calls = 0

    async def hang():
        nonlocal calls
        calls += 1
        await asyncio.Event().wait()

    try:
        result = await workflow.run_phase("sca", hang)
        assert result.status == "error"
        assert calls == 1
    finally:
        workflow.close()


@pytest.mark.asyncio
async def test_stream_deadline_does_not_cancel_consumer_between_chunks():
    provider = FakeProvider()
    workflow = ScanWorkflow(provider, SOURCES, ScanOptions(call_timeout_seconds=0.01))
    stream = workflow.provider.stream(None)
    try:
        assert await anext(stream) == "a"
        await asyncio.sleep(0.02)
        with pytest.raises(ScanBudgetExceeded):
            await anext(stream)
        assert provider.stream_closed
    finally:
        await stream.aclose()
        workflow.close()
