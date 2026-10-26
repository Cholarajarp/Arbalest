"""SDK contract tests: no credentials, model calls or vulnerability lookups."""

from __future__ import annotations

import asyncio
import json
import sys

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from engine import sdk
from engine.agents.architect_agent import ThreatFinding
from engine.services.scan_archive import ScanArchiveError, load_scan_archive
from engine.services.scan_pipeline import AgentStat, SwarmResult
from engine.services.scan_workflow import ScanOptions
from engine.services.source_collector import run_recon


@pytest.fixture
def setup_sdk(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    provider = SimpleNamespace(aclose=AsyncMock())
    build = Mock(return_value=(provider, "fake", "fake-model"))
    monkeypatch.setattr(sdk, "build_provider", build)
    config = SimpleNamespace(
        provider="project-provider", model="project-model", scan=ScanOptions(concurrency=2),
        preflight=Mock(return_value={"ready": True}),
    )
    load = Mock(return_value=config)
    # Exercise the exact shared import/API even while the parent is adding it.
    monkeypatch.setitem(sys.modules, "engine.services.project_config", SimpleNamespace(load_project_config=load))
    finding = ThreatFinding(
        finding_id="SDK-1", cwe="CWE-89", severity="high", summary="Unsafe query",
        affected_nodes=["app.py"], evidence=["line 1"],
    )
    swarm = SwarmResult(
        findings=[finding], recon=run_recon(tmp_path),
        stats={"sast": AgentStat("sast")}, buckets={"sast": [finding]},
        budget={"reserved_model_calls": 1},
    )
    pipeline = AsyncMock(return_value=swarm)
    monkeypatch.setattr(sdk, "run_agent_swarm", pipeline)
    return SimpleNamespace(
        target=tmp_path, provider=provider, build=build, config=config, load=load,
        swarm=swarm, pipeline=pipeline,
    )


@pytest.mark.asyncio
async def test_run_shared_config_pipeline_and_sealed_archive(setup_sdk):
    env = setup_sdk
    client = sdk.Arbalest(config_path=env.target / "config.toml")
    async with client:
        result = await client.run(env.target, checkpoint_dir=env.target / "checkpoint", resume=True)
    assert isinstance(result, sdk.ScanResult)
    assert result.complete and result.status == "complete"
    assert result.findings == env.swarm.findings
    assert result.budget == env.swarm.budget
    assert result.severity_counts == {"high": 1}
    assert result.agent_errors == {}
    env.load.assert_called_once_with(env.target, env.target / "config.toml")
    env.build.assert_called_once_with("project-provider", "project-model")
    call = env.pipeline.call_args
    assert call.args[0] is env.provider
    assert call.args[1] == {"app.py": "print('hello')\n"}
    assert call.args[2].total_files == 1
    assert call.kwargs == {
        "options": env.config.scan, "checkpoint_dir": env.target / "checkpoint", "resume": True,
    }
    env.provider.aclose.assert_awaited_once()
    archive = load_scan_archive(env.target, result.run_id)
    assert archive["seal"]["bundle_sha256"] == result.archive.seal_sha256
    assert archive["findings.json"]["findings"][0]["finding"]["finding_id"] == "SDK-1"
    assert json.loads(json.dumps(result.report))["budget"] == result.budget
    with pytest.raises(RuntimeError, match="closed"):
        await client.run(env.target)


@pytest.mark.asyncio
async def test_explicit_overrides_and_client_reuse(setup_sdk):
    env = setup_sdk
    options = ScanOptions(max_model_calls=0)
    async with sdk.Arbalest(provider="override", model="chosen") as client:
        first = await client.run(env.target, options=options)
        second = await client.run(env.target)
    assert first.run_id != second.run_id
    assert env.build.call_count == 2
    env.build.assert_called_with("override", "chosen")
    assert env.pipeline.call_args_list[0].kwargs["options"] is options
    assert env.pipeline.call_args_list[1].kwargs["options"] is env.config.scan
    assert env.provider.aclose.await_count == 2


@pytest.mark.asyncio
async def test_incomplete_is_not_clean_and_history_compare_verify_seals(setup_sdk):
    env = setup_sdk
    async with sdk.Arbalest() as client:
        before = await client.run(env.target)
        env.swarm.stats["sast"] = AgentStat("sast", "partial", detail="budget exhausted")
        after = await client.run(env.target)
        assert not after.complete and after.status == "incomplete"
        assert after.agent_errors == {"sast": "budget exhausted"}
        history = await client.history(env.target)
        assert {row["scan_id"] for row in history} == {before.run_id, after.run_id}
        comparison = await client.compare(env.target, before.run_id, after.run_id)
        assert len(comparison["persistent"]) == 1
        assert not comparison["new"] and not comparison["resolved"]
        (after.archive.directory / "findings.json").write_text("{}", encoding="utf-8")
        with pytest.raises(ScanArchiveError, match="changed"):
            await client.compare(env.target, before.run_id, after.run_id)


@pytest.mark.asyncio
async def test_offline_preflight_sbom_and_history_do_not_build_provider(setup_sdk):
    env = setup_sdk
    async with sdk.Arbalest() as client:
        assert await client.preflight(env.target) == {"ready": True}
        env.config.preflight.assert_called_once_with(env.target)
        assert await client.history(env.target) == []
        sources = {"requirements.txt": "requests==2.32.3\n"}
        assert client.sbom(sources) == sdk.build_sbom(sources)
        assert client.sbom(sources)["bomFormat"] == "CycloneDX"
    env.build.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_at", ["pipeline", "archive"])
async def test_provider_closed_on_failure(setup_sdk, monkeypatch, failure_at):
    env = setup_sdk
    if failure_at == "pipeline":
        env.pipeline.side_effect = RuntimeError("pipeline failed")
    else:
        monkeypatch.setattr(sdk, "save_scan_archive", Mock(side_effect=OSError("archive failed")))
    async with sdk.Arbalest() as client:
        with pytest.raises((RuntimeError, OSError), match="failed"):
            await client.run(env.target)
    env.provider.aclose.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("close_client", [False, True])
async def test_cancellation_awaits_provider_cleanup(setup_sdk, close_client):
    env = setup_sdk
    started = asyncio.Event()
    cleaned = asyncio.Event()

    async def scan(*args, **kwargs):
        started.set()
        await asyncio.Event().wait()

    async def close():
        await asyncio.sleep(0)
        cleaned.set()

    env.pipeline.side_effect = scan
    env.provider.aclose.side_effect = close
    client = sdk.Arbalest()
    task = asyncio.create_task(client.run(env.target))
    await asyncio.wait_for(started.wait(), 2)
    if close_client:
        await client.aclose()
    else:
        task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cleaned.is_set()
    assert not list((env.target / ".arbalest" / "scans").glob("*"))
    env.provider.aclose.assert_awaited_once()
    await client.aclose()


@pytest.mark.asyncio
async def test_repeated_cancellation_cannot_interrupt_provider_close(setup_sdk):
    env = setup_sdk
    closing = asyncio.Event()
    release = asyncio.Event()
    cleaned = asyncio.Event()

    async def close():
        closing.set()
        await release.wait()
        cleaned.set()

    env.provider.aclose.side_effect = close
    async with sdk.Arbalest() as client:
        task = asyncio.create_task(client.run(env.target))
        await asyncio.wait_for(closing.wait(), 2)
        for _ in range(3):
            task.cancel()
            await asyncio.sleep(0)
            assert not cleaned.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cleaned.is_set()
    env.provider.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_context_exit_cancels_all_concurrent_runs(setup_sdk):
    env = setup_sdk
    started = asyncio.Event()
    calls = 0

    async def scan(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            started.set()
        await asyncio.Event().wait()

    env.pipeline.side_effect = scan
    async with sdk.Arbalest() as client:
        first = asyncio.create_task(client.run(env.target))
        second = asyncio.create_task(client.run(env.target))
        await asyncio.wait_for(started.wait(), 2)
    for task in (first, second):
        with pytest.raises(asyncio.CancelledError):
            await task
    assert env.provider.aclose.await_count == 2


@pytest.mark.asyncio
async def test_diff_scope_uses_shared_recon(setup_sdk, monkeypatch):
    env = setup_sdk
    scope = object()
    resolve = Mock(return_value=scope)
    scoped = run_recon(env.target)
    scoped.scope_kind = "diff"
    apply = Mock(return_value=scoped)
    monkeypatch.setattr(sdk, "resolve_git_diff", resolve)
    monkeypatch.setattr(sdk, "scope_recon_to_diff", apply)
    async with sdk.Arbalest() as client:
        result = await client.run(env.target, diff_base="HEAD~1")
    resolve.assert_called_once_with(env.target, "HEAD~1")
    assert apply.call_args.args[1] is scope
    assert env.pipeline.call_args.args[2] is scoped
    assert result.report["coverage"]["scope_kind"] == "diff"


@pytest.mark.asyncio
async def test_setup_errors_never_arm_provider(setup_sdk):
    env = setup_sdk
    async with sdk.Arbalest() as client:
        with pytest.raises(FileNotFoundError):
            await client.run(env.target / "missing")
        with pytest.raises(TypeError, match="ScanOptions"):
            await client.run(env.target, options={})
        (env.target / "app.py").unlink()
        with pytest.raises(ValueError, match="No source"):
            await client.run(env.target)
    env.build.assert_not_called()


@pytest.mark.asyncio
async def test_provider_error_propagates_without_fallback(setup_sdk):
    env = setup_sdk
    env.build.side_effect = RuntimeError("No API key armed")
    async with sdk.Arbalest() as client:
        with pytest.raises(RuntimeError, match="No API key"):
            await client.run(env.target)
    env.pipeline.assert_not_awaited()
    env.provider.aclose.assert_not_awaited()


def test_no_credential_constructor_parameter():
    with pytest.raises(TypeError):
        sdk.Arbalest(api_key="never-accepted")
