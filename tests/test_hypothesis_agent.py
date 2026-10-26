"""Recon-driven review hypotheses: autonomous, target-specific SAST steering."""

from __future__ import annotations

import json

import pytest

from engine.agents.hypothesis_agent import HypothesisAgent
from engine.agents.sast_agent import SastAgent
from engine.services.scan_pipeline import ScanOptions, run_agent_swarm

_PRIORITIES = json.dumps({
    "review_priorities": [
        {
            "area": "Webhook signature verification",
            "rationale": "Stripe webhook handler present; verify signature checks before state changes",
        },
        {
            "area": "Tenant isolation",
            "rationale": "Object ids surface in URL routes; check per-tenant ownership on every read",
        },
    ]
})


class _RecordingProvider:
    name = "recording-test-core"
    settings = None

    def __init__(self, responses: dict[str, str] | None = None):
        self.requests: list = []
        self._responses = responses or {}

    async def generate_structured(self, request):
        self.requests.append(request)
        if request.schema_name in self._responses:
            return self._responses[request.schema_name]
        return '{"vulnerabilities": []}'

    async def list_models(self):
        return []

    async def aclose(self):
        return None


def test_parse_strict_and_recovered_priorities():
    parsed = HypothesisAgent.parse(_PRIORITIES)
    assert len(parsed) == 2
    assert parsed[0].startswith("Webhook signature verification:")

    aliased = HypothesisAgent.parse(json.dumps({
        "review_priorities": [{"area": "Upload abuse", "rationale": "avatars accepted from users"}],
    }))
    assert aliased == ["Upload abuse: avatars accepted from users"]


def test_parse_garbage_is_failure_tolerant():
    assert HypothesisAgent.parse("not json at all") == []
    assert HypothesisAgent.parse('{"review_priorities": "nope"}') == []
    assert HypothesisAgent.parse(json.dumps({
        "review_priorities": [{"area": "", "rationale": "x" * 20}],
    })) == []


@pytest.mark.asyncio
async def test_generate_sanitizes_control_characters():
    provider = _RecordingProvider({"review-hypotheses": json.dumps({
        "review_priorities": [
            {"area": "Pay\x1b[2Aout", "rationale": "amount tampering between client and provider"},
        ],
    })})
    priorities = await HypothesisAgent(provider).generate({"entrypoints": ["/api/pay"]})
    assert priorities == ["Payout: amount tampering between client and provider"]
    request = provider.requests[0]
    assert request.schema_name == "review-hypotheses"
    assert "autonomous security reviewer" in request.instructions
    assert "/api/pay" in request.input_text  # recon data reaches the model


@pytest.mark.asyncio
async def test_sast_batches_receive_review_priorities():
    provider = _RecordingProvider()
    agent = SastAgent(provider)
    await agent.analyze(
        {"app.py": "import os\nos.system(cmd)\n"},
        review_priorities=["Tenant isolation: check object ownership"],
    )
    assert provider.requests, "SAST must issue at least one batch"
    instructions = provider.requests[0].instructions
    assert "Recon-derived review priorities" in instructions
    assert "Tenant isolation" in instructions
    assert "never report a finding without source evidence" in instructions


@pytest.mark.asyncio
async def test_sast_without_priorities_keeps_standard_instructions():
    provider = _RecordingProvider()
    agent = SastAgent(provider)
    await agent.analyze({"app.py": "x = 1\n"})
    assert "Recon-derived review priorities" not in provider.requests[0].instructions


@pytest.mark.asyncio
async def test_pipeline_opt_in_threads_hypotheses_into_sast(monkeypatch):
    from engine.services import scan_pipeline

    monkeypatch.setattr(scan_pipeline.SemgrepAgent, "available", property(lambda self: False))

    async def no_rag(self, **kwargs):
        return []

    monkeypatch.setattr(scan_pipeline.ThreatIntelRAG, "analyze", no_rag)
    monkeypatch.setattr(scan_pipeline, "get_vector_memory", lambda *args: None)

    provider = _RecordingProvider({"review-hypotheses": _PRIORITIES})
    swarm = await run_agent_swarm(
        provider,
        {"app.py": "import os\nos.system(cmd)\n"},
        None,
        options=ScanOptions(concurrency=1, max_model_calls=10, max_retries=0, review_hypotheses=True),
    )
    assert swarm.stats["sast"].status == "ok"
    schemas = [request.schema_name for request in provider.requests]
    assert "review-hypotheses" in schemas
    sast_requests = [r for r in provider.requests if r.schema_name == "sast-analysis-result"]
    assert sast_requests and "Webhook signature verification" in sast_requests[0].instructions


@pytest.mark.asyncio
async def test_pipeline_default_off_never_calls_hypotheses(monkeypatch):
    from engine.services import scan_pipeline

    monkeypatch.setattr(scan_pipeline.SemgrepAgent, "available", property(lambda self: False))

    async def no_rag(self, **kwargs):
        return []

    monkeypatch.setattr(scan_pipeline.ThreatIntelRAG, "analyze", no_rag)
    monkeypatch.setattr(scan_pipeline, "get_vector_memory", lambda *args: None)

    provider = _RecordingProvider()
    await run_agent_swarm(
        provider,
        {"app.py": "import os\nos.system(cmd)\n"},
        None,
        options=ScanOptions(concurrency=1, max_model_calls=10, max_retries=0),
    )
    assert all(request.schema_name == "sast-analysis-result" for request in provider.requests)


@pytest.mark.asyncio
async def test_hypothesis_failure_never_breaks_the_scan(monkeypatch):
    from engine.services import scan_pipeline

    monkeypatch.setattr(scan_pipeline.SemgrepAgent, "available", property(lambda self: False))

    async def no_rag(self, **kwargs):
        return []

    monkeypatch.setattr(scan_pipeline.ThreatIntelRAG, "analyze", no_rag)
    monkeypatch.setattr(scan_pipeline, "get_vector_memory", lambda *args: None)

    class _HypothesisDown(_RecordingProvider):
        async def generate_structured(self, request):
            self.requests.append(request)
            if request.schema_name == "review-hypotheses":
                raise RuntimeError("hypothesis core offline")
            return '{"vulnerabilities": []}'

    provider = _HypothesisDown()
    swarm = await run_agent_swarm(
        provider,
        {"app.py": "import os\nos.system(cmd)\n"},
        None,
        options=ScanOptions(concurrency=1, max_model_calls=10, max_retries=0, review_hypotheses=True),
    )
    assert swarm.stats["sast"].status == "ok"
