"""Per-role model routing: strong reviewer, fast summarizer, one provider."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from engine.agents.hypothesis_agent import HypothesisAgent
from engine.agents.sast_agent import SastAgent
from engine.services.ai_provider import StructuredOutputRequest
from engine.services.runtime import model_for


class _CaptureProvider:
    name = "capture-test-core"
    settings = None

    def __init__(self):
        self.requests: list = []

    async def generate_structured(self, request):
        self.requests.append(request)
        return '{"vulnerabilities": []}'

    async def list_models(self):
        return []

    async def aclose(self):
        return None


def test_model_for_reads_validated_env(monkeypatch):
    monkeypatch.delenv("ARBALEST_MODEL_SAST", raising=False)
    assert model_for("sast") is None
    monkeypatch.setenv("ARBALEST_MODEL_SAST", "nvidia/Nemotron-3-Nano-30B-A3B")
    assert model_for("sast") == "nvidia/Nemotron-3-Nano-30B-A3B"
    monkeypatch.setenv("ARBALEST_MODEL_SAST", "bad model id; rm")
    assert model_for("sast") is None  # invalid ids are ignored, not fatal


def test_request_model_field_is_validated():
    assert StructuredOutputRequest(
        instructions="x", input_text="y", schema_name="s", json_schema={}, model="a/b:1",
    ).model == "a/b:1"
    with pytest.raises(ValidationError):
        StructuredOutputRequest(
            instructions="x", input_text="y", schema_name="s", json_schema={}, model="has space",
        )


@pytest.mark.asyncio
async def test_sast_override_reaches_every_batch_request():
    provider = _CaptureProvider()
    agent = SastAgent(provider, model_override="fast-reviewer-model")
    await agent.analyze({"app.py": "x = 1\n"})
    assert provider.requests and all(r.model == "fast-reviewer-model" for r in provider.requests)


@pytest.mark.asyncio
async def test_sast_without_override_leaves_model_unset():
    provider = _CaptureProvider()
    await SastAgent(provider).analyze({"app.py": "x = 1\n"})
    assert provider.requests and all(r.model is None for r in provider.requests)


@pytest.mark.asyncio
async def test_hypothesis_override_reaches_request():
    provider = _CaptureProvider()
    agent = HypothesisAgent(provider, model_override="cheap-sumer")
    await agent.generate({"entrypoints": ["/x"]})
    assert provider.requests[0].model == "cheap-sumer"
