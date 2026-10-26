"""Agentic upgrades: BM25 retrieval, self-verification, priorities, antibodies."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.agents.architect_agent import Severity, ThreatFinding
from engine.agents.finding_verifier import FindingVerifier
from engine.agents.sast_agent import SastAgent
from engine.services.retrieval import bm25_rank, expand_query, tokenize

REPO_ROOT = Path(__file__).resolve().parent.parent


# ── BM25 + security thesaurus ────────────────────────────────────────────────

def test_synonym_expansion_bridges_vocabularies():
    tokens = expand_query(tokenize("CWE-89 sqli"))
    assert "sql" in tokens and "injection" in tokens


def test_bm25_ranks_relevant_document_first():
    documents = [
        ("doc-sql", "SQL injection via string-built queries in database access code"),
        ("doc-xss", "Cross site scripting reflects user input into HTML pages"),
        ("doc-crypto", "Weak cipher usage with static keys"),
    ]
    ranked = bm25_rank("sql injection", documents, limit=3)
    assert ranked and ranked[0][1] == "doc-sql"
    assert all(score > 0 for score, _ in ranked)


def test_bm25_empty_inputs_are_safe():
    assert bm25_rank("", [("a", "text")], limit=3) == []
    assert bm25_rank("query", [], limit=3) == []


@pytest.mark.asyncio
async def test_vector_memory_bm25_recall(tmp_path, monkeypatch):
    monkeypatch.setenv("ARBALEST_MEMORY_PATH", str(tmp_path / "mem"))
    from engine.services.vector_memory import get_vector_memory

    memory = get_vector_memory(tmp_path)
    await memory.ingest_finding("F-1", "SQL injection in orders query", "cursor.execute with f-string")
    await memory.ingest_finding("F-2", "Timing-unsafe token comparison", "== operator on secrets")
    results = await memory.query_similar("database sqli in query", n_results=2)
    assert results and results[0]["metadata"]["finding_id"] == "F-1"


# ── Self-verification: annotate, never delete ───────────────────────────────

class _VerdictProvider:
    name = "verdict-test-core"
    settings = None

    def __init__(self, raw: str):
        self.requests: list = []
        self._raw = raw

    async def generate_structured(self, request):
        self.requests.append(request)
        return self._raw

    async def list_models(self):
        return []

    async def aclose(self):
        return None


def _candidate(fid: str) -> ThreatFinding:
    return ThreatFinding(
        finding_id=fid, cwe="CWE-89", severity=Severity.HIGH, summary="SQL injection",
        affected_nodes=["app.py"], evidence=["cursor.execute(f...)"],
    )


@pytest.mark.asyncio
async def test_verifier_annotates_without_deleting():
    provider = _VerdictProvider(json.dumps({"verdicts": [
        {"finding_id": "A", "verdict": "confirmed", "reason": "f-string reaches execute"},
        {"finding_id": "B", "verdict": "rejected", "reason": "parameterized query used"},
    ]}))
    verdicts = await FindingVerifier(provider).verify([_candidate("A"), _candidate("B")], {"app.py": "x=1\n"})
    assert verdicts == {"A": "confirmed", "B": "rejected"}
    assert provider.requests[0].schema_name == "finding-verification"


@pytest.mark.asyncio
async def test_verifier_garbage_output_keeps_everything():
    provider = _VerdictProvider("total nonsense")
    verdicts = await FindingVerifier(provider).verify([_candidate("A")], {"app.py": "x=1\n"})
    assert verdicts == {}


@pytest.mark.asyncio
async def test_verifier_ignores_unknown_ids():
    provider = _VerdictProvider(json.dumps({"verdicts": [
        {"finding_id": "NOT-PRESENT", "verdict": "rejected", "reason": "fabricated id"},
    ]}))
    verdicts = await FindingVerifier(provider).verify([_candidate("A")], {"app.py": "x=1\n"})
    assert verdicts == {}


# ── Antibody few-shot injection ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sast_receives_antibody_patterns():
    class _Capture(_VerdictProvider):
        async def generate_structured(self, request):
            self.requests.append(request)
            return '{"vulnerabilities": []}'

    provider = _Capture("")
    agent = SastAgent(provider)
    await agent.analyze(
        {"app.py": "x = 1\n"},
        known_patterns=["Unsafe git clone (CWE-78): command built from request input"],
    )
    instructions = provider.requests[0].instructions
    assert "antibody memory" in instructions
    assert "Unsafe git clone" in instructions


# ── Priority ranking and self-check annotations in the pipeline ─────────────

@pytest.mark.asyncio
async def test_pipeline_priorities_and_self_check(monkeypatch):
    from engine.services import scan_pipeline

    monkeypatch.setattr(scan_pipeline.SemgrepAgent, "available", property(lambda self: False))

    async def no_rag(self, **kwargs):
        return []

    monkeypatch.setattr(scan_pipeline.ThreatIntelRAG, "analyze", no_rag)
    monkeypatch.setattr(scan_pipeline, "get_vector_memory", lambda *args: None)

    injected = ThreatFinding(
        finding_id="SAST-x1", cwe="CWE-89", severity=Severity.HIGH,
        summary="SQL injection from request parameter",
        affected_nodes=["routes.py"], evidence=["cursor.execute(f-string with request input)"],
    )

    class Sast:
        def __init__(self, provider, *, concurrency=1, model_override=None):
            self.coverage = type("C", (), {"complete": True, "detail": "ok", "as_dict": lambda s: {"complete": True}})()

        async def analyze(self, sources, **kwargs):
            return [injected]

    class Verifier:
        def __init__(self, provider, *, model_override=None):
            pass

        async def verify(self, findings, sources):
            return {"SAST-x1": "confirmed"}

    monkeypatch.setattr(scan_pipeline, "SastAgent", Sast)
    monkeypatch.setattr(scan_pipeline, "FindingVerifier", Verifier)

    class _EntryRecon:
        entrypoints = ["routes.py"]

        def summary(self):
            return {}

    original_recon = scan_pipeline.ReconReport

    class _PatchedReport(original_recon):
        def __init__(self):
            super().__init__()
            self.entrypoints = ["routes.py"]
            self.files = {"routes.py": "x=1\n"}

    swarm = await scan_pipeline.run_agent_swarm(
        _VerdictProvider(""),
        {"routes.py": "x=1\n"},
        _PatchedReport(),
        options=scan_pipeline.ScanOptions(concurrency=1, max_model_calls=5, max_retries=0, sast_self_check=True),
    )
    priority = swarm.priorities["SAST-x1"]
    assert priority["components"]["public_surface"] == 1.5
    assert priority["components"]["untrusted_source_evidence"] == 1.0
    assert priority["components"]["self_check_confirmed"] == 1.0
    assert any("self-check: confirmed" in item for item in swarm.findings[0].evidence)


# ── Benchmark harness functions ─────────────────────────────────────────────

def test_benchmark_offline_scores_bundled_case():
    import sys

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import benchmark

    case = REPO_ROOT / "benchmarks" / "vulns" / "py_classic"
    text = benchmark.run_offline(case)
    found, total, missed = benchmark.score(text, case / "ground_truth.json", "deterministic")
    assert total == 5
    assert found == total, f"expected all deterministic classes, missed: {missed}"


def test_secret_patterns_catch_prefixed_credential_names():
    import asyncio

    from engine.agents.secret_scanner import SecretScannerAgent
    from engine.immune.detection import sweep_sources

    sources = {"cfg.py": 'DB_PASSWORD = "Sup3rS3cretPr0dPassword!"\n'}
    findings = asyncio.run(SecretScannerAgent().analyze(sources))
    assert any("credential" in f.summary.lower() for f in findings)
    assert sweep_sources(sources) != []
