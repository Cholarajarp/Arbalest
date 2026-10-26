"""Remaining open gaps, built: feedback loop, advisories, refinement, DAST probe."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from engine.agents.architect_agent import Severity, ThreatFinding

REPO_ROOT = Path(__file__).resolve().parent.parent


# ── Operator dispositions ────────────────────────────────────────────────────

def test_disposition_roundtrip_and_validation(tmp_path):
    from engine.services.dispositions import load_dispositions, record_disposition

    with pytest.raises(ValueError):
        record_disposition(tmp_path, "F-1", "not-a-verdict")
    record_disposition(tmp_path, "F-1", "false-positive", "benign config pattern")
    record_disposition(tmp_path, "F-2", "accepted")
    data = load_dispositions(tmp_path)
    assert data["F-1"]["verdict"] == "false-positive"
    assert data["F-1"]["note"] == "benign config pattern"
    assert data["F-2"]["verdict"] == "accepted"


@pytest.mark.asyncio
async def test_disposition_ranks_down_and_annotates(monkeypatch):
    from engine.services import scan_pipeline
    from engine.services.dispositions import record_disposition

    monkeypatch.setattr(scan_pipeline.SemgrepAgent, "available", property(lambda self: False))

    async def no_rag(self, **kwargs):
        return []

    monkeypatch.setattr(scan_pipeline.ThreatIntelRAG, "analyze", no_rag)
    monkeypatch.setattr(scan_pipeline, "get_vector_memory", lambda *args: None)
    record_disposition(REPO_ROOT.parent if not REPO_ROOT.exists() else REPO_ROOT, "x", "accepted")  # warm path

    injected = ThreatFinding(
        finding_id="SAST-fp1", cwe="CWE-94", severity=Severity.MEDIUM,
        summary="Suspicious eval-like usage", affected_nodes=["util.py"], evidence=["eval in config parser"],
    )

    class Sast:
        def __init__(self, provider, *, concurrency=1, model_override=None):
            self.coverage = type("C", (), {"complete": True, "detail": "ok", "as_dict": lambda s: {"complete": True}})()

        async def analyze(self, sources, **kwargs):
            return [injected]

    monkeypatch.setattr(scan_pipeline, "SastAgent", Sast)

    from engine.services.scan_pipeline import ReconReport

    class _Recon(ReconReport):
        def __init__(self, root):
            super().__init__()
            self.root_path = str(root)
            self.files = {"util.py": "x=1\n"}
            self.entrypoints = []

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        from engine.services.dispositions import record_disposition as record

        record(root, "SAST-fp1", "false-positive", "config dsl")
        swarm = await scan_pipeline.run_agent_swarm(
            _QueueProvider(["{}"]),
            {"util.py": "x=1\n"},
            _Recon(root),
            options=scan_pipeline.ScanOptions(concurrency=1, max_model_calls=3, max_retries=0),
        )
    assert swarm.dispositions.get("SAST-fp1") == "false-positive"
    components = swarm.priorities["SAST-fp1"]["components"]
    assert components.get("operator_false_positive") == -2.5
    assert any("operator marked" in item for item in swarm.findings[0].evidence)


class _QueueProvider:
    name = "queue-test-core"
    settings = None

    def __init__(self, responses):
        self._responses = list(responses)

    async def generate_structured(self, request):
        return self._responses.pop(0) if self._responses else "{}"

    async def list_models(self):
        return []

    async def aclose(self):
        return None


# ── Operator advisories file ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_operator_advisories_extend_the_table(tmp_path, monkeypatch):
    from engine.agents.black_box_fuzzer import FuzzingPolicy  # noqa: F401
    from engine.services import runtime_versions
    from tests.test_runtime_versions import _offline_client

    advisory_file = tmp_path / "advisories.json"
    advisory_file.write_text(json.dumps({"advisories": [{
        "tag": "nginx-test-2027", "component": "nginx", "published": "2027-01-15",
        "ids": ["CVE-2027-00000"], "floors": {"1.26": "1.26.9"},
        "lines": ["1.26"], "affected": "nginx 1.26 before 1.26.9 (operator entry)",
        "url": "https://example.com",
    }]}), encoding="utf-8")
    monkeypatch.setenv("ARBALEST_ADVISORIES_FILE", str(advisory_file))

    decls = runtime_versions.collect_runtime_declarations({"Dockerfile": "FROM nginx:1.26.1\n"})
    findings, _ = await runtime_versions.check_runtime_declarations(decls, client=_offline_client())
    entry = next(f for f in findings if f.finding_id == "RUNTIME-nginx-nginx-test-2027")
    assert entry.severity == Severity.CRITICAL
    assert "1.26≥1.26.9" in entry.summary


def test_malformed_advisories_file_is_ignored(tmp_path, monkeypatch):
    from engine.services import runtime_versions

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("ARBALEST_ADVISORIES_FILE", str(bad))
    tags = {entry["tag"] for entry in runtime_versions.active_advisories()}
    assert "php2shell" in tags  # built-ins intact


# ── Red-team execution-feedback refinement ───────────────────────────────────

@pytest.mark.asyncio
async def test_failed_harness_is_refined_once(monkeypatch):
    import engine.agents.red_team_swarm as rts
    from engine.agents.polyglot_translator import CodeLanguage, GeneratedCodeBundle, GeneratedFile

    marker = "ARBALEST_EXPLOIT_01"
    completed = rts.HARNESS_COMPLETED_MARKER
    attack_json = json.dumps({
        "language": "bash", "filename": "attack1.sh",
        "content": f"#!/bin/sh\ngrep {marker} app.py && echo {marker}\necho {completed}\n",
        "success_marker": marker,
        "objective": "first draft",
    })
    refined_json = json.dumps({
        "language": "bash", "filename": "attack2.sh",
        "content": f"#!/bin/sh\ngrep {marker} app.py && echo {marker}\ncat app.py >/dev/null\necho {completed}\n",
        "success_marker": marker, "objective": "refined draft",
    })
    analysis_json = json.dumps({
        "exploit_successful": False, "inconclusive": True,
        "reasoning": "harness never completed", "evidence": ["no completion marker"], "confidence": 0.3,
    })
    provider = _QueueProvider([attack_json, analysis_json, refined_json, analysis_json])

    class _ScriptedSandbox:
        def __init__(self):
            self.runs: list[str] = []

        async def run(self, spec, *, log_sink=None):
            self.runs.append(spec.entrypoint if hasattr(spec, "entrypoint") else str(spec))
            class _R:
                def __init__(self, ok):
                    self.succeeded = ok
                    self.stdout = f"noise\n{completed}\n" if ok else "Segmentation fault\n"
                    self.stderr = ""
                    self.exit_code = 0 if ok else 139
                    self.status = type("S", (), {"value": "completed"})()
            return _R(ok=(len(self.runs) == 2))

        async def aclose(self):
            return None

    sandbox = _ScriptedSandbox()
    bundle = GeneratedCodeBundle(
        language=CodeLanguage.PYTHON, entrypoint="app.py",
        files=[GeneratedFile(path="app.py", content="x = 1\n")],
        build_instructions=["none"], test_instructions=["none"],
    )
    plan = type("P", (), {"model_dump": lambda self, mode="json": {"plan": 1}})()
    swarm = rts.RedTeamSwarm(sandbox=sandbox, provider=provider)
    result = await swarm.execute(
        generated_code=bundle, mutation_plan=plan,
        findings=[ThreatFinding(
            finding_id="F", cwe="CWE-78", severity=Severity.HIGH, summary="s",
            affected_nodes=["app.py"], evidence=["e"],
        )],
    )
    assert result.attack.filename == "attack2.sh", "refined harness must win when it completes"
    assert result.harness_completed
    assert len(sandbox.runs) == 2


# ── Live probe (DAST seed) ───────────────────────────────────────────────────

class _VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if "next=" in self.path:
            self.send_response(302)
            self.send_header("Location", "//arbo-probe.invalid/redirect-check")
            self.end_headers()
            return
        if "arbalest-probe-" in self.path:
            body = b"Traceback (most recent call last):\n  File \"app.py\""
            self.send_response(404)
            self.send_header("Server", "Werkzeug/2.0.1")
            self.end_headers()
            self.wfile.write(body)
            return
        if "q=arbo0xss" in self.path:
            marker = "arbo0xss\"'<()>"
            self.send_response(200)
            self.send_header("Server", "Werkzeug/2.0.1")
            self.end_headers()
            self.wfile.write(f"<div>{marker}</div>".encode())
            return
        if "id=arbo0sql" in self.path:
            self.send_response(500)
            self.send_header("Server", "Werkzeug/2.0.1")
            self.end_headers()
            self.wfile.write(b"You have an error in your SQL syntax near 'arbo0sql''")
            return
        self.send_response(200)
        self.send_header("Server", "Werkzeug/2.0.1")
        self.end_headers()
        self.wfile.write(b"<html>ok</html>")

    def log_message(self, *args):
        pass


@pytest.mark.asyncio
async def test_live_probe_detects_runtime_only_flaws():
    from engine.agents.black_box_fuzzer import FuzzingPolicy, ScopeViolation
    from engine.agents.live_probe import run_probe

    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        result = await run_probe(url, policy=FuzzingPolicy(allow_private_networks=True))
        cwes = {finding.cwe for finding in result.findings}
        assert "CWE-693" in cwes   # missing security headers
        assert "CWE-200" in cwes   # version disclosure
        assert "CWE-209" in cwes   # verbose error page
        assert "CWE-601" in cwes   # open redirect
        assert "CWE-79" in cwes    # unescaped reflection of the XSS marker
        assert "CWE-89" in cwes    # database error exposed through a parameter
        assert result.requests <= 12

        with pytest.raises(ScopeViolation):
            await run_probe("https://some-public-saas.example.com", policy=FuzzingPolicy())
    finally:
        server.shutdown()
        server.server_close()
