"""Ouroboros CLI — meta-mode contract for the self-evolution command."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "arbalest_cli.py"), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
    )


def test_evolve_help():
    proc = _run_cli("evolve", "--help")
    assert proc.returncode == 0
    normalized = " ".join(proc.stdout.split())
    assert "Ouroboros Protocol" in normalized
    assert "mirror" in normalized


def test_evolve_requires_issue():
    proc = _run_cli("evolve")
    assert proc.returncode == 2


def test_evolve_unresolvable_issue_is_a_clean_mission_error():
    proc = _run_cli("evolve", "--issue", "999999")
    assert proc.returncode == 2
    assert "could not be resolved" in proc.stdout
    assert ".arbalest/issues/999999.md" in proc.stdout


def test_evolve_stage1_real_introspection_then_requires_core():
    """No API key: the meta-graph is real introspection; synthesis aborts armed-check."""
    proc = _run_cli("evolve", "--issue", "Add Java AST parsing support to the topology parser")
    assert proc.returncode == 2
    out = proc.stdout
    assert "OUROBOROS PROTOCOL" in out
    assert "[1/4]" in out and "META-GRAPH" in out.upper()
    assert "engine/immune/topology.py" in out, "relevance mapping must find the AST module"
    assert "AI CORE NOT ARMED" in out


def test_local_issue_file_is_honored(tmp_path: Path):
    """A local issue file resolves without gh — the deterministic path."""
    issues_dir = REPO_ROOT / ".arbalest" / "issues"
    issues_dir.mkdir(parents=True, exist_ok=True)
    issue_file = issues_dir / "4242.md"
    issue_file.write_text("# Add Java AST parsing support\n\nBody detail.\n", encoding="utf-8")
    try:
        proc = _run_cli("evolve", "--issue", "4242")
    finally:
        issue_file.unlink(missing_ok=True)
    # The request resolves (no "could not be resolved"), then hits the unarmed-core abort.
    assert "could not be resolved" not in proc.stdout
    assert "Add Java AST parsing support" in proc.stdout
    assert proc.returncode == 2
