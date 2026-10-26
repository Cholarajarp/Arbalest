"""The Mirror Sandbox — the shim, the harness, and a real self-test run."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from engine.ouroboros.mirror import (
    MARKER_FAILED,
    MARKER_PASSED,
    build_mirror_workspace,
    conservative_verdict,
)
from engine.ouroboros.metacognitive import MetacognitiveAgent

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_pydantic_shim_supports_class_definitions():
    """The shim must let engine modules define pydantic models without pydantic."""
    shim = Path(__file__).resolve().parent.parent / "engine" / "ouroboros" / "mirror.py"
    namespace: dict[str, object] = {}
    exec(compile(shim.read_text(encoding="utf-8").split('_MIRROR_HARNESS = ')[0], "shim", "exec"), namespace)
    # The shim source above only defines the template strings — instead execute
    # the embedded sitecustomize source directly:
    from engine.ouroboros.mirror import _SITECUSTOMIZE

    proc = subprocess.run(
        [sys.executable, "-c", _SITECUSTOMIZE + "\n"
         "import pydantic\n"
         "class Probe(pydantic.BaseModel):\n"
         "    x: int\n"
         "    name: str = 'arbalest'\n"
         "p = Probe(x=42)\n"
         "assert p.x == 42 and p.name == 'arbalest'\n"
         "assert p.model_dump()['x'] == 42\n"
         "assert pydantic.Field(default=1) is not None\n"
         "print('SHIM_OK')"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "SHIM_OK" in proc.stdout


def _write_closure(workspace: Path, closure: list[str], sources: dict[str, str]) -> None:
    for rel in closure:
        target = workspace / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(sources[rel], encoding="utf-8")


def test_mirror_harness_runs_real_engine_end_to_end(tmp_path: Path):
    """Full mirror run on the host interpreter: shims + closure + battery + capability.

    This is the real mirror-sandbox script set executed as a subprocess —
    the same files the Docker sandbox would receive.
    """
    from engine.ouroboros.mirror import BATTERY_SEEDS

    agent = MetacognitiveAgent(self_root=REPO_ROOT)
    sources = agent.self_sources()
    mutated = {
        "engine/immune/detection.py": sources["engine/immune/detection.py"]
        + "\n\ndef ouroboros_sentinel():\n    return 42\n"
    }
    closure, _external = agent.import_closure(
        list(BATTERY_SEEDS) + list(mutated), sources, cap=30,
    )

    capability_test = (
        "from engine.immune.detection import ouroboros_sentinel, sweep_file\n"
        "assert ouroboros_sentinel() == 42\n"
        "hits = sweep_file('m.py', 'import pickle\\n\\nvoid = pickle.loads(b)\\n')\n"
        "assert any(f.rule_id == 'SENT-PY-004' for f in hits)\n"
    )
    workspace = build_mirror_workspace(
        mutated=mutated, closure=closure, original_sources=sources, capability_test=capability_test,
    )
    assert "sitecustomize.py" in workspace and "mirror_harness.py" in workspace
    assert "engine/__init__.py" in workspace, "mirror install must include package inits"

    run_dir = tmp_path / "mirror"
    for rel, content in workspace.items():
        target = run_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "mirror_harness.py"], cwd=str(run_dir), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
    )
    transcript = proc.stdout + proc.stderr
    assert MARKER_PASSED in transcript, transcript[-3000:]
    assert proc.returncode == 0
    assert "engine.immune.detection sweep" in proc.stdout
    assert "engine.hive.federation cross-repo link" in proc.stdout
    assert "capability synthesis" in proc.stdout


def test_conservative_verdict_requires_marker_and_clean_exit():
    assert conservative_verdict(sandbox_succeeded=True, exit_code=0,
                                transcript=f"all good\n{MARKER_PASSED}\n") is True
    assert conservative_verdict(sandbox_succeeded=True, exit_code=1, transcript=MARKER_PASSED) is False
    assert conservative_verdict(sandbox_succeeded=True, exit_code=0, transcript=MARKER_FAILED) is False
    assert conservative_verdict(sandbox_succeeded=False, exit_code=0, transcript=MARKER_PASSED) is False


def test_build_mirror_workspace_includes_all_layers():
    workspace = build_mirror_workspace(
        mutated={"engine/immune/detection.py": "mutated\n"},
        closure=["engine/__init__.py", "engine/immune/__init__.py"],
        original_sources={"engine/__init__.py": "", "engine/immune/__init__.py": ""},
        capability_test="assert True\n",
        fixtures={"fixtures/sample.py": "x = 1\n"},
    )
    assert set(workspace) == {
        "sitecustomize.py", "mirror_harness.py", "capability_test.py",
        "engine/immune/detection.py", "engine/__init__.py", "engine/immune/__init__.py",
        "fixtures/sample.py",
    }
    assert workspace["engine/immune/detection.py"] == "mutated\n"
