"""Immune mission — split-pane readout fallback, wargame bounds, CLI contract."""

from __future__ import annotations

import asyncio
import io
import subprocess
import sys
import unittest.mock as mock
from pathlib import Path

import pytest

from engine.immune.readout import WargameReadout
from engine.immune.wargame import WargameEngine
from engine.ui.terminal import Console
from arbalest_cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_readout_nontty_fallback_lines():
    async def scenario() -> str:
        buf = io.StringIO()
        console = Console(stream=buf)
        console.live = False
        readout = WargameReadout(console, title="Iter 1: Architect vs RedTeam")
        readout.open("Iter 1: Architect vs RedTeam")
        readout.left("ARCHITECT drafting mutation plan")
        readout.right("REDTEAM crafting breach harness")
        await readout.close()
        return buf.getvalue()

    out = asyncio.run(scenario())
    assert "[WARGAME]" in out
    assert "▣ ARCH ▸ ARCHITECT drafting mutation plan" in out
    assert "▣ REDTEAM ▸ REDTEAM crafting breach harness" in out
    assert "\x1b[" not in out, "non-TTY readout must not emit ANSI cursor control"


def test_readout_tty_keeps_final_frame_when_closed_before_flush():
    async def scenario() -> str:
        buf = io.StringIO()
        console = Console(stream=buf)
        console.live = True
        readout = WargameReadout(console, title="Iter 1")
        readout.open("Iter 1")
        readout.left("ARCHITECT drafting mutation plan")
        readout.right("BREACH FAILED — patch held")
        await readout.close()
        return buf.getvalue()

    out = asyncio.run(scenario())
    final = out.rsplit("╔═[WARGAME]", 1)[-1]
    assert "ARCHITECT drafting mutation plan" in final
    assert "BREACH FAILED — patch held" in final


def test_wargame_rejects_invalid_budget():
    with pytest.raises(ValueError):
        WargameEngine(provider=None, sandbox=None, max_iterations=0)


def test_readout_pane_frame_renders_two_columns():
    async def scenario() -> str:
        buf = io.StringIO()
        console = Console(stream=buf, silent=False)
        readout = WargameReadout(console, height=9, title="Iter 2: Architect vs RedTeam")
        readout._pane_live = True  # force the TTY split-pane renderer deterministically
        readout.open("Iter 2: Architect vs RedTeam")
        readout.left("plan a1b2: 3 mutations → go")
        readout.right("BREACH — objective reached")
        await asyncio.sleep(0.3)  # flush loop redraws the frame
        await readout.close()
        return buf.getvalue()

    out = asyncio.run(scenario())
    assert "ARCHITECT-01" in out and "REDTEAM-SWARM" in out
    assert "plan a1b2" in out and "BREACH" in out
    assert "╔" in out and "╚" in out                    # pane borders drawn
    assert "\x1b[" in out                              # cursor-controlled redraw in pane mode


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "arbalest_cli.py"), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def test_immune_help():
    proc = _run_cli("immune", "--help")
    assert proc.returncode == 0
    normalized = " ".join(proc.stdout.split())
    assert "Immune System mode" in normalized
    assert "blast-radius" in normalized


def test_immune_rejects_missing_target():
    proc = _run_cli("immune", "Z:/definitely/not/here")
    assert proc.returncode == 2
    assert "ORGANISM REJECTED" in proc.stdout


def test_immune_stage1_runs_real_topology_then_requires_core():
    """No API key: stage 1 (detection + topology) is real; stage 2 aborts armed-check."""
    proc = _run_cli("immune", str(REPO_ROOT / "examples" / "immune_target"))
    assert proc.returncode == 2
    out = proc.stdout
    assert "IMMUNE SYSTEM MODE" in out
    assert "[1/3]" in out and "BLAST-RADIUS" in out.upper()
    assert "EXPLOITABILITY PROVEN" in out, "real AST chain must be proven without any AI core"
    assert "AI CORE NOT ARMED" in out


def test_main_dispatches_immune():
    with mock.patch("sys.argv", ["arbalest", "immune", "Z:/nope"]):
        try:
            main()
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError("main() must exit with code 2")


def test_stage_heal_writes_patch_and_leaves_source_untouched(tmp_path):
    """Default immune behavior: verified bundles stage reviewable patches only."""
    from types import SimpleNamespace

    from engine.immune.mission import _stage_heal

    original = "import os" + chr(10) + "os.system(cmd)" + chr(10)
    healed = "import subprocess" + chr(10) + "subprocess.run(cmd_list)" + chr(10)
    (tmp_path / "exec.py").write_text(original, encoding="utf-8")
    bundle = SimpleNamespace(file_mapping=lambda: {"exec.py": healed})
    target = SimpleNamespace(
        finding=SimpleNamespace(rule_id="SENT-PY-008"),
        wargame=SimpleNamespace(resolved=True, final_bundle=bundle),
    )
    console = Console(stream=io.StringIO())
    _stage_heal(console, tmp_path, target)

    patch = tmp_path / ".arbalest" / "proposed-heals" / "SENT-PY-008.patch"
    assert patch.is_file()
    assert "VERIFIED HEAL" in patch.read_text(encoding="utf-8")
    assert (tmp_path / "exec.py").read_text(encoding="utf-8") == original


def test_immune_help_documents_deploy_flag():
    proc = _run_cli("immune", "--help")
    assert "--deploy" in proc.stdout
