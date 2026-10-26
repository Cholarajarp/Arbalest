"""Hive Mind CLI — board rendering, fleet discovery, and the real mission contract."""

from __future__ import annotations

import asyncio
import io
import subprocess
import sys
import unittest.mock as mock
from pathlib import Path

from engine.hive.board import FleetBoard
from engine.hive.mission import discover_fleet
from engine.ui.terminal import Console
from arbalest_cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent
FLEET_DIR = REPO_ROOT / "examples" / "hive_fleet"


def test_fleet_discovers_fixture_repos():
    repos = discover_fleet(FLEET_DIR)
    assert set(repos) == {"authlib", "billing-api", "search-api"}


def test_board_nontty_status_lines():
    async def scenario() -> str:
        buf = io.StringIO()
        console = Console(stream=buf)
        console.live = False
        board = FleetBoard(console, rows=["authlib:SENT-PY-004", "billing-api:SENT-PY-004"])
        board.update("authlib:SENT-PY-004", cwe="CWE-502", status="WARGAMING", sandbox="docker")
        board.update("authlib:SENT-PY-004", cwe="CWE-502", iter="3", status="HEALED", sandbox="docker")
        board.update("billing-api:SENT-PY-004", cwe="CWE-502", status="AUDITED", sandbox="—")
        board.close()
        return buf.getvalue()

    out = asyncio.run(scenario())
    assert "⬡ [authlib:SENT-PY-004]" in out
    assert "status=HEALED" in out
    assert "status=AUDITED" in out
    assert "\x1b[" not in out, "non-TTY board must not emit ANSI cursor control"


def test_board_pane_mode_draws_matrix():
    async def scenario() -> str:
        buf = io.StringIO()
        console = Console(stream=buf, silent=False)
        board = FleetBoard(console, rows=["authlib:R1", "billing-api:R2"])
        board._live = True  # force the TTY matrix renderer deterministically
        board.update("authlib:R1", cwe="CWE-502", status="HEALED", iter="2", sink="tokens.py:7", sandbox="docker")
        board.update("billing-api:R2", cwe="CWE-502", status="AUDITED", sink="app.py:12", sandbox="—")
        board.close()
        return buf.getvalue()

    out = asyncio.run(scenario())
    assert "REPO" in out and "STATUS" in out          # header row
    assert "authlib:R1" in out and "billing-api:R2" in out
    assert "╔" in out or "┌" in out                    # matrix borders drawn


def test_fleet_help():
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "arbalest_cli.py"), "fleet", "--help"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert proc.returncode == 0
    normalized = " ".join(proc.stdout.split())
    assert "Hive Mind" in normalized
    assert "target-dir" in normalized


def test_fleet_requires_target_dir():
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "arbalest_cli.py"), "fleet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert proc.returncode == 2


def test_fleet_stages_1_2_real_then_requires_core():
    """No API key: federated recon + cross-repo blast radius are real; stage 3 aborts."""
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "arbalest_cli.py"), "fleet", "--target-dir", str(FLEET_DIR)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert proc.returncode == 2
    out = proc.stdout
    assert "HIVE MIND" in out
    assert "[1/4]" in out and "FEDERATED RECON" in out.upper()
    assert "billing-api" in out and "authlib" in out
    assert "EXPLOITABILITY PROVEN" in out, "cross-repo chain must be proven without any AI core"
    assert "spanning 2 repositories" in out, "the authlib sink must reach the billing-api route"
    assert "AI CORE NOT ARMED" in out


def test_main_dispatches_fleet():
    with mock.patch("sys.argv", ["arbalest", "fleet", "--target-dir", "Z:/nope"]):
        try:
            main()
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError("main() must exit with code 2")
