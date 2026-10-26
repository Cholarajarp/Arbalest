"""Exit-code contract: 0 = SECURED, 1 = VULNERABLE, 2 = MISSION ERROR."""

from __future__ import annotations

import subprocess
import sys

from arbalest_cli import _gate_exit_code, main

VULNERABLE = {"critical": 1, "high": 2, "medium": 1, "low": 3, "info": 0}
CLEAN: dict[str, int] = {}


def test_default_gate_any_finding_fails():
    assert _gate_exit_code(VULNERABLE, "low", strict=False) == 1


def test_gate_clean_is_secured():
    assert _gate_exit_code(CLEAN, "low", strict=False) == 0


def test_gate_threshold_ignores_below():
    counts = {"medium": 1, "low": 5}
    assert _gate_exit_code(counts, "medium", strict=False) == 1
    assert _gate_exit_code(counts, "high", strict=False) == 0


def test_gate_none_opt_out():
    assert _gate_exit_code(VULNERABLE, "none", strict=False) == 0


def test_gate_strict_counts_info():
    counts = {"info": 2}
    assert _gate_exit_code(counts, "low", strict=False) == 0
    assert _gate_exit_code(counts, "low", strict=True) == 1


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(__import__("pathlib").Path(__file__).parent.parent / "arbalest_cli.py"), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def test_cli_scan_missing_target_exit_2():
    proc = _run_cli("scan", "Z:/definitely/not/here")
    assert proc.returncode == 2


def test_cli_scan_unarmed_core_exit_2():
    import pathlib

    proc = _run_cli("scan", str(pathlib.Path(__file__).parent.parent))
    assert proc.returncode == 2
    assert "No API key armed" in proc.stdout


def test_cli_version():
    proc = _run_cli("--version")
    assert proc.returncode == 0
    assert "arbalest" in proc.stdout


def test_main_dispatches_scan():
    # Missing target must exit 2 via the real argparse dispatch path.
    sys_argv = ["arbalest", "scan", "Z:/nope"]
    import unittest.mock as mock

    with mock.patch("sys.argv", sys_argv):
        try:
            main()
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError("main() must exit with code 2")
