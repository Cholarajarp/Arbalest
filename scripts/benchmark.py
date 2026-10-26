"""Arbalest detection benchmark: measured recall per case, per layer.

Offline mode scores the deterministic layers only (tripwire, taint, runtime
and dependency tables) — no provider, no network, fully reproducible. Live
mode runs a real `arbalest scan` per case and scores every class.

    python scripts/benchmark.py --offline
    python scripts/benchmark.py --provider nebius

Exit code: 0 when every offline-scored class is found, 1 otherwise (CI gate).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.agents.secret_scanner import SecretScannerAgent  # noqa: E402
from engine.immune.detection import sweep_sources  # noqa: E402
from engine.services.runtime_versions import (  # noqa: E402
    check_runtime_declarations,
    collect_runtime_declarations,
)
from engine.services import taint_analysis  # noqa: E402

CASES_ROOT = REPO_ROOT / "benchmarks" / "vulns"


def _read_sources(case: Path) -> dict[str, str]:
    return {
        path.relative_to(case).as_posix(): path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(case.rglob("*"))
        if path.is_file() and path.name != "ground_truth.json"
    }


def run_offline(case: Path) -> str:
    """Deterministic layers only: findings flattened into one scoring text."""
    sources = _read_sources(case)
    parts: list[str] = []
    for hit in sweep_sources(sources):
        parts.append(f"{hit.rule_id} {hit.name} {hit.cwe} {hit.evidence}")
    try:
        result = taint_analysis.analyze_taint(sources)
        for finding in result.findings:
            parts.append(f"{finding.finding_id} {finding.summary} {finding.cwe} {' '.join(finding.evidence)}")
    except Exception as exc:  # noqa: BLE001 - benchmark must report, not crash
        parts.append(f"taint-analysis-error: {exc}")
    declarations = collect_runtime_declarations(sources)
    findings, _ = asyncio.run(check_runtime_declarations(declarations, client=_NoClient()))
    for finding in findings:
        parts.append(f"{finding.finding_id} {finding.cwe} {finding.summary} {' '.join(finding.evidence)}")
    try:
        for finding in asyncio.run(SecretScannerAgent().analyze(sources)):
            parts.append(f"{finding.finding_id} {finding.cwe} {finding.summary} {' '.join(finding.evidence)}")
    except Exception as exc:  # noqa: BLE001
        parts.append(f"secret-scan-error: {exc}")
    return " ".join(parts).lower()


class _NoClient:
    """Forces the offline emergency table; no network access."""

    async def get(self, url: str):
        import httpx

        raise httpx.ConnectError("offline benchmark")

    async def aclose(self):
        return None


def run_live(case: Path, provider: str | None, model: str | None) -> str:
    command = [
        sys.executable, str(REPO_ROOT / "arbalest_cli.py"), "scan", str(case),
        "-f", "json", "-o", "-", "--hypotheses",
    ]
    if provider:
        command += ["--provider", provider]
    if model:
        command += ["-m", model]
    completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return f"live-scan-error: exit {completed.returncode}: {completed.stderr[-400:]}"
    rows = []
    for finding in payload.get("findings", []):
        rows.append(f"{finding.get('summary', '')} {finding.get('cwe', '')} {' '.join(finding.get('evidence', []))}")
    return " ".join(rows).lower()


def score(text: str, ground_truth: Path, layer: str | None) -> tuple[int, int, list[str]]:
    data = json.loads(ground_truth.read_text(encoding="utf-8"))
    found, missed = 0, []
    total = 0
    for item in data["classes"]:
        if layer is not None and item.get("layer") != layer:
            continue
        total += 1
        keywords = [keyword.lower() for keyword in item["keywords"]]
        if all(keyword in text for keyword in keywords):
            found += 1
        else:
            missed.append(item["id"])
    return found, total, missed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--offline", action="store_true", help="deterministic layers only (no provider)")
    mode.add_argument("--provider", help="run a live scan per case with this provider")
    parser.add_argument("--model", help="model id for live mode")
    args = parser.parse_args()

    layer = "deterministic" if args.offline else None
    print(f"{'case':16} {'mode':8} {'recall':>9}  missed")
    print("-" * 60)
    failures = 0
    for case in sorted(path for path in CASES_ROOT.iterdir() if path.is_dir()):
        truth = case / "ground_truth.json"
        if not truth.is_file():
            continue
        if args.offline:
            text = run_offline(case)
            mode = "offline"
        else:
            text = run_live(case, args.provider, args.model)
            mode = "live"
        found, total, missed = score(text, truth, layer)
        if not total:
            print(f"{case.name:16} {mode:8} {'n/a':>9}  (no classes for this mode)")
            continue
        status = "OK" if not missed else "MISS"
        if missed:
            failures += 1
        print(f"{case.name:16} {mode:8} {found}/{total:>5}  {status}: {', '.join(missed) or '-'}")
    print("-" * 60)
    print("result:", "PASS" if failures == 0 else f"{failures} case(s) with misses")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
