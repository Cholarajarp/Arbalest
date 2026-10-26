"""Run the local, synthetic taint corpus: python benchmarks/taint/runner.py.

Fixtures are data, never imported or executed. Metrics match exact sink path,
line and CWE, not just whether a case produced any finding.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.services.taint_analysis import analyze_taint  # noqa: E402


def run_benchmark() -> dict[str, Any]:
    cases = json.loads((Path(__file__).parent / "fixtures" / "cases.json").read_text(encoding="utf-8"))
    started = time.perf_counter()
    tp = fp = fn = negative = clean_negative = complete = source_files = 0
    details = []
    for case in cases:
        result = analyze_taint(case["sources"])
        expected = {tuple(item) for item in case["expected"]}
        predicted = set()
        for finding in result.findings:
            match = re.match(r"^(.*):(\d+) sink ", finding.evidence[-1])
            if match is None:
                raise AssertionError(f"Finding lacks sink trace: {finding}")
            predicted.add((match[1], int(match[2]), finding.cwe))
        hits, extras, misses = predicted & expected, predicted - expected, expected - predicted
        tp += len(hits)
        fp += len(extras)
        fn += len(misses)
        source_files += len(case["sources"])
        complete += int(result.coverage.complete)
        if not expected:
            negative += 1
            clean_negative += int(not predicted)
        details.append(
            {
                "name": case["name"],
                "expected": sorted(expected),
                "predicted": sorted(predicted),
                "complete": result.coverage.complete,
                "issues": result.coverage.issues,
            }
        )
    return {
        "corpus": "local synthetic Python cross-file fixtures (not an external evaluation)",
        "fixture_count": len(cases),
        "source_file_count": source_files,
        "positive_fixture_count": len(cases) - negative,
        "negative_fixture_count": negative,
        "clean_negative_fixture_count": clean_negative,
        "complete_fixture_count": complete,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "elapsed_seconds": time.perf_counter() - started,
        "fixtures": details,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optionally write the JSON measurements to this path")
    args = parser.parse_args()
    report = run_benchmark()
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(text, end="")
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    return int(
        bool(
            report["false_positives"]
            or report["false_negatives"]
            or report["complete_fixture_count"] != report["fixture_count"]
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
