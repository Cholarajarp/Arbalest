"""Operator feedback: per-finding dispositions that survive across scans.

A finding marked false-positive by the operator is never deleted — the
fail-closed contract keeps every finding visible — but it is annotated and
ranked down in every future scan that reproduces the same content-hash id.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("arbalest.dispositions")

VERDICTS = frozenset({"false-positive", "accepted"})


def dispositions_path(target: Path) -> Path:
    return target.resolve() / ".arbalest" / "dispositions.json"


def load_dispositions(target: Path) -> dict[str, dict[str, Any]]:
    path = dispositions_path(target)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.warning("Ignoring unreadable dispositions file: %s", path)
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(key): value
        for key, value in data.items()
        if isinstance(value, dict) and value.get("verdict") in VERDICTS
    }


def record_disposition(target: Path, finding_id: str, verdict: str, note: str = "") -> Path:
    """Persist one operator verdict; write-once per finding id unless repeated."""
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {sorted(VERDICTS)}")
    finding_id = finding_id.strip()[:128]
    if not finding_id:
        raise ValueError("finding id must not be empty")
    path = dispositions_path(target)
    existing = load_dispositions(target)
    existing[finding_id] = {
        "verdict": verdict,
        "note": note.strip()[:500],
        "updated_utc": datetime.now(UTC).isoformat(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")
    return path


__all__ = ["VERDICTS", "dispositions_path", "load_dispositions", "record_disposition"]
