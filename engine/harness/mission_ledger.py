"""Tamper-evident, append-only mission ledger.

Every consequential harness event — denied action, neutralized injection,
wargame verdict — is recorded as a hash-chained JSONL entry. Each entry
commits to the SHA-256 of the previous entry, so deleting, reordering, or
editing recorded history after the fact is detectable by ``verify()``.

This is an audit trail, not a security boundary: it makes a verdict's
provenance inspectable, which is exactly what a Tier-1 debrief requires.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

_GENESIS_HASH = "0" * 64
_MAX_DETAIL = 500


def _canonical_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


class LedgerEntry(BaseModel):
    """One hash-chained audit record."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=1)
    ts: str
    actor: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=128)
    verdict: str = Field(min_length=1, max_length=64)
    detail: str = Field(default="", max_length=_MAX_DETAIL)
    prev_hash: str = Field(min_length=64, max_length=64)
    hash: str = Field(min_length=64, max_length=64)


class MissionLedger:
    """Append-only JSONL ledger with SHA-256 chain integrity."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = self._count_entries()

    @property
    def path(self) -> Path:
        return self._path

    def record(self, *, actor: str, action: str, verdict: str, detail: str = "") -> LedgerEntry:
        detail = " ".join((detail or "").split())[:_MAX_DETAIL]
        entry_hash_source = {
            "seq": self._seq + 1,
            "actor": actor,
            "action": action,
            "verdict": verdict,
            "detail": detail,
            "prev_hash": self._last_hash(),
        }
        entry = LedgerEntry(
            seq=entry_hash_source["seq"],
            ts=datetime.now(UTC).isoformat(timespec="milliseconds"),
            actor=entry_hash_source["actor"],
            action=entry_hash_source["action"],
            verdict=entry_hash_source["verdict"],
            detail=entry_hash_source["detail"],
            prev_hash=entry_hash_source["prev_hash"],
            hash=_canonical_hash(entry_hash_source),
        )
        with self._path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(entry.model_dump_json() + "\n")
        self._seq += 1
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """Re-walk the chain. Returns (intact, first_broken_seq_or_None)."""
        previous = _GENESIS_HASH
        line_number = 0
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line_number += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = LedgerEntry.model_validate_json(line)
                except Exception:
                    return False, line_number  # malformed record is itself a break
                expected_source = {
                    "seq": entry.seq,
                    "actor": entry.actor,
                    "action": entry.action,
                    "verdict": entry.verdict,
                    "detail": entry.detail,
                    "prev_hash": entry.prev_hash,
                }
                if entry.prev_hash != previous or entry.hash != _canonical_hash(expected_source):
                    return False, entry.seq
                previous = entry.hash
        return True, None

    def _last_hash(self) -> str:
        last = _GENESIS_HASH
        if not self._path.exists():
            return last
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    try:
                        last = str(json.loads(line).get("hash", last))
                    except json.JSONDecodeError:
                        continue
        return last

    def _count_entries(self) -> int:
        if not self._path.exists():
            return 0
        count = 0
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    count += 1
        return count


def previous_seq_safe(previous: str) -> int:
    """Best-effort sequence for malformed-line reporting; 0 signals unknown."""
    return 0


__all__ = ["LedgerEntry", "MissionLedger"]
