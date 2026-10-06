"""HiveRegistry — the organization's global immune memory.

One filesystem-backed store at the fleet root holding:

* broadcast antibodies (Semgrep YAML, shared with the per-repo Antibody format)
* learned threat patterns (from the ImmuneSystemAgent / graph memory)

Publish/acknowledge semantics give repositories peer-to-peer behavior: a
pattern published by repo-A is outstanding for repo-B until repo-B's sweep
has incorporated and acknowledged it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from engine.immune.antibody import Antibody

_HIVE_DIR = ".arbalest/hive"
_ANTIBODIES = "antibodies"
_PATTERNS = "patterns.json"


class HiveRegistry:
    def __init__(self, fleet_root: Path) -> None:
        self.root = Path(fleet_root)
        self.directory = self.root / _HIVE_DIR
        self.antibody_dir = self.directory / _ANTIBODIES
        self._patterns_path = self.directory / _PATTERNS

    # -- antibodies ------------------------------------------------------------
    def broadcast_antibody(self, antibody: Antibody, *, origin_repo: str) -> dict[str, object]:
        """Publish an antibody to the whole fleet. Idempotent per rule_id."""
        self.antibody_dir.mkdir(parents=True, exist_ok=True)
        target = self.antibody_dir / f"{antibody.rule_id}.yml"
        target.write_text(antibody.yaml_text, encoding="utf-8")
        record = {
            "rule_id": antibody.rule_id,
            "cwe": antibody.cwe,
            "severity": antibody.severity,
            "threat_name": antibody.threat_name,
            "language": antibody.language,
            "origin_repo": origin_repo,
            "broadcast_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "path": str(target),
        }
        registry_path = self.antibody_dir / "registry.json"
        entries: list[dict[str, object]] = []
        if registry_path.is_file():
            try:
                entries = json.loads(registry_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                entries = []
        entries = [e for e in entries if e.get("rule_id") != antibody.rule_id]
        entries.append(record)
        registry_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        return record

    # -- learned threat patterns ---------------------------------------------------
    def list_patterns(self) -> list[dict[str, object]]:
        if not self._patterns_path.is_file():
            return []
        try:
            return json.loads(self._patterns_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []

    def save_pattern(self, record: dict[str, object]) -> dict[str, object]:
        self.directory.mkdir(parents=True, exist_ok=True)
        entries = self.list_patterns()
        entries = [e for e in entries if e.get("pattern_id") != record.get("pattern_id")]
        entries.append(record)
        self._patterns_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        return record

    def outstanding_for(self, repo: str) -> list[dict[str, object]]:
        """Patterns published but not yet acknowledged by *repo* (P2P sync queue)."""
        return [
            p for p in self.list_patterns()
            if repo not in (p.get("acknowledged_by") or [])
        ]

    def acknowledge(self, repo: str, pattern_id: str) -> bool:
        entries = self.list_patterns()
        changed = False
        for entry in entries:
            if entry.get("pattern_id") == pattern_id:
                acked = entry.setdefault("acknowledged_by", [])
                if repo not in acked:
                    acked.append(repo)
                    changed = True
        if changed:
            self._patterns_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        return changed
