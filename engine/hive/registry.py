"""Typed, filesystem-backed fleet immune memory."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from engine.immune.antibody import Antibody, AntibodyError

_HIVE_DIR = ".arbalest/hive"
_ANTIBODIES = "antibodies"
_PATTERNS = "patterns.json"


def _object_records(value: Any) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


class HiveRegistry:
    def __init__(self, fleet_root: Path) -> None:
        self.root = Path(fleet_root)
        self.directory = self.root / _HIVE_DIR
        self.antibody_dir = self.directory / _ANTIBODIES
        self._patterns_path = self.directory / _PATTERNS

    def broadcast_antibody(self, antibody: Antibody, *, origin_repo: str) -> dict[str, object]:
        if not antibody.validated:
            raise AntibodyError("refusing to broadcast an unvalidated antibody")
        self.antibody_dir.mkdir(parents=True, exist_ok=True)
        target = self.antibody_dir / f"{antibody.rule_id}.yml"
        target.write_text(antibody.yaml_text, encoding="utf-8")
        record: dict[str, object] = {
            "rule_id": antibody.rule_id, "cwe": antibody.cwe, "severity": antibody.severity,
            "threat_name": antibody.threat_name, "language": antibody.language, "validated": True,
            "origin_repo": origin_repo, "broadcast_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "path": str(target),
        }
        registry_path = self.antibody_dir / "registry.json"
        entries: list[dict[str, object]] = []
        if registry_path.is_file():
            try:
                entries = _object_records(json.loads(registry_path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                entries = []
        entries = [entry for entry in entries if entry.get("rule_id") != antibody.rule_id]
        entries.append(record)
        registry_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        return record

    def list_patterns(self) -> list[dict[str, object]]:
        if not self._patterns_path.is_file():
            return []
        try:
            return _object_records(json.loads(self._patterns_path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            return []

    def save_pattern(self, record: dict[str, object]) -> dict[str, object]:
        self.directory.mkdir(parents=True, exist_ok=True)
        entries = [entry for entry in self.list_patterns() if entry.get("pattern_id") != record.get("pattern_id")]
        entries.append(record)
        self._patterns_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        return record

    def outstanding_for(self, repo: str) -> list[dict[str, object]]:
        outstanding: list[dict[str, object]] = []
        for pattern in self.list_patterns():
            raw = pattern.get("acknowledged_by")
            acknowledged = [str(item) for item in raw] if isinstance(raw, list) else []
            if repo not in acknowledged:
                outstanding.append(pattern)
        return outstanding

    def acknowledge(self, repo: str, pattern_id: str) -> bool:
        entries = self.list_patterns()
        changed = False
        for entry in entries:
            if entry.get("pattern_id") != pattern_id:
                continue
            raw = entry.get("acknowledged_by")
            acknowledged = [str(item) for item in raw] if isinstance(raw, list) else []
            if repo not in acknowledged:
                acknowledged.append(repo)
                entry["acknowledged_by"] = acknowledged
                changed = True
        if changed:
            self.directory.mkdir(parents=True, exist_ok=True)
            self._patterns_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        return changed
