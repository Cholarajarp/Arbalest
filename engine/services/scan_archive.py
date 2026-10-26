"""Canonical, tamper-evident scan archives and deterministic comparison."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from engine import __version__
from engine.agents.architect_agent import ThreatFinding
from engine.services.scan_pipeline import SwarmResult

_SCAN_ID = re.compile(r"^[a-f0-9]{12}$")
_SCHEMA_VERSION = "1"


class ScanArchiveError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ScanArchiveRef:
    scan_id: str
    directory: Path
    manifest_path: Path
    seal_sha256: str


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _occurrence_id(finding: ThreatFinding) -> str:
    material = {
        "cwe": finding.cwe.upper(),
        "summary": " ".join(finding.summary.lower().split()),
        "nodes": sorted(node.replace("\\", "/") for node in finding.affected_nodes),
    }
    return _sha(_canonical(material))[:24]


def _repository_state(root: Path) -> dict[str, Any]:
    def git(*args: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", *args], cwd=root, capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return result.stdout.strip() if result.returncode == 0 else None

    top = git("rev-parse", "--show-toplevel")
    if not top or Path(top).resolve() != root.resolve():
        return {"kind": "directory_snapshot", "revision": None, "dirty": None}
    revision = git("rev-parse", "HEAD")
    status = git("status", "--porcelain=v1", "--untracked-files=normal")
    return {"kind": "git_worktree", "revision": revision, "dirty": bool(status)}


def save_scan_archive(
    target: Path,
    scan_id: str,
    result: SwarmResult,
    *,
    provider: str,
    model: str,
) -> ScanArchiveRef:
    if not _SCAN_ID.fullmatch(scan_id):
        raise ScanArchiveError("scan id must contain exactly 12 lowercase hexadecimal characters")
    root = target.resolve()
    directory = root / ".arbalest" / "scans" / scan_id
    directory.mkdir(parents=True, exist_ok=False)

    provenance: dict[str, list[str]] = {}
    for agent, findings in result.buckets.items():
        for finding in findings:
            provenance.setdefault(finding.finding_id, []).append(agent)
    findings_document = {
        "schema_version": _SCHEMA_VERSION,
        "scan_id": scan_id,
        "findings": [
            {
                "occurrence_id": _occurrence_id(finding),
                "finding": finding.model_dump(mode="json"),
                "sources": sorted(provenance.get(finding.finding_id, [])),
            }
            for finding in result.findings
        ],
    }
    coverage_document = {
        "schema_version": _SCHEMA_VERSION,
        "scan_id": scan_id,
        "coverage": result.recon.summary() if result.recon else None,
        "analyzers": {
            name: stat.coverage for name, stat in result.stats.items() if stat.coverage is not None
        },
    }
    receipts_document = {
        "schema_version": _SCHEMA_VERSION,
        "scan_id": scan_id,
        "agents": {name: stat.as_dict() for name, stat in result.stats.items()},
        "injection_hits": [hit.model_dump(mode="json") for hit in result.injection_hits],
        "memory": {"ingested": result.memory_ingested, "detail": result.memory_detail},
        "budget": result.budget,
    }

    documents = {
        "findings.json": findings_document,
        "coverage.json": coverage_document,
        "receipts.json": receipts_document,
    }
    artifact_records: list[dict[str, str]] = []
    for name, payload in documents.items():
        data = _canonical(payload) + b"\n"
        _atomic_write(directory / name, data)
        artifact_records.append({"path": name, "sha256": _sha(data)})

    manifest = {
        "schema_version": _SCHEMA_VERSION,
        "scan_id": scan_id,
        "producer": {"name": "Arbalest", "version": __version__},
        "created_at": datetime.now(UTC).isoformat(),
        "status": result.status,
        "complete": result.complete,
        "target": {"root": str(root), **_repository_state(root)},
        "provider": provider,
        "model": model,
        "finding_count": len(result.findings),
        "artifacts": sorted(artifact_records, key=lambda item: item["path"]),
    }
    manifest_data = _canonical(manifest) + b"\n"
    _atomic_write(directory / "manifest.json", manifest_data)
    manifest_sha = _sha(manifest_data)
    bundle_sha = _sha(_canonical({"manifest": manifest_sha, "artifacts": manifest["artifacts"]}))
    seal = {"schema_version": _SCHEMA_VERSION, "scan_id": scan_id, "manifest_sha256": manifest_sha,
            "bundle_sha256": bundle_sha, "sealed_at": datetime.now(UTC).isoformat()}
    _atomic_write(directory / "seal.json", _canonical(seal) + b"\n")
    return ScanArchiveRef(scan_id, directory, directory / "manifest.json", bundle_sha)


def load_scan_archive(target: Path, scan_id: str) -> dict[str, Any]:
    if not _SCAN_ID.fullmatch(scan_id):
        raise ScanArchiveError("invalid scan id")
    root = target.resolve()
    directory = (root / ".arbalest" / "scans" / scan_id).resolve()
    try:
        directory.relative_to(root)
    except ValueError as exc:
        raise ScanArchiveError("scan archive escapes target root") from exc
    if directory.is_symlink() or not directory.is_dir():
        raise ScanArchiveError("scan archive does not exist as a regular directory")
    manifest_data = _read_checked(directory, "manifest.json")
    seal_data = _read_checked(directory, "seal.json")
    try:
        manifest = json.loads(manifest_data)
        seal = json.loads(seal_data)
    except json.JSONDecodeError as exc:
        raise ScanArchiveError("scan archive contains invalid JSON") from exc
    if manifest.get("scan_id") != scan_id or seal.get("scan_id") != scan_id:
        raise ScanArchiveError("scan archive identifiers do not match")
    target_record = manifest.get("target")
    if not isinstance(target_record, dict) or Path(str(target_record.get("root", ""))).resolve() != root:
        raise ScanArchiveError("scan archive target does not match the selected repository")
    if _sha(manifest_data) != seal.get("manifest_sha256"):
        raise ScanArchiveError("scan manifest seal mismatch")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ScanArchiveError("scan manifest has no artifact inventory")
    loaded: dict[str, Any] = {"manifest": manifest, "seal": seal}
    canonical_records: list[dict[str, str]] = []
    for record in artifacts:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise ScanArchiveError("invalid scan artifact record")
        name = _safe_artifact_name(record["path"])
        data = _read_checked(directory, name)
        digest = _sha(data)
        if digest != record.get("sha256"):
            raise ScanArchiveError(f"sealed scan artifact changed: {name}")
        try:
            loaded[name] = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ScanArchiveError(f"scan artifact is invalid JSON: {name}") from exc
        if loaded[name].get("scan_id") != scan_id:
            raise ScanArchiveError(f"scan artifact id mismatch: {name}")
        canonical_records.append({"path": name, "sha256": digest})
    bundle_sha = _sha(_canonical({"manifest": seal["manifest_sha256"], "artifacts": sorted(canonical_records, key=lambda item: item["path"])}))
    if bundle_sha != seal.get("bundle_sha256"):
        raise ScanArchiveError("scan bundle seal mismatch")
    return loaded


def list_scan_archives(target: Path, limit: int = 20) -> list[dict[str, Any]]:
    count = min(max(int(limit), 1), 100)
    directory = target.resolve() / ".arbalest" / "scans"
    if not directory.is_dir():
        return []
    summaries: list[dict[str, Any]] = []
    for child in sorted(directory.iterdir(), key=lambda item: item.lstat().st_mtime, reverse=True):
        if not _SCAN_ID.fullmatch(child.name):
            continue
        try:
            archive = load_scan_archive(target, child.name)
        except ScanArchiveError:
            continue
        manifest = archive["manifest"]
        summaries.append({key: manifest.get(key) for key in (
            "scan_id", "created_at", "status", "complete", "finding_count", "provider", "model", "target"
        )})
        if len(summaries) >= count:
            break
    return summaries


def resolve_archived_finding(target: Path, finding_id: str) -> ThreatFinding | None:
    """Return the sealed finding record for ``finding_id`` from the newest matching scan.

    Remediation must plan from the finding the scan actually reported — real CWE,
    severity, summary and evidence — not a synthetic ``CWE-Unknown`` stub. Sealed
    archives are hash-verified by ``load_scan_archive``, so a tampered history
    yields no finding rather than a forged one.
    """
    wanted = finding_id.strip()
    if not wanted:
        return None
    root = target.resolve()
    scans = root / ".arbalest" / "scans"
    if not scans.is_dir():
        return None
    for child in sorted(scans.iterdir(), key=lambda item: item.lstat().st_mtime, reverse=True):
        if not _SCAN_ID.fullmatch(child.name):
            continue
        try:
            archive = load_scan_archive(root, child.name)
        except ScanArchiveError:
            continue
        rows = archive.get("findings.json", {}).get("findings", [])
        for row in rows if isinstance(rows, list) else []:
            finding = row.get("finding") if isinstance(row, dict) else None
            if isinstance(finding, dict) and finding.get("finding_id") == wanted:
                try:
                    return ThreatFinding.model_validate(finding)
                except Exception:
                    return None
    return None


def compare_scan_archives(target: Path, before_id: str, after_id: str) -> dict[str, Any]:
    before = load_scan_archive(target, before_id)
    after = load_scan_archive(target, after_id)
    before_rows = before["findings.json"].get("findings", [])
    after_rows = after["findings.json"].get("findings", [])
    before_map = {row["occurrence_id"]: row for row in before_rows if isinstance(row, dict) and "occurrence_id" in row}
    after_map = {row["occurrence_id"]: row for row in after_rows if isinstance(row, dict) and "occurrence_id" in row}
    before_ids, after_ids = set(before_map), set(after_map)
    return {
        "schema_version": _SCHEMA_VERSION,
        "before_scan_id": before_id,
        "after_scan_id": after_id,
        "new": [after_map[key] for key in sorted(after_ids - before_ids)],
        "persistent": [{"before": before_map[key], "after": after_map[key]} for key in sorted(before_ids & after_ids)],
        "resolved": [before_map[key] for key in sorted(before_ids - after_ids)],
        "uncertain": [],
        "method": "deterministic occurrence identity; semantically changed findings remain separate",
    }


def _safe_artifact_name(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or len(path.parts) != 1 or any(part in {"", ".", ".."} for part in path.parts):
        raise ScanArchiveError("unsafe scan artifact path")
    return path.as_posix()


def _read_checked(directory: Path, name: str) -> bytes:
    path = directory / _safe_artifact_name(name)
    if path.is_symlink() or not path.is_file():
        raise ScanArchiveError(f"missing regular scan artifact: {name}")
    resolved = path.resolve()
    try:
        resolved.relative_to(directory.resolve())
    except ValueError as exc:
        raise ScanArchiveError(f"scan artifact escapes archive: {name}") from exc
    return resolved.read_bytes()


def _atomic_write(path: Path, data: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".arbalest-scan-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


__all__ = [
    "ScanArchiveError", "ScanArchiveRef", "compare_scan_archives", "list_scan_archives",
    "load_scan_archive", "resolve_archived_finding", "save_scan_archive",
]
