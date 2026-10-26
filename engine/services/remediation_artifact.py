"""Immutable remediation artifacts binding generation, verification, and deployment."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from engine.agents.architect_agent import ArchitectureGraphContext, MutationPlan, ThreatFinding
from engine.agents.polyglot_translator import GeneratedCodeBundle, validate_generated_bundle
from engine.services.runtime import resolve_bundle_paths, safe_finding_id

_SCHEMA_VERSION = "1"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class RemediationArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = _SCHEMA_VERSION
    artifact_id: str = Field(pattern=r"^[a-f0-9]{24}$")
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: str
    finding: ThreatFinding
    plan: MutationPlan
    bundle: GeneratedCodeBundle
    source_hashes: dict[str, str]

    @model_validator(mode="after")
    def verify_integrity(self) -> "RemediationArtifact":
        if self.schema_version != _SCHEMA_VERSION:
            raise ValueError(f"unsupported remediation schema {self.schema_version!r}")
        bundle_hash = hashlib.sha256(_canonical(self.bundle.model_dump(mode="json"))).hexdigest()
        if bundle_hash != self.bundle_sha256:
            raise ValueError("remediation bundle hash mismatch")
        expected = _artifact_hash(self.finding, self.plan, self.bundle, self.source_hashes)
        if expected != self.artifact_sha256 or self.artifact_id != expected[:24]:
            raise ValueError("remediation artifact integrity check failed")
        if set(self.source_hashes) != set(self.bundle.file_mapping()):
            raise ValueError("remediation source hashes do not match bundle paths")
        if any(len(value) != 64 for value in self.source_hashes.values()):
            raise ValueError("invalid remediation source hash")
        return self


def _artifact_hash(
    finding: ThreatFinding,
    plan: MutationPlan,
    bundle: GeneratedCodeBundle,
    source_hashes: dict[str, str],
) -> str:
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "finding": finding.model_dump(mode="json"),
        "plan": plan.model_dump(mode="json"),
        "bundle": bundle.model_dump(mode="json"),
        "source_hashes": source_hashes,
    }
    return hashlib.sha256(_canonical(payload)).hexdigest()


def create_artifact(
    finding: ThreatFinding,
    plan: MutationPlan,
    bundle: GeneratedCodeBundle,
    original_sources: dict[str, str],
) -> RemediationArtifact:
    source_hashes = {path: _sha256_text(original_sources.get(path, "")) for path in bundle.file_mapping()}
    artifact_hash = _artifact_hash(finding, plan, bundle, source_hashes)
    return RemediationArtifact(
        artifact_id=artifact_hash[:24],
        artifact_sha256=artifact_hash,
        bundle_sha256=hashlib.sha256(_canonical(bundle.model_dump(mode="json"))).hexdigest(),
        created_at=datetime.now(UTC).isoformat(),
        finding=finding,
        plan=plan,
        bundle=bundle,
        source_hashes=source_hashes,
    )


def create_validated_artifact(
    target: Path,
    finding: ThreatFinding,
    plan: MutationPlan,
    bundle: GeneratedCodeBundle,
    sources: dict[str, str],
    graph: ArchitectureGraphContext,
) -> RemediationArtifact:
    """Build an artifact only after the plan and bundle pass every safety gate.

    This is the trust boundary for host-authored remediation candidates: the
    plan must be consistent with the architecture graph and available sources,
    the generated bundle must pass static safety inspection, and the bundle may
    only touch files the plan targets or brand-new files. An existing source
    file that the plan never named can never be silently overwritten.
    """
    plan.validate_against_context(graph, sources, plan.target_language)
    validate_generated_bundle(bundle, plan.target_language)
    plan_targets = {mutation.target_file.replace("\\", "/") for mutation in plan.mutations}
    source_paths = {path.replace("\\", "/") for path in sources}
    for path in bundle.file_mapping():
        normalized = path.replace("\\", "/")
        if normalized in plan_targets:
            continue
        if normalized in source_paths:
            raise ValueError(
                f"generated bundle rewrites an existing source file not targeted by the plan: {path}"
            )
    resolve_bundle_paths(target, list(bundle.file_mapping()))
    return create_artifact(finding, plan, bundle, sources)


def save_artifact(target: Path, artifact: RemediationArtifact) -> Path:
    """Publish an artifact write-once; an existing artifact is never overwritten."""
    root = target.resolve()
    directory = root / ".arbalest" / "remediations"
    directory.mkdir(parents=True, exist_ok=True)
    finding = safe_finding_id(artifact.finding.cwe or artifact.finding.finding_id)
    path = directory / f"{finding}-{artifact.artifact_id}.json"
    payload = artifact.model_dump_json(indent=2)

    if path.is_symlink():
        raise ValueError("remediation artifact destination is a symlink; refusing to write")
    if path.exists() and not path.is_file():
        raise ValueError("remediation artifact destination is not a regular file; refusing to write")

    if not path.exists():
        try:
            _publish_write_once(path, payload)
            return path
        except FileExistsError:
            # A concurrent writer won the race; fall through and reconcile.
            pass

    existing = RemediationArtifact.model_validate_json(path.read_text(encoding="utf-8"))
    if existing.artifact_sha256 == artifact.artifact_sha256:
        return path
    raise ValueError("refusing to overwrite an existing remediation artifact with different content")


def _publish_write_once(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` exactly once, never clobbering a file.

    A temp file is written in the destination directory and then linked into
    place: ``os.link`` fails with ``FileExistsError`` if the destination already
    exists, which makes publication atomic and non-destructive. On platforms or
    filesystems without hard links, an exclusive ``open(..., "x")`` provides the
    same no-overwrite guarantee.
    """
    fd, temp_name = tempfile.mkstemp(prefix=".arbalest-", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temp_path, path)
        except FileExistsError:
            raise
        except (AttributeError, NotImplementedError, OSError):
            with open(path, "x", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
    finally:
        temp_path.unlink(missing_ok=True)


def load_artifact(target: Path, reference: str | Path | None, finding_id: str) -> tuple[RemediationArtifact, Path]:
    root = target.resolve()
    directory = (root / ".arbalest" / "remediations").resolve()
    safe_finding = safe_finding_id(finding_id)
    if reference is None:
        matches = sorted(directory.glob(f"{safe_finding}-*.json"), key=lambda item: item.stat().st_mtime, reverse=True) if directory.is_dir() else []
        if not matches:
            raise FileNotFoundError(f"no remediation artifact found for {safe_finding}; run `arbalest fix` first")
        path = matches[0]
    else:
        raw = Path(reference)
        if raw.is_absolute():
            path = raw.resolve()
        elif len(str(reference)) == 24 and all(char in "0123456789abcdef" for char in str(reference)):
            matches = list(directory.glob(f"*-{reference}.json")) if directory.is_dir() else []
            if len(matches) != 1:
                raise FileNotFoundError(f"remediation artifact id {reference!s} was not found uniquely")
            path = matches[0].resolve()
        else:
            path = (root / raw).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("remediation artifact must be inside the target repository") from exc
    artifact = RemediationArtifact.model_validate_json(path.read_text(encoding="utf-8"))
    if safe_finding not in {artifact.finding.cwe, artifact.finding.finding_id}:
        raise ValueError("remediation artifact does not match the requested finding")
    return artifact, path


def verify_source_state(target: Path, artifact: RemediationArtifact) -> None:
    destinations = resolve_bundle_paths(target, artifact.source_hashes)
    stale: list[str] = []
    for relative, expected in artifact.source_hashes.items():
        path = destinations[relative]
        current = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
        if _sha256_text(current) != expected:
            stale.append(relative)
    if stale:
        raise ValueError(f"source changed after remediation generation: {', '.join(stale[:8])}")


def apply_artifact(target: Path, artifact: RemediationArtifact) -> None:
    """Apply exactly the bytes covered by a validated artifact."""
    atomic_apply_mapping(target, artifact.bundle.file_mapping())


def atomic_apply_mapping(target: Path, mapping: dict[str, str]) -> None:
    """Atomically replace each file and roll back every applied path on failure."""
    destinations = resolve_bundle_paths(target, mapping)
    originals: dict[str, bytes | None] = {}
    prepared: dict[str, Path] = {}
    applied: list[str] = []
    try:
        for relative, content in mapping.items():
            destination = destinations[relative]
            destination.parent.mkdir(parents=True, exist_ok=True)
            originals[relative] = destination.read_bytes() if destination.exists() else None
            fd, temp_name = tempfile.mkstemp(prefix=".arbalest-", suffix=".tmp", dir=destination.parent)
            temp_path = Path(temp_name)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            prepared[relative] = temp_path
        for relative, temp_path in prepared.items():
            os.replace(temp_path, destinations[relative])
            applied.append(relative)
    except Exception:
        for relative in reversed(applied):
            destination = destinations[relative]
            original = originals[relative]
            if original is None:
                destination.unlink(missing_ok=True)
            else:
                fd, temp_name = tempfile.mkstemp(prefix=".arbalest-rollback-", dir=destination.parent)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(original)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp_name, destination)
        raise
    finally:
        for temp_path in prepared.values():
            temp_path.unlink(missing_ok=True)


def _atomic_write_text(path: Path, content: str) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=".arbalest-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        Path(temp_name).unlink(missing_ok=True)


__all__ = [
    "RemediationArtifact", "apply_artifact", "atomic_apply_mapping", "create_artifact",
    "create_validated_artifact", "load_artifact", "save_artifact", "verify_source_state",
]
