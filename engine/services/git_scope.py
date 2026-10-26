"""Immutable Git revision and working-tree diff scope resolution."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from engine.services.source_collector import ReconReport

_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}~^:+-]{0,255}$")


class GitScopeError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class GitDiffScope:
    base_revision: str
    head_revision: str
    changed_files: tuple[str, ...]
    deleted_files: tuple[str, ...]
    renamed_files: tuple[tuple[str, str], ...]
    untracked_files: tuple[str, ...]


def resolve_git_diff(target: Path, base: str) -> GitDiffScope:
    root = target.resolve()
    git = shutil.which("git") or shutil.which("git.exe")
    if git is None:
        raise GitScopeError("Git executable is required for diff scans")
    if not _REF.fullmatch(base) or base.startswith("-"):
        raise GitScopeError("diff base must be a safe Git revision name")

    def run(*args: str, binary: bool = False):
        process = subprocess.run(
            [git, *args], cwd=root, capture_output=True, text=not binary, timeout=30,
        )
        if process.returncode != 0:
            detail = (process.stderr if isinstance(process.stderr, str) else process.stderr.decode(errors="replace"))
            raise GitScopeError(f"git {args[0]} failed: {detail.strip()[:300]}")
        return process.stdout

    top = str(run("rev-parse", "--show-toplevel")).strip()
    if Path(top).resolve() != root:
        raise GitScopeError("diff target must be a Git worktree root")
    base_revision = str(run("rev-parse", "--verify", f"{base}^{{commit}}")).strip()
    head_revision = str(run("rev-parse", "HEAD")).strip()
    raw = bytes(run("diff", "--name-status", "-z", "--find-renames", base_revision, "--", binary=True))
    tokens = raw.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    changed: set[str] = set()
    deleted: set[str] = set()
    renamed: list[tuple[str, str]] = []
    index = 0
    while index < len(tokens):
        status = tokens[index].decode("utf-8", errors="replace")
        index += 1
        if index >= len(tokens):
            raise GitScopeError("Git returned a truncated diff record")
        first = _safe_path(tokens[index].decode("utf-8", errors="replace"))
        index += 1
        if status.startswith(("R", "C")):
            if index >= len(tokens):
                raise GitScopeError("Git returned a truncated rename record")
            second = _safe_path(tokens[index].decode("utf-8", errors="replace"))
            index += 1
            renamed.append((first, second))
            changed.add(second)
            if status.startswith("R"):
                deleted.add(first)
        elif status.startswith("D"):
            deleted.add(first)
        else:
            changed.add(first)

    untracked_raw = bytes(run("ls-files", "--others", "--exclude-standard", "-z", binary=True))
    untracked = {_safe_path(item.decode("utf-8", errors="replace")) for item in untracked_raw.split(b"\0") if item}
    changed.update(untracked)
    return GitDiffScope(
        base_revision=base_revision,
        head_revision=head_revision,
        changed_files=tuple(sorted(changed)),
        deleted_files=tuple(sorted(deleted)),
        renamed_files=tuple(sorted(renamed)),
        untracked_files=tuple(sorted(untracked)),
    )


def scope_recon_to_diff(recon: ReconReport, scope: GitDiffScope) -> ReconReport:
    selected = {path: recon.files[path] for path in scope.changed_files if path in recon.files}
    omitted = sorted(set(scope.changed_files) - set(selected))
    notes = list(recon.coverage_notes)
    if omitted:
        notes.append(f"{len(omitted)} changed file(s) were outside supported source types or collection limits")
    language_counts: dict[str, int] = {}
    for path in selected:
        extension = Path(path).suffix.lower().lstrip(".") or "other"
        language = {"py": "python", "js": "javascript", "ts": "typescript", "jsx": "react", "tsx": "react", "rs": "rust", "rb": "ruby"}.get(extension, extension)
        language_counts[language] = language_counts.get(language, 0) + 1
    return replace(
        recon,
        files=selected,
        total_files=len(selected),
        language_counts=language_counts,
        manifests=[path for path in recon.manifests if path in selected],
        entrypoints=[path for path in recon.entrypoints if path in selected],
        sink_hits=0,
        collection_complete=recon.collection_complete and not omitted,
        coverage_notes=sorted(set(notes)),
        scope_kind="git_diff",
        base_revision=scope.base_revision,
        head_revision=scope.head_revision,
        changed_files=list(scope.changed_files),
        deleted_files=list(scope.deleted_files),
        renamed_files=[list(pair) for pair in scope.renamed_files],
    )


def _safe_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise GitScopeError(f"unsafe Git path in diff: {value!r}")
    return path.as_posix()


__all__ = ["GitDiffScope", "GitScopeError", "resolve_git_diff", "scope_recon_to_diff"]
