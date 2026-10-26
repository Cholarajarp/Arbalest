"""Isolated branch, commit, push, and pull-request operations for verified fixes."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping

_GIT_TIMEOUT = 60


@dataclass
class FleetPullRequest:
    repo: str
    branch: str
    commit: str
    restored_branch: str
    files_committed: list[str]
    summary_path: str
    pr_url: str = ""
    pr_error: str = ""
    ok: bool = True
    detail: str = ""


class FleetGitOpsError(RuntimeError):
    pass


def _git(repo: Path, *args: str, timeout: int = _GIT_TIMEOUT) -> str:
    proc = subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "git command failed").replace("\n", " ")[:300]
        raise FleetGitOpsError(f"git {args[0] if args else 'operation'} failed: {message}")
    return proc.stdout.strip()


def _safe_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ":" in normalized or any(part in {"", ".", ".."} for part in path.parts):
        raise FleetGitOpsError(f"unsafe repository-relative path: {value!r}")
    return path.as_posix()


class FleetGitOps:
    """Create commits in temporary Git worktrees without touching operator state."""

    def __init__(self, *, incident: str) -> None:
        self._incident = re.sub(r"[^A-Za-z0-9_-]", "", incident)[:64] or "incident"

    @staticmethod
    def is_repo(path: Path) -> bool:
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"], cwd=str(path), capture_output=True, text=True, timeout=15,
            )
            return proc.returncode == 0 and Path(proc.stdout.strip()).resolve() == path.resolve()
        except (OSError, subprocess.TimeoutExpired):
            return False

    def commit_heal(
        self,
        repo_path: Path,
        *,
        cwe: str,
        files: list[str],
        summary: str,
        evidence: list[str],
        branch_prefix: str = "arbalest/hive",
        content_by_path: Mapping[str, str | bytes] | None = None,
    ) -> FleetPullRequest:
        repo = repo_path.resolve()
        if not self.is_repo(repo):
            raise FleetGitOpsError(f"not a Git worktree root: {repo}")
        requested = list(dict.fromkeys(_safe_path(item) for item in files))
        if not requested:
            raise FleetGitOpsError("no verified files were supplied")

        exact_content: dict[str, bytes] = {}
        if content_by_path is None:
            for relative in requested:
                source = (repo / relative).resolve()
                try:
                    source.relative_to(repo)
                except ValueError as exc:
                    raise FleetGitOpsError(f"path escapes repository: {relative}") from exc
                if not source.is_file():
                    raise FleetGitOpsError(f"verified file does not exist: {relative}")
                exact_content[relative] = source.read_bytes()
        else:
            if set(content_by_path) != set(requested):
                raise FleetGitOpsError("exact content keys must match requested files")
            for relative in requested:
                value = content_by_path[relative]
                exact_content[relative] = value if isinstance(value, bytes) else value.encode("utf-8")

        original_branch = _git(repo, "branch", "--show-current") or "HEAD"
        base = f"{branch_prefix}-{cwe.lower().replace('-', '')}"
        branch, suffix = base, 2
        while subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"], cwd=repo, timeout=15,
        ).returncode == 0:
            branch = f"{base}-{suffix}"
            suffix += 1

        worktree = Path(tempfile.mkdtemp(prefix="arbalest-gitops-"))
        commit = ""
        changed: list[str] = []
        try:
            _git(repo, "worktree", "add", "--quiet", "-b", branch, str(worktree), "HEAD")
            for relative, content in exact_content.items():
                destination = worktree.joinpath(*PurePosixPath(relative).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                mode_output = _git(worktree, "ls-files", "-s", "--", relative)
                mode = mode_output.split(None, 1)[0] if mode_output else "100644"
                blob_process = subprocess.run(
                    ["git", "hash-object", "-w", "--stdin"], cwd=worktree,
                    input=content, capture_output=True, timeout=30,
                )
                if blob_process.returncode != 0:
                    raise FleetGitOpsError(f"could not store verified blob for {relative}")
                blob = blob_process.stdout.decode("ascii", errors="strict").strip()
                _git(worktree, "update-index", "--add", "--cacheinfo", f"{mode},{blob},{relative}")
            changed = [line for line in _git(worktree, "diff", "--cached", "--name-only", "--").splitlines() if line]
            unexpected = set(changed) - set(requested)
            if unexpected:
                raise FleetGitOpsError(f"isolated commit contains unexpected paths: {sorted(unexpected)}")
            if not changed:
                raise FleetGitOpsError("verified content is identical to HEAD; no commit created")
            message = (
                f"fix(security): auto-heal {cwe} (fleet incident {self._incident})\n\n"
                "Verified in an isolated Arbalest sandbox.\n\n"
                + "\n".join(f"- {item[:200]}" for item in evidence[:5])
            )
            _git(worktree, "commit", "-m", message)
            commit = _git(worktree, "rev-parse", "--short", "HEAD")
            committed = set(_git(worktree, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").splitlines())
            if committed != set(changed):
                raise FleetGitOpsError("commit tree did not match the staged verified paths")
            for relative in changed:
                blob_read = subprocess.run(
                    ["git", "show", f"HEAD:{relative}"], cwd=worktree, capture_output=True, timeout=30,
                )
                if blob_read.returncode != 0 or blob_read.stdout != exact_content[relative]:
                    raise FleetGitOpsError(f"committed blob differs from verified bytes: {relative}")
        finally:
            with _suppress_git_errors():
                _git(repo, "worktree", "remove", "--force", str(worktree))
            shutil.rmtree(worktree, ignore_errors=True)

        summary_path = repo / ".arbalest" / "hive" / f"pr-{branch.replace('/', '-')}.md"
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(
            self._pr_markdown(cwe=cwe, files=changed, summary=summary, evidence=evidence, branch=branch, commit=commit),
            encoding="utf-8",
        )
        result = FleetPullRequest(
            repo=repo.name, branch=branch, commit=commit, restored_branch=original_branch,
            files_committed=changed, summary_path=str(summary_path),
        )

        gh = shutil.which("gh") or shutil.which("gh.exe")
        remotes = _git(repo, "remote").splitlines()
        if "origin" not in remotes:
            result.pr_error = "no origin remote; verified branch remains local"
            return result
        try:
            _git(repo, "push", "-u", "origin", branch, timeout=120)
        except FleetGitOpsError as exc:
            result.pr_error = str(exc)
            return result
        if gh is None:
            result.pr_error = "gh CLI unavailable; branch was pushed and PR summary is on disk"
            return result
        proc = subprocess.run(
            [gh, "pr", "create", "--head", branch, "--title", f"Arbalest security fix: {cwe} ({self._incident})",
             "--body-file", str(summary_path)],
            cwd=repo, capture_output=True, text=True, timeout=120,
            env={**os.environ, "GH_PROMPT_DISABLED": "1"},
        )
        if proc.returncode == 0 and proc.stdout.strip():
            result.pr_url = proc.stdout.strip().splitlines()[-1]
        else:
            result.pr_error = (proc.stderr or "gh pr create failed").replace("\n", " ")[:300]
        return result

    @staticmethod
    def _pr_markdown(*, cwe: str, files: list[str], summary: str, evidence: list[str], branch: str, commit: str) -> str:
        return "\n".join([
            f"## Arbalest Fleet Auto-Heal — {cwe}", "", f"- **Branch:** `{branch}` (commit `{commit}`)",
            "- **Verification:** isolated adversarial sandbox", f"- **Files:** {', '.join(f'`{item}`' for item in files) or '—'}",
            "", "### Summary", summary[:2000], "", "### Evidence", *[f"- {item[:300]}" for item in evidence[:8]],
            "", "_Review the exact verified bytes before merging._",
        ])


class _suppress_git_errors:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return True
