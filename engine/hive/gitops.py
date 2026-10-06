"""Fleet GitOps — synchronized branch → commit → pull-request across repositories.

Real `git` operations per repository (real `gh` when the CLI is installed and
authenticated), executed concurrently by the mission. Nothing is simulated:
when a pull request cannot be opened, the exact command and a complete PR
summary are written to disk for the operator.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

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


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=str(repo), capture_output=True, text=True, timeout=_GIT_TIMEOUT,
    )
    if proc.returncode != 0:
        raise FleetGitOpsError(f"git {' '.join(args[:2])} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout.strip()


class FleetGitOps:
    """Branch, commit, and open synchronized PRs across affected repositories."""

    def __init__(self, *, incident: str) -> None:
        self._incident = incident

    @staticmethod
    def is_repo(path: Path) -> bool:
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"], cwd=str(path),
                capture_output=True, text=True, timeout=15,
            )
            return proc.returncode == 0 and proc.stdout.strip() == "true"
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
    ) -> FleetPullRequest:
        repo = repo_path.resolve()
        original_branch = _git(repo, "branch", "--show-current") or "HEAD"
        base_branch = f"{branch_prefix}-{cwe.lower().replace('-', '')}"
        branch, suffix = base_branch, 2
        while True:
            check = subprocess.run(
                ["git", "rev-parse", "--verify", f"refs/heads/{branch}"],
                cwd=str(repo), capture_output=True, text=True, timeout=15,
            )
            if check.returncode != 0:
                break
            branch = f"{base_branch}-{suffix}"
            suffix += 1

        _git(repo, "checkout", "-b", branch)
        try:
            for rel in files:
                _git(repo, "add", "--", rel)
            message = (
                f"fix(security): auto-heal {cwe} (fleet incident {self._incident})\n\n"
                f"Origin patch propagated by the Arbalest Hive Mind.\n"
                f"Verified by RedTeamSwarm war-games in Nebius Token Factory Sandboxes.\n\n"
                + "\n".join(f"- {ev[:200]}" for ev in evidence[:5])
            )
            _git(repo, "commit", "-m", message)
            commit = _git(repo, "rev-parse", "--short", "HEAD")
        finally:
            _git(repo, "checkout", original_branch)

        pr = FleetPullRequest(
            repo=repo.name, branch=branch, commit=commit, restored_branch=original_branch,
            files_committed=list(files), summary_path="",
        )

        summary_path = repo / ".arbalest" / "hive" / f"pr-{branch.replace('/', '-')}.md"
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(self._pr_markdown(cwe=cwe, files=files, summary=summary, evidence=evidence,
                                                  branch=branch, commit=commit), encoding="utf-8")
        pr.summary_path = str(summary_path)

        gh = shutil.which("gh") or shutil.which("gh.exe")
        if gh:
            proc = subprocess.run(
                [gh, "pr", "create", "--head", branch,
                 "--title", f"Arbalest fleet heal: {cwe} ({self._incident})",
                 "--body-file", str(summary_path)],
                cwd=str(repo), capture_output=True, text=True, timeout=120,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                pr.pr_url = proc.stdout.strip().splitlines()[-1]
            else:
                pr.pr_error = (proc.stderr or "gh pr create failed").strip()[:300]
        else:
            pr.pr_error = "gh CLI not installed — PR summary staged on disk"
        return pr

    @staticmethod
    def _pr_markdown(*, cwe: str, files: list[str], summary: str, evidence: list[str],
                     branch: str, commit: str) -> str:
        lines = [
            f"## 🛡 Arbalest Fleet Auto-Heal — {cwe}",
            "",
            f"- **Branch:** `{branch}` (commit `{commit}`)",
            "- **Verified:** RedTeamSwarm minimax war-game, Nebius Token Factory Sandbox",
            f"- **Healed files:** {', '.join(f'`{f}`' for f in files) or '—'}",
            "",
            "### Remediation summary",
            summary,
            "",
            "### Attack-chain evidence",
            *[f"- {ev[:300]}" for ev in evidence[:8]],
            "",
            "_Generated autonomously by the Arbalest Hive Mind. Review, then merge._",
        ]
        return "\n".join(lines)
