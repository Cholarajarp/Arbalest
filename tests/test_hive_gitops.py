"""Fleet GitOps — real git operations across multiple repositories."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from engine.hive.gitops import FleetGitOps

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _make_repo(path: Path, filename: str, content: str) -> Path:
    path.mkdir(parents=True)
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "sentinel@arbalest.sh")
    _git(path, "config", "user.name", "Arbalest Fleet")
    (path / filename).write_text("original\n", encoding="utf-8")
    _git(path, "add", ".")
    _git(path, "commit", "-q", "-m", "baseline")
    return path


def test_synchronized_heal_across_two_repos(tmp_path: Path):
    gitops = FleetGitOps(incident="deadbeef")
    healed_content = "healed by the swarm\n"
    repos = {}
    for name in ("repo-a", "repo-b"):
        repo = _make_repo(tmp_path / name, "lib.py", "original\n")
        original_branch = _git(repo, "branch", "--show-current")
        repos[name] = (repo, original_branch)
        (repo / "lib.py").write_text(healed_content, encoding="utf-8")

    prs = [
        gitops.commit_heal(
            repo, cwe="CWE-78", files=["lib.py"],
            summary="Fleet auto-heal propagated by the Hive Mind.",
            evidence=["SENT-PY-008: os.system(cmd)"],
        )
        for repo, _branch in (repos["repo-a"], repos["repo-b"])
    ]

    for pr, (repo, original_branch) in zip(prs, repos.values()):
        assert pr.ok is True
        assert pr.branch.startswith("arbalest/hive-cwe78")
        assert len(pr.commit) == 7
        assert _git(repo, "branch", "--show-current") == original_branch, (
            "FleetGitOps must restore the developer's branch"
        )
        # The healed content lives on the fleet branch, not the developer's branch.
        assert "healed by the swarm" in _git(repo, "show", f"{pr.branch}:lib.py")
        assert Path(pr.summary_path).is_file()
        assert "Arbalest Fleet Auto-Heal — CWE-78" in Path(pr.summary_path).read_text(encoding="utf-8")


def test_branch_collision_gets_suffix(tmp_path: Path):
    repo = _make_repo(tmp_path / "repo", "lib.py", "original\n")
    gitops = FleetGitOps(incident="aaa")
    (repo / "lib.py").write_text("healed v1\n", encoding="utf-8")
    first = gitops.commit_heal(repo, cwe="CWE-89", files=["lib.py"], summary="s", evidence=[])
    _git(repo, "branch", "--show-current")  # back on baseline
    (repo / "lib.py").write_text("healed v2\n", encoding="utf-8")
    second = gitops.commit_heal(repo, cwe="CWE-89", files=["lib.py"], summary="s", evidence=[])
    assert first.branch != second.branch
    assert second.branch.startswith(first.branch + "-")


def test_non_repo_directory_is_detected(tmp_path: Path):
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    assert FleetGitOps.is_repo(plain) is False
