#!/usr/bin/env python3
"""Offline release metadata/policy checks; does not build, publish, or verify signatures.

Signature verification is performed by Cosign in release.yml, not by this script.
Python 3.12+ is required; --check-files also uses the project's PyYAML dependency.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
ACTION = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}")


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalized_requirement(requirement: str) -> str:
    name, separator, version = requirement.partition("==")
    require(separator and version, f"Release dependencies must be exactly pinned: {requirement}")
    return re.sub(r"[-_.]+", "-", name).lower() + separator + version


def release_version(root: Path, tag: str | None = None) -> str:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    require(VERSION.fullmatch(version), "Releases require a stable MAJOR.MINOR.PATCH project version")
    require(
        project["requires-python"] == ">=3.12", "Review the Python 3.12 release runtime before changing Python support"
    )
    lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    packages = [package for package in lock["package"] if package["name"] == project["name"]]
    require(len(packages) == 1, "uv.lock must contain exactly one project package")
    package = packages[0]
    require(package["version"] == version, "uv.lock project version does not match pyproject.toml")
    require(package["source"] == {"editable": "."}, "uv.lock must lock the local project")
    locked_dependencies = {
        normalized_requirement(dependency["name"] + dependency["specifier"])
        for dependency in package["metadata"]["requires-dist"]
    }
    require(
        locked_dependencies == {normalized_requirement(value) for value in project["dependencies"]},
        "uv.lock direct dependencies differ from pyproject.toml",
    )
    if tag is not None:
        require(tag == f"v{version}", f"Release tag must be v{version}, got {tag!r}")
    return version


def check_sdk_steps(job: dict, label: str) -> None:
    steps = job["steps"]
    setup = [step for step in steps if step.get("uses", "").startswith("actions/setup-node@")]
    require(len(setup) == 1, f"{label}: SDK checks require one pinned Node setup step")
    require(ACTION.fullmatch(setup[0]["uses"]), f"{label}: Node setup must use a full commit")
    require(setup[0]["with"]["node-version"] == "22", f"{label}: SDK checks must use Node 22")
    require(
        setup[0]["with"].get("cache-dependency-path") == "sdk/typescript/package-lock.json",
        f"{label}: Node cache must use the SDK lockfile",
    )
    require("registry-url" not in setup[0]["with"], f"{label}: SDK checks must not configure registry authentication")
    npm_steps = [step for step in steps if step.get("run", "").startswith("npm ")]
    require(
        [step["run"] for step in npm_steps] == ["npm ci --no-audit --no-fund", "npm test", "npm pack --dry-run"],
        f"{label}: SDK gates must install the lock, compile/test, then check packaging without publishing",
    )
    require(
        all(step.get("working-directory") == "sdk/typescript" for step in npm_steps),
        f"{label}: SDK commands must run in sdk/typescript",
    )
    require(steps.index(setup[0]) < steps.index(npm_steps[0]), f"{label}: Set up Node before running npm")


def check_files(root: Path) -> int:
    import yaml

    # BaseLoader preserves GitHub's `on` key rather than interpreting it as a YAML 1.1 boolean.
    workflow = yaml.load((root / ".github/workflows/release.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    require(
        set(workflow["on"]) == {"push", "workflow_dispatch"}, "Only version-tag pushes and manual releases are allowed"
    )
    require(workflow["on"]["push"]["tags"] == ["v*"], "Push releases must be version-tag gated")
    require(workflow["permissions"] == {"contents": "read"}, "Workflow permissions must default to contents: read")
    jobs = workflow["jobs"]
    require(jobs["tests"]["needs"] == "validate", "Tests must follow version validation")
    require(set(jobs["publish"]["needs"]) == {"validate", "tests"}, "Publishing must require validation and tests")
    require("if" not in jobs["publish"], "Do not override the publish job's default success gate")
    require(
        jobs["publish"]["permissions"]
        == {
            "contents": "read",
            "packages": "write",
            "id-token": "write",
        },
        "Publish permissions must be limited to reading source, GHCR and OIDC",
    )
    count = 0
    for name, job in jobs.items():
        require("timeout-minutes" in job, f"{name}: missing timeout")
        if name != "publish":
            require("permissions" not in job, f"{name}: must inherit read-only permissions")
        for step in job["steps"]:
            if "uses" not in step:
                continue
            count += 1
            require(ACTION.fullmatch(step["uses"]), f"Action must be pinned to a full commit: {step['uses']}")
            if step["uses"].startswith("actions/checkout@"):
                require(
                    step.get("with", {}).get("persist-credentials") == "false", "Checkout must not persist credentials"
                )
    build = [step for step in jobs["publish"]["steps"] if step.get("id") == "build"]
    require(len(build) == 1, "Expected one image build")
    settings = build[0]["with"]
    require(settings["platforms"] == "linux/amd64,linux/arm64", "Both release platforms are required")
    require(settings["push"] == "true", "Release build must publish")
    require(
        settings["sbom"] == "true" and settings["provenance"] == "mode=max", "Build must include SBOM and provenance"
    )
    require(
        not ({"build-args", "secrets", "secret-envs", "secret-files", "ssh"} & settings.keys()),
        "Do not pass application credentials into the release build",
    )
    test_commands = "\n".join(step.get("run", "") for step in jobs["tests"]["steps"])
    require("uv sync --locked --group dev" in test_commands, "Tests must check and install the lock")
    require("uv run --frozen pytest -q" in test_commands, "Release tests must run pytest")
    check_sdk_steps(jobs["tests"], "Release tests")
    ci = yaml.load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    require(ci["permissions"] == {"contents": "read"}, "CI must default to contents: read")
    sdk_job = ci["jobs"]["typescript-sdk"]
    require("permissions" not in sdk_job, "SDK CI must inherit read-only permissions")
    require("timeout-minutes" in sdk_job, "SDK CI requires a timeout")
    check_sdk_steps(sdk_job, "SDK CI")
    for step in sdk_job["steps"]:
        if "uses" in step:
            require(ACTION.fullmatch(step["uses"]), f"SDK CI action must use a full commit: {step['uses']}")
            if step["uses"].startswith("actions/checkout@"):
                require(
                    step.get("with", {}).get("persist-credentials") == "false",
                    "SDK CI checkout must not persist credentials",
                )

    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    require(
        re.search(r"^FROM python:3\.12-slim-bookworm@sha256:[0-9a-f]{64} AS base$", dockerfile, re.M),
        "Python 3.12 base must be digest pinned",
    )
    require(
        "uv sync --locked --no-dev --no-editable" in dockerfile,
        "Runtime dependencies must be locked, noneditable and production-only",
    )
    require(
        re.findall(r"^USER (.+)$", dockerfile, re.M) == ["10001:10001"], "Runtime must use the unprivileged UID/GID"
    )
    require(
        not re.search(r"^(?:ADD|VOLUME|ARG)\b|docker\.sock", dockerfile, re.M | re.I),
        "Do not add remote content, credential build args or implicit socket volumes",
    )
    require(not re.search(r"^COPY\s+\.\s", dockerfile, re.M), "Do not copy the entire build context")
    ignore = [
        line.strip()
        for line in (root / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    require(ignore[0] == "**", "Docker context must deny files by default")
    allowed = {
        "!Dockerfile",
        "!.dockerignore",
        "!pyproject.toml",
        "!uv.lock",
        "!README.md",
        "!LICENSE",
        "!arbalest_cli.py",
        "!mcp_server.py",
        "!engine/",
        "!engine/**/",
        "!engine/**/*.py",
    }
    require(
        {line for line in ignore if line.startswith("!")} == allowed, "Review changes to the Docker context allowlist"
    )
    require(
        {"**/.env", "**/.env.*", "**/.git", "**/.venv", "**/*.pem", "**/*.key"} <= set(ignore),
        "Docker context must exclude credentials and local state",
    )
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="Require an exact vMAJOR.MINOR.PATCH match to pyproject.toml and uv.lock")
    parser.add_argument(
        "--github-output", action="store_true", help="Validate GitHub event/ref and emit version/image job outputs"
    )
    parser.add_argument(
        "--check-files", action="store_true", help="Check local release workflow/container policy (requires PyYAML)"
    )
    args = parser.parse_args()
    try:
        version = release_version(ROOT, args.tag)
        if args.check_files:
            count = check_files(ROOT)
            print(f"Release file policy OK ({count} full-commit action references; offline, existence not checked)")
        if args.github_output:
            require(args.tag is not None, "--github-output requires --tag")
            require(os.environ.get("GITHUB_EVENT_NAME") in {"push", "workflow_dispatch"}, "Unsupported release event")
            require(
                os.environ.get("GITHUB_REF") == f"refs/tags/{args.tag}",
                "Select the matching version tag as the workflow ref; branch releases are forbidden",
            )
            repository = os.environ.get("GITHUB_REPOSITORY", "")
            require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "Invalid GITHUB_REPOSITORY")
            output = os.environ.get("GITHUB_OUTPUT")
            if not output:
                raise ValueError("GITHUB_OUTPUT is required")
            with Path(output).open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(f"version={version}\nimage=ghcr.io/{repository.lower()}\n")
        print(f"Release metadata OK: v{version}")
    except (ValueError, KeyError, OSError, ImportError, TypeError, IndexError) as exc:
        print(f"Release validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
