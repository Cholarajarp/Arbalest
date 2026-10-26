"""Declared-runtime awareness: inventory, offline emergency table, live EOL."""

from __future__ import annotations


import httpx
import pytest

from engine.agents.architect_agent import Severity
from engine.services.runtime_versions import (
    check_runtime_declarations,
    collect_runtime_declarations,
)


def test_dockerfile_from_lines_are_inventoried():
    decls = collect_runtime_declarations({
        "Dockerfile": (
            "# syntax=docker/dockerfile:1\n"
            "FROM php:8.3.4-cli AS base\n"
            "RUN docker-php-ext-install pdo\n"
            "FROM --platform=$BUILDPLATFORM node:22.0.0-alpine AS build\n"
            "FROM python:3.12-slim\n"
        ),
    })
    parsed = {(d.component, d.version) for d in decls}
    assert ("php", "8.3.4") in parsed
    assert ("nodejs", "22.0.0") in parsed
    assert ("python", "3.12") in parsed


def test_version_files_and_manifests_are_inventoried():
    decls = collect_runtime_declarations({
        ".nvmrc": "20.10.0\n",
        ".tool-versions": "ruby 3.0.2\nphp 8.1.0\n",
        "composer.json": '{"require": {"php": "^8.2.5"}}',
        "package.json": '{"engines": {"node": ">=22.0.0"}}',
        "Gemfile": 'source "https://rubygems.org"\nruby "3.1.0"\n',
        "go.mod": "module x\n\ngo 1.21.0\n",
    })
    parsed = {(d.component, d.version) for d in decls}
    assert ("nodejs", "20.10.0") in parsed
    assert ("ruby", "3.0.2") in parsed
    assert ("php", "8.1.0") in parsed
    assert ("php", "8.2.5") in parsed
    assert ("nodejs", "22.0.0") in parsed
    assert ("ruby", "3.1.0") in parsed
    assert ("go", "1.21.0") in parsed


def test_unrelated_images_and_junk_are_ignored():
    decls = collect_runtime_declarations({
        "Dockerfile": "FROM debian:bookworm-slim\nFROM mycustom/app:1.0\n",
        ".nvmrc": "node\n",
        "notes.txt": "php 8.3.4\n",
    })
    assert decls == []


@pytest.mark.asyncio
async def test_php2shell_emergency_table_flags_unpatched_php():
    decls = collect_runtime_declarations({"Dockerfile": "FROM php:8.3.4-cli\n"})
    findings, info = await check_runtime_declarations(decls, client=_offline_client())
    tags = {f.finding_id: f for f in findings}
    php2shell = tags["RUNTIME-php-php2shell"]
    assert php2shell.severity == Severity.CRITICAL
    assert php2shell.cwe == "CVE-2026-109618"
    assert "CVE-2026-109618" in php2shell.summary or "PHP 8.2" in php2shell.summary
    assert "Dockerfile:1" in php2shell.evidence[0]
    assert info["declarations"] == 1


@pytest.mark.asyncio
async def test_patched_php_is_not_flagged():
    decls = collect_runtime_declarations({"Dockerfile": "FROM php:8.4.27-cli\n"})
    findings, _ = await check_runtime_declarations(decls, client=_offline_client())
    assert findings == []


@pytest.mark.asyncio
async def test_unknown_floor_line_reports_verify_finding():
    decls = collect_runtime_declarations({"composer.json": '{"require": {"php": "^8.2.5"}}'})
    findings, _ = await check_runtime_declarations(decls, client=_offline_client())
    php2shell = next(f for f in findings if f.finding_id == "RUNTIME-php-php2shell")
    assert php2shell.severity == Severity.MEDIUM
    assert "8.2: see vendor advisory" in php2shell.summary


@pytest.mark.asyncio
async def test_nodejs_october_2026_release_note():
    decls = collect_runtime_declarations({"Dockerfile": "FROM node:22.0.0-alpine\n"})
    findings, _ = await check_runtime_declarations(decls, client=_offline_client())
    node = next(f for f in findings if f.finding_id == "RUNTIME-nodejs-nodejs-october-2026")
    assert node.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_eol_data_flags_dead_lines():
    decls = collect_runtime_declarations({"Dockerfile": "FROM php:8.1.20-cli\n"})
    findings, info = await check_runtime_declarations(decls, client=_eol_client({
        "php": [{"cycle": "8.1", "eol": "2025-12-31", "latest": "8.1.31"}],
    }))
    eol = next(f for f in findings if f.finding_id == "RUNTIME-php-eol")
    assert eol.severity == Severity.HIGH
    assert "end-of-life" in eol.summary
    assert info["eol_checked"] is True


@pytest.mark.asyncio
async def test_eol_service_failure_is_failure_tolerant():
    decls = collect_runtime_declarations({"Dockerfile": "FROM php:8.3.36-cli\n"})
    findings, info = await check_runtime_declarations(decls, client=_failing_client())
    assert findings == []
    assert info["eol_checked"] is False
    assert "unreachable" in info["note"]


class _FakeResponse:
    def __init__(self, payload: list | dict, status: int = 200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=None)

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, routes: dict[str, object]):
        self._routes = routes

    async def get(self, url: str):
        product = url.rsplit("/", 1)[-1].removesuffix(".json")
        payload = self._routes.get(product, [])
        if isinstance(payload, Exception):
            raise payload
        return _FakeResponse(payload)

    async def aclose(self):
        return None


def _offline_client() -> _FakeClient:
    # Every product request fails: only the offline emergency table applies.
    return _FakeClient({name: httpx.ConnectError("offline") for name in ("php", "nodejs", "gitlab", "ubuntu")})


def _eol_client(routes: dict[str, list | dict]) -> _FakeClient:
    return _FakeClient(routes)


def _failing_client() -> _FakeClient:
    return _offline_client()


# ── Declared infrastructure (self-hosted GitLab, distro and service images) ──

def test_infrastructure_images_are_inventoried():
    decls = collect_runtime_declarations({
        "Dockerfile": (
            "FROM gitlab/gitlab-ce:19.4.0-ee.0 AS gitlab\n"
            "FROM ubuntu:20.04\n"
            "FROM nginx:1.18.0-alpine\n"
        ),
    })
    parsed = {(d.component, d.version) for d in decls}
    assert ("gitlab", "19.4.0") in parsed
    assert ("ubuntu", "20.04") in parsed
    assert ("nginx", "1.18.0") in parsed


@pytest.mark.asyncio
async def test_gitlab_october_2026_unpatched_line_is_critical():
    decls = collect_runtime_declarations({"Dockerfile": "FROM gitlab/gitlab-ce:19.4.0-ee.0\n"})
    findings, _ = await check_runtime_declarations(decls, client=_offline_client())
    gitlab = next(f for f in findings if f.finding_id == "RUNTIME-gitlab-gitlab-october-2026")
    assert gitlab.severity == Severity.CRITICAL
    assert gitlab.cwe == "CVE-2026-110264"
    assert "19.4≥19.4.3" in gitlab.summary


@pytest.mark.asyncio
async def test_gitlab_versions_below_every_patched_line_are_affected():
    decls = collect_runtime_declarations({"Dockerfile": "FROM gitlab/gitlab-ee:18.2.1-ee.0\n"})
    findings, _ = await check_runtime_declarations(decls, client=_offline_client())
    gitlab = next(f for f in findings if f.finding_id == "RUNTIME-gitlab-gitlab-october-2026")
    assert gitlab.severity == Severity.CRITICAL
    assert "18.2: upgrade to ≥19.5.1" in gitlab.summary


@pytest.mark.asyncio
async def test_patched_gitlab_is_not_flagged():
    decls = collect_runtime_declarations({"Dockerfile": "FROM gitlab/gitlab-ce:19.5.1-ee.0\n"})
    findings, _ = await check_runtime_declarations(decls, client=_offline_client())
    assert findings == []


@pytest.mark.asyncio
async def test_eol_lookup_falls_back_to_major_cycle():
    decls = collect_runtime_declarations({"Dockerfile": "FROM nginx:1.18.0-alpine\n"})
    findings, info = await check_runtime_declarations(decls, client=_eol_client({
        # nginx cycles on endoflife.date are majors: "1" is EOL, "1.18" absent.
        "nginx": [{"cycle": "1", "eol": "2024-05-01", "latest": "1.26"}],
    }))
    eol = next(f for f in findings if f.finding_id == "RUNTIME-nginx-eol")
    assert eol.severity == Severity.HIGH
    assert info["eol_checked"] is True


@pytest.mark.asyncio
async def test_sca_agent_reports_runtime_findings_without_manifests():

    from engine.agents.sca_agent import ScaAgent

    agent = ScaAgent(client=_offline_httpx_stub())
    findings = await agent.analyze({"Dockerfile": "FROM php:8.3.4-cli\n"})
    assert any(f.finding_id == "RUNTIME-php-php2shell" for f in findings)
    assert agent.coverage.runtime_declarations == 1
    assert agent.coverage.complete  # runtime data is informational, never a coverage failure
    await agent.aclose()


def _offline_httpx_stub():
    class _StubClient:
        async def post(self, url, json=None):
            raise AssertionError("OSV must not be called when no dependencies exist")

        async def get(self, url):
            raise httpx.ConnectError("offline")

        async def aclose(self):
            return None

    return _StubClient()
