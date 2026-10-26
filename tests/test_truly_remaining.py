"""Truly-remaining builds: Go taint, CISA KEV lookup, outdated-line freshness."""

from __future__ import annotations

import httpx
import pytest

from engine.agents.architect_agent import Severity
from engine.services.runtime_versions import check_runtime_declarations, collect_runtime_declarations
from engine.services.taint_analysis import analyze_taint
from engine.services.taint_go import analyze_go_taint


# ── Go subset taint ──────────────────────────────────────────────────────────

def test_go_handler_shell_injection():
    result = analyze_go_taint({
        "handler.go": (
            "package main\n"
            "func runTool(w http.ResponseWriter, r *http.Request) {\n"
            "\ttool := r.FormValue(\"tool\")\n"
            "\tcmd := exec.Command(\"sh\", \"-c\", \"run \"+tool)\n"
            "\t_ = cmd\n"
            "}\n"
        ),
    })
    assert [f.cwe for f in result.findings] == ["CWE-78"]
    assert result.findings[0].finding_id.startswith("TAINT-GO-")


def test_go_sql_concat_and_sprintf():
    result = analyze_go_taint({
        "sql.go": (
            "package main\n"
            "func users(r *http.Request) {\n"
            "\tq := \"SELECT * FROM u WHERE n=\" + r.URL.Query().Get(\"n\")\n"
            "\tdb.Query(q)\n"
            "}\n"
        ),
        "sprintf.go": (
            "package main\n"
            "func list(r *http.Request) {\n"
            "\tq := fmt.Sprintf(\"SELECT * WHERE n=%s\", r.FormValue(\"n\"))\n"
            "\tdb.Query(q)\n"
            "}\n"
        ),
    })
    assert [f.cwe for f in result.findings] == ["CWE-89", "CWE-89"]


def test_go_safe_patterns_stay_silent():
    result = analyze_go_taint({
        "clean.go": (
            "package main\n"
            "func handler(r *http.Request) {\n"
            "\tid := r.URL.Query().Get(\"id\")\n"
            "\trows := db.Query(\"SELECT * FROM u WHERE id = ?\", id)\n"
            "\t_ = rows\n"
            "\trepo := r.FormValue(\"repo\")\n"
            "\texec.Command(\"git\", \"clone\", repo)\n"
            "}\n"
        ),
    })
    assert result.findings == []


def test_go_cross_function_flow():
    result = analyze_go_taint({
        "via.go": (
            "package main\n"
            "func launch(cmd string) { exec.Command(cmd) }\n"
            "func handler(r *http.Request) {\n"
            "\ttarget := r.FormValue(\"target\")\n"
            "\tlaunch(target)\n"
            "}\n"
        ),
    })
    assert [f.cwe for f in result.findings] == ["CWE-78"]


def test_dispatcher_routes_go_files():
    result = analyze_taint({
        "app.go": "package main\nfunc h(r *http.Request) {\n\tt := r.FormValue(\"t\")\n\texec.Command(t)\n}\n",
        "notes.txt": "text",
    })
    assert [f.cwe for f in result.findings] == ["CWE-78"]
    assert result.coverage.analyzed_paths == ["app.go"]
    assert result.coverage.unsupported_files == ["notes.txt"]
    assert result.coverage.complete
    assert "go" in result.coverage.as_dict()["supported_languages"]
    assert any(note["reason"] == "go_subset" for note in result.coverage.approximation_notes)


# ── Live intelligence: CISA KEV + outdated-line freshness ────────────────────

class _IntelClient:
    def __init__(self, *, cycles=None, kev=None):
        self._cycles = cycles or {}
        self._kev = kev

    async def get(self, url: str):
        if "known_exploited" in url:
            if self._kev is None:
                raise httpx.ConnectError("offline")
            class _KevResponse:
                status_code = 200

                def raise_for_status(self):
                    return None

                def json(self):
                    return self_payload

            self_payload = self._kev
            return _KevResponse()
        product = url.rsplit("/", 1)[-1].removesuffix(".json")
        payload = self._cycles.get(product)
        if payload is None:
            raise httpx.ConnectError("offline")

        class _Response:
            status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return payload

        return _Response()

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_kev_entry_demands_verification_without_version_claims():
    decls = collect_runtime_declarations({"Dockerfile": "FROM gitlab/gitlab-ce:19.5.1-ee.0\n"})
    client = _IntelClient(kev={
        "dateReleased": "2026-10-24T00:00:00.0000Z",
        "vulnerabilities": [
            {"vendor": "GitLab", "product": "GitLab", "cveID": "CVE-2026-85706"},
        ],
    })
    findings, info = await check_runtime_declarations(decls, client=client)
    kev = next(f for f in findings if f.finding_id == "RUNTIME-gitlab-kev")
    assert kev.severity == Severity.MEDIUM
    assert "feed dated 2026-10-24" in kev.summary
    assert "no version ranges" in kev.summary
    assert info["kev_checked"] is True


@pytest.mark.asyncio
async def test_outdated_within_release_line_is_low_severity():
    decls = collect_runtime_declarations({"Dockerfile": "FROM php:8.3.30-cli\n"})
    client = _IntelClient(cycles={
        "php": [{"cycle": "8.3", "eol": "2027-12-31", "latest": "8.3.36"}],
    })
    findings, info = await check_runtime_declarations(decls, client=client)
    outdated = next(f for f in findings if f.finding_id == "RUNTIME-php-outdated")
    assert outdated.severity == Severity.LOW
    assert "8.3.36" in outdated.summary
    assert info["eol_checked"] is True


@pytest.mark.asyncio
async def test_current_release_produces_no_freshness_noise():
    decls = collect_runtime_declarations({"Dockerfile": "FROM php:8.3.36-cli\n"})
    client = _IntelClient(cycles={
        "php": [{"cycle": "8.3", "eol": "2027-12-31", "latest": "8.3.36"}],
    })
    findings, _ = await check_runtime_declarations(decls, client=client)
    assert findings == []


@pytest.mark.asyncio
async def test_kev_offline_never_breaks_the_check():
    decls = collect_runtime_declarations({"Dockerfile": "FROM gitlab/gitlab-ce:19.4.0-ee.0\n"})
    client = _IntelClient()  # everything offline
    findings, info = await check_runtime_declarations(decls, client=client)
    # The offline emergency table still fires; KEV degrades silently.
    assert any(f.finding_id == "RUNTIME-gitlab-gitlab-october-2026" for f in findings)
    assert info.get("kev_checked") is False
