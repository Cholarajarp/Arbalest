"""Scope-gated live probing (DAST seed): safe, read-only response checks.

This is the runtime-only complement to static scanning: response headers,
error verbosity and redirect behavior can only be observed on a running
service. Scope is enforced by the same defensive-only policy as the fuzzer:
targets must be explicitly allowlisted or local; checks are bounded GETs that
never mutate state. No model is involved — findings are deterministic
observations of the responses themselves.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

import httpx

from engine.agents.architect_agent import Severity, ThreatFinding
from engine.agents.black_box_fuzzer import FuzzingPolicy, ScopeViolation, _TargetScope

_PROBE_TIMEOUT = httpx.Timeout(10.0)
_MAX_REDIRECTS = 0
_STACK_TRACE = re.compile(
    r"Traceback \(most recent call last\)|at [A-Za-z0-9_$.]+\([A-Za-z0-9_$.]+\.java:\d+\)"
    r"|Exception in thread|System\.NullReferenceException|Fatal error: Uncaught",
    re.I,
)
_REDIRECT_TARGET = "arbo-probe.invalid/redirect-check"

# Benign, unmistakable markers. The XSS marker carries quoting characters so
# unescaped reflection is observable; the SQL marker triggers driver error
# pages without ever attempting an actual injection payload.
_XSS_MARKER = "arbo0xss\"'<()>"
_SQL_MARKER = "arbo0sql'"
_SQL_ERROR = re.compile(
    r"SQLITE_ERROR|syntax error at or near|You have an error in your SQL syntax"
    r"|MySQLSyntaxErrorException|psycopg2\.(errors\.)?ProgrammingError|unclosed quotation mark"
    r"|org\.postgresql\.util\.PSQLException|SQLSTATE\[",
    re.I,
)
_PROBE_PARAMS = ("q", "id", "search", "term", "url", "name", "callback", "redirect")


def _reflection_findings(response: httpx.Response, marker: str, param: str) -> list[ThreatFinding]:
    body = response.text or ""
    findings: list[ThreatFinding] = []
    if _SQL_ERROR.search(body):
        # Stronger signal first: error pages that echo the probe usually also
        # reflect it, but a live database error is the finding that matters.
        findings.append(_finding(
            "SQL error exposed through parameter", "CWE-89", Severity.HIGH,
            f"parameter '{param}' reaches a database query and error details are returned to the caller",
            [f"body matched database error signatures after ?{param}= probe"],
        ))
    elif marker in body:
        # Escaped output entitles the app to a pass: only the raw marker,
        # including its quotes/angle brackets, counts as unsafe reflection.
        findings.append(_finding(
            "Reflected input without escaping", "CWE-79", Severity.MEDIUM,
            f"a caller-controlled value in parameter '{param}' is reflected into the response unescaped",
            [f"reflected marker with quotes/brackets intact from ?{param}="],
        ))
    return findings


@dataclass(slots=True)
class ProbeResult:
    findings: list[ThreatFinding]
    url: str
    requests: int
    scope_note: str = ""


def _finding(name: str, cwe: str, severity: Severity, summary: str, evidence: list[str]) -> ThreatFinding:
    digest = hashlib.sha256(f"{cwe}|{name}|{summary}".encode()).hexdigest()[:16]
    return ThreatFinding(
        finding_id=f"PROBE-{digest}",
        cwe=cwe,
        severity=severity,
        summary=f"PROBE: {name} — {summary}",
        affected_nodes=[],
        evidence=evidence[:10],
    )


def _header_findings(response: httpx.Response, url: str) -> list[ThreatFinding]:
    findings: list[ThreatFinding] = []
    headers = {key.lower() for key in response.headers}
    missing = []
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        missing.append("clickjacking framing (X-Frame-Options / CSP frame-ancestors)")
    if "x-content-type-options" not in headers:
        missing.append("MIME sniffing (X-Content-Type-Options: nosniff)")
    if url.startswith("https") and "strict-transport-security" not in headers:
        missing.append("transport security (Strict-Transport-Security)")
    if missing:
        findings.append(_finding(
            "Missing security headers", "CWE-693", Severity.MEDIUM,
            "response is missing standard hardening headers",
            [f"missing: {item}" for item in missing],
        ))
    disclosures: list[str] = []
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = response.headers.get(header)
        if value and re.search(r"\d+\.\d+", value):
            disclosures.append(f"{header}: {value.strip()[:60]}")
    if disclosures:
        findings.append(_finding(
            "Version disclosure in response headers", "CWE-200", Severity.LOW,
            "server technology and version exposed to any caller",
            disclosures,
        ))
    return findings


async def run_probe(
    url: str, *, policy: FuzzingPolicy, client: httpx.AsyncClient | None = None,
) -> ProbeResult:
    """Run bounded read-only checks against one in-scope URL."""
    scope = await _TargetScope.create(url, policy)  # raises ScopeViolation when out of scope
    normalized = scope.base_url
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=_PROBE_TIMEOUT, follow_redirects=False)
    requests = 0
    try:
        findings: list[ThreatFinding] = []

        try:
            root = await client.get(url)
            requests += 1
        except httpx.HTTPError as exc:
            return ProbeResult([], url, requests, f"probe request failed: {type(exc).__name__}")
        findings.extend(_header_findings(root, url))

        try:
            missing = await client.get(f"{url.rstrip('/')}/arbalest-probe-{hashlib.sha256(url.encode()).hexdigest()[:8]}")
            requests += 1
            if _STACK_TRACE.search(missing.text or ""):
                findings.append(_finding(
                    "Verbose error response", "CWE-209", Severity.MEDIUM,
                    "error pages disclose stack traces or internals to any caller",
                    [f"status {missing.status_code}; body matched stack-trace signatures"],
                ))
        except httpx.HTTPError:
            pass

        try:
            redirect = await client.get(url, params={"next": f"//{_REDIRECT_TARGET}"})
            requests += 1
            location = redirect.headers.get("location", "")
            if 300 <= redirect.status_code < 400 and _REDIRECT_TARGET in location:
                findings.append(_finding(
                    "Open redirect", "CWE-601", Severity.HIGH,
                    "a caller-controlled parameter is reflected into the redirect target",
                    [f"status {redirect.status_code}; Location: {location[:120]}"],
                ))
        except httpx.HTTPError:
            pass

        # Response-evidence injection probes on common parameters: benign
        # markers only, read-only GETs; we judge by what the service echoes
        # back, never by attempting an actual exploit.
        for index, param in enumerate(_PROBE_PARAMS):
            if requests >= 12:  # bounded total request budget
                break
            marker = _XSS_MARKER if index % 2 == 0 else _SQL_MARKER
            try:
                probe = await client.get(url, params={param: marker})
                requests += 1
            except httpx.HTTPError:
                continue
            findings.extend(_reflection_findings(probe, marker, param))

        return ProbeResult(findings, normalized, requests)
    finally:
        if owns_client:
            await client.aclose()


__all__ = ["ProbeResult", "ScopeViolation", "run_probe"]
