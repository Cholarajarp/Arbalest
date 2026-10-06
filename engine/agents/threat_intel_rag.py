"""Provider-neutral, retrieval-grounded threat-intelligence analysis."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from engine.agents.architect_agent import ArchitectureGraphContext, ThreatFinding
from engine.agents.black_box_fuzzer import RouteDiscovery
from engine.services.ai_provider import AIProvider, AIProviderError, StructuredOutputRequest
from engine.services.tavily_intel import TavilyIntelClient, enrich_retrieved_intel
from engine.services.vector_memory import vector_memory

logger = logging.getLogger(__name__)
_CWE = re.compile(r"^CWE-[1-9][0-9]{0,5}$", re.IGNORECASE)


class ThreatIntelError(RuntimeError):
    """Threat findings were malformed or exceeded the retrieved evidence."""


@dataclass(frozen=True, slots=True)
class ThreatIntelDocument:
    """Small local knowledge record that can be replaced by a vector store later."""

    cwe: str
    title: str
    keywords: tuple[str, ...]
    summary: str
    verification: str
    asi_code: str | None = None


_KNOWLEDGE_BASE: tuple[ThreatIntelDocument, ...] = (
    ThreatIntelDocument(
        "CWE-89",
        "SQL Injection",
        ("sql", "query", "search", "order", "report", "database", "db"),
        "Request values must not be concatenated into SQL or passed as query syntax.",
        "Use only where route or graph metadata establishes a database/query boundary; recommend parameterization.",
        "ASI02", # Agentic Data Poisoning / Data Leakage
    ),
    ThreatIntelDocument(
        "CWE-798",
        "Use of Hard-coded Credentials",
        ("secret", "token", "key", "credential", "auth", "config", "login"),
        "Secrets embedded in source are hard to rotate and can leak through artifacts or source control.",
        "Do not infer hard-coded secrets from a path alone; require explicit graph evidence.",
        "ASI10",  # Sensitive Information Disclosure
    ),
    ThreatIntelDocument(
        "CWE-862",
        "Missing Authorization",
        ("admin", "account", "order", "profile", "user", "payment", "internal", "auth"),
        "Sensitive operations require server-side authorization tied to the authenticated principal.",
        "An unauthenticated successful response is potential evidence, not proof of data exposure.",
        "ASI03",  # Identity & Privilege Abuse
    ),
    ThreatIntelDocument(
        "CWE-639",
        "Authorization Bypass Through User-Controlled Key",
        ("id", "order", "account", "profile", "user", "resource", "invoice"),
        "User-provided object identifiers must be scoped to the caller before resources are returned or modified.",
        "Use only for object-id routes when authorization evidence is missing or negative.",
        "ASI03",  # Identity & Privilege Abuse
    ),
    ThreatIntelDocument(
        "CWE-20",
        "Improper Input Validation",
        ("upload", "search", "filter", "redirect", "callback", "query", "input", "payload"),
        "Untrusted request values need type, length, and semantic validation before downstream use.",
        "Report as a potential only when a discovered route accepts relevant untrusted input.",
        "ASI01",  # Prompt Injection / Input Manipulation
    ),
    # ── DAST-specific CWEs from real HTTP response analysis ──
    ThreatIntelDocument(
        "CWE-693",
        "Missing Security Headers (Protection Mechanism Failure)",
        ("strict-transport-security", "content-security-policy", "x-content-type-options",
         "missing", "header", "hsts", "csp", "security"),
        "The server does not set essential HTTP security headers such as HSTS, CSP, X-Content-Type-Options, "
        "or X-Frame-Options, leaving clients vulnerable to protocol downgrade, XSS, MIME sniffing, and clickjacking.",
        "Report when scan_notes or route discovery confirms specific security headers are missing from HTTP responses.",
        "ASI05",  # Insecure Plugin/Tool Design
    ),
    ThreatIntelDocument(
        "CWE-200",
        "Exposure of Sensitive Information (Information Disclosure)",
        ("server", "x-powered-by", "version", "stack", "trace", "debug", "error", "internal", "disclosure"),
        "Server or X-Powered-By headers, verbose error messages, or debug endpoints expose technology stack "
        "details that attackers use for targeted exploitation.",
        "Report when HTTP responses include Server/X-Powered-By version strings or verbose error details.",
        "ASI10",  # Sensitive Information Disclosure
    ),
    ThreatIntelDocument(
        "CWE-1295",
        "Exposed Debug or API Documentation Endpoint",
        ("docs", "swagger", "openapi", "graphql", "playground", "debug", "actuator", "phpinfo"),
        "Publicly accessible API documentation, debug, or introspection endpoints expose internal route "
        "structure, parameter schemas, and authentication mechanisms to unauthorized parties.",
        "Report when unauthenticated access to /docs, /swagger, /openapi.json, or similar endpoints returns 200 OK.",
        "ASI10",  # Sensitive Information Disclosure
    ),
    ThreatIntelDocument(
        "CWE-942",
        "Overly Permissive Cross-domain Policy (CORS Misconfiguration)",
        ("access-control-allow-origin", "cors", "wildcard", "origin", "cross-domain"),
        "An Access-Control-Allow-Origin: * header or overly permissive CORS policy allows any website "
        "to make authenticated cross-origin requests, enabling data theft via the victim's browser.",
        "Report when Access-Control-Allow-Origin is set to * or reflects arbitrary origins.",
        "ASI05",  # Insecure Plugin/Tool Design
    ),
    ThreatIntelDocument(
        "CWE-1021",
        "Improper Restriction of Rendered UI Layers (Clickjacking)",
        ("x-frame-options", "frame", "iframe", "clickjack", "ui-redress"),
        "Missing X-Frame-Options or frame-ancestors CSP directive allows the page to be embedded in an "
        "attacker-controlled iframe for clickjacking attacks.",
        "Report when X-Frame-Options header is absent and no frame-ancestors CSP directive is present.",
        "ASI05",  # Insecure Plugin/Tool Design
    ),
)


class ThreatIntelReport(BaseModel):
    """Strict response schema for an evidence-bound collection of findings."""

    model_config = ConfigDict(extra="forbid")

    findings: list[ThreatFinding] = Field(max_length=100)

    @model_validator(mode="after")
    def unique_ids(self) -> "ThreatIntelReport":
        ids = [finding.finding_id for finding in self.findings]
        if len(ids) != len(set(ids)):
            raise ValueError("finding_id values must be unique")
        return self


class ThreatIntelRAG:
    """Implements the orchestrator's ``ThreatIntelAnalyzer`` protocol."""

    def __init__(self, *, provider: AIProvider, tavily: TavilyIntelClient | None = None) -> None:
        self._provider = provider
        self._tavily = tavily

    async def aclose(self) -> None:
        """Compatibility no-op; the application owns the injected provider."""

    async def analyze(
        self,
        *,
        discovery: RouteDiscovery,
        graph_context: ArchitectureGraphContext,
        legacy_sources: Mapping[str, str] | None = None,
    ) -> list[ThreatFinding]:
        """Return retrieved-CWE findings from route discovery and source code analysis."""
        if not discovery.routes and not legacy_sources:
            return []
        if not graph_context.nodes and not legacy_sources:
            logger.warning("Threat analysis received an empty architecture graph and no sources; returning empty findings")
            return []

        retrieved = await _retrieve(discovery, graph_context, legacy_sources)
        retrieved = await enrich_retrieved_intel(retrieved, self._tavily)
        format_spec = _report_format()["format"]
        payload: dict[str, Any] = {
            "route_discovery": discovery.model_dump(mode="json"),
            "architecture_graph": graph_context.model_dump(mode="json"),
            "retrieved_threat_intel": [
                {
                    "cwe": item.cwe,
                    "title": item.title,
                    "summary": item.summary,
                    "verification_guidance": item.verification,
                }
                for item in retrieved
            ],
        }
        if legacy_sources:
            # Include bounded source code so the AI can see actual vulnerabilities
            bounded_sources: dict[str, str] = {}
            total = 0
            for path, content in legacy_sources.items():
                truncated = content[:32_000]
                total += len(truncated)
                if total > 96_000:
                    break
                bounded_sources[path] = truncated
            payload["legacy_source_code"] = bounded_sources
        try:
            raw = await self._provider.generate_structured(
                StructuredOutputRequest(
                    instructions=_instructions(),
                    input_text=json.dumps(payload, separators=(",", ":")),
                    schema_name=str(format_spec["name"]),
                    json_schema=dict(format_spec["schema"]),
                    max_output_tokens=8_000,
                )
            )
        except AIProviderError as exc:
            raise ThreatIntelError("AI provider threat analysis request failed") from exc
        report = await self._parse(raw, format_spec)
        _validate_report(report, graph_context, retrieved)
        logger.info("Threat Intel analysis completed", extra={"findings": len(report.findings)})
        return report.findings

    async def _parse(self, raw: str, format_spec: dict[str, Any]) -> ThreatIntelReport:
        try:
            return ThreatIntelReport.model_validate_json(raw)
        except ValidationError:
            try:
                repaired = await self._provider.generate_structured(
                    StructuredOutputRequest(
                        instructions=(
                            "Return exactly one valid threat-intel-report JSON object. Keep only findings supported by "
                            "the provided graph IDs and retrieved CWE documents. Return JSON only."
                        ),
                        input_text=raw[:24_000],
                        schema_name=str(format_spec["name"]),
                        json_schema=dict(format_spec["schema"]),
                        max_output_tokens=8_000,
                    )
                )
                return ThreatIntelReport.model_validate_json(repaired)
            except (AIProviderError, ValidationError, ValueError) as second_error:
                raise ThreatIntelError("Threat Intel output failed strict JSON validation after repair") from second_error


async def _retrieve(
    discovery: RouteDiscovery,
    graph_context: ArchitectureGraphContext,
    legacy_sources: Mapping[str, str] | None = None,
) -> list[ThreatIntelDocument]:
    """Retrieve a bounded, deterministic CWE context from allowed metadata and source code."""
    fragments = [discovery.target_url]
    for route in discovery.routes:
        fragments.append(route.path)
        fragments.extend(method.value for method in route.methods)
        if route.auth_required is False:
            fragments.append("unauthenticated")
    # Include scan_notes — these contain REAL security observations from HTTP probes
    for note in discovery.scan_notes:
        fragments.append(note)
    for node in graph_context.nodes:
        fragments.extend(node.labels)
        fragments.extend(str(value) for value in node.properties.values() if isinstance(value, (str, int, float, bool)))
    # Include source code content in the scoring corpus so that keywords like
    # "sql", "secret", "admin" found in the actual code boost relevant CWEs.
    if legacy_sources:
        for content in legacy_sources.values():
            fragments.append(content[:8_000])
    corpus = " ".join(fragments).lower()
    scored: list[tuple[int, ThreatIntelDocument]] = []
    for document in _KNOWLEDGE_BASE:
        score = sum(keyword in corpus for keyword in document.keywords)
        if document.cwe == "CWE-862" and any(route.auth_required is False for route in discovery.routes):
            score += 3
        # Boost DAST CWEs when real evidence exists in scan_notes
        if document.cwe == "CWE-1295" and any(
            path in corpus for path in ("/docs", "/swagger", "/openapi.json", "/graphql")
        ):
            score += 4
        if document.cwe == "CWE-693" and "missing" in corpus and "header" in corpus:
            score += 4
        if document.cwe == "CWE-200" and ("server" in corpus or "x-powered-by" in corpus):
            score += 3
        if score:
            scored.append((score, document))
            
    # Attempt to query vector memory for contextually relevant past findings
    try:
        vector_results = await vector_memory.query_similar(corpus[:1000], n_results=2)
        for res in vector_results:
            doc_text = res.get("document", "")
            meta = res.get("metadata", {})
            if doc_text:
                # Synthesize a ThreatIntelDocument from the vector memory hit
                finding_id = meta.get("finding_id", "CUSTOM-000")
                vector_doc = ThreatIntelDocument(
                    cwe="CWE-CUSTOM", 
                    title=f"Historical Vector Memory Hit ({finding_id})",
                    keywords=(),
                    summary=doc_text[:200],
                    verification="Verify against historical remediation patterns stored in vector DB.",
                    asi_code="ASI99"
                )
                # Assign a high score to prioritize historical enterprise knowledge
                scored.append((10, vector_doc))
    except Exception as e:
        logger.warning(f"Failed to query vector memory during threat intelligence retrieval: {e}")

    if not scored:
        return [item for item in _KNOWLEDGE_BASE if item.cwe in {"CWE-20", "CWE-862", "CWE-693"}]
    # Return up to 10 documents so all relevant DAST and code-level CWEs are included
    return [item for _, item in sorted(scored, key=lambda value: (-value[0], value[1].cwe))[:10]]


def _validate_report(
    report: ThreatIntelReport,
    graph_context: ArchitectureGraphContext,
    retrieved: Iterable[ThreatIntelDocument],
) -> None:
    node_ids = {node.id for node in graph_context.nodes}
    retrieved_cwes = {item.cwe for item in retrieved}
    valid_findings = []
    for finding in report.findings:
        cwe = finding.cwe.upper()
        if not _CWE.fullmatch(cwe) or cwe not in retrieved_cwes:
            logger.warning("Dropping finding %r: used CWE %s outside retrieved intelligence", finding.finding_id, cwe)
            continue
        unknown_nodes = set(finding.affected_nodes) - node_ids
        if unknown_nodes:
            logger.warning("Dropping finding %r: referenced unknown graph nodes %s", finding.finding_id, unknown_nodes)
            continue
        if not finding.evidence:
            logger.warning("Dropping finding %r: missing evidence", finding.finding_id)
            continue
        valid_findings.append(finding)
    report.findings = valid_findings


def _report_format() -> dict[str, Any]:
    return {
        "format": {
            "type": "json_schema",
            "name": "threat_intel_report",
            "strict": True,
            "schema": ThreatIntelReport.model_json_schema(),
        }
    }


def _instructions() -> str:
    return """You are ThreatIntelRAG in an authorized DevSecOps remediation pipeline.

You receive:
1. Route discovery: endpoints and scan_notes from LIVE HTTP probing of the target.
2. Architecture graph: Neo4j nodes representing routes and source files. Use element IDs from this graph in `affected_nodes`.
3. Retrieved CWE documents: the vulnerability categories you may report.
4. Legacy source code (if provided): source code of the application being assessed.

PRIORITY 1 — Real DAST Findings (from live scanning):
Analyze the route discovery data and scan_notes for REAL security issues observed during HTTP probing:
- **Missing security headers**: If scan_notes mention missing Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, or X-Content-Type-Options, report as CWE-693 or CWE-1021.
- **Information disclosure**: If Server or X-Powered-By headers expose technology/version, report as CWE-200.
- **Exposed API documentation**: If /docs, /swagger, /openapi.json returned 200 OK without authentication, report as CWE-1295.
- **CORS misconfiguration**: If Access-Control-Allow-Origin is * (wildcard), report as CWE-942.
- **Unauthenticated sensitive endpoints**: If routes with auth_required=false expose sensitive data, report as CWE-862.

For DAST findings, use `evidence` to quote the actual scan_notes observation or the specific header/endpoint.
Use `affected_nodes` to reference the route node IDs from the architecture graph.

PRIORITY 2 — Source Code Findings (from legacy code):
If legacy source code is provided, also look for:
- SQL injection (string concatenation in queries) → CWE-89
- Hardcoded secrets/credentials → CWE-798
- Missing authorization checks → CWE-862
- Authorization bypass through user-controlled keys → CWE-639
- Input validation gaps → CWE-20

For code findings, quote the vulnerable code pattern in `evidence`.

Rules:
- Every finding MUST use a CWE from the retrieved intelligence documents.
- Every finding MUST reference valid graph node IDs in `affected_nodes`.
- You MUST report findings when scan_notes contain clear security observations. Do not skip them.
- Do not invent CVEs, external sources, or hidden reasoning.
- Return structured data only."""


__all__ = ["ThreatIntelError", "ThreatIntelRAG", "ThreatIntelReport"]
