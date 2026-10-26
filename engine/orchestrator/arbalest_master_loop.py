"""Experimental composable six-phase remediation orchestrator.

This research API is not invoked by the supported CLI or MCP entry points.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import uuid
from collections.abc import AsyncGenerator, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, Field

from engine.agents.architect_agent import (
    ArchitectAgent,
    ArchitectureGraphContext,
    CodeLanguage,
    MutationPlan,
    ThreatFinding,
)
from engine.agents.black_box_fuzzer import BlackBoxFuzzer, DiscoveryRoute, HttpMethod, RouteDiscovery
from engine.agents.immune_system_agent import ImmuneSystemError, LearnedThreatPattern
from engine.agents.polyglot_translator import GeneratedCodeBundle, PolyglotTranslator
from engine.agents.red_team_swarm import RedTeamError, RedTeamResult, RedTeamSwarm
from engine.agents.sca_agent import ScaAgent
from engine.agents.sast_agent import SastAgent
from engine.agents.secret_scanner import SecretScannerAgent
from engine.agents.semgrep_agent import SemgrepAgent
from engine.agents.sentinel_agent import SentinelAgent, TrafficEvent
from engine.services.graph_manager import FunctionNode, GraphManager, RouteNode

logger = logging.getLogger(__name__)


class ThreatIntelAnalyzer(Protocol):
    """Real threat-intelligence implementation supplied by the application layer."""

    async def analyze(
        self,
        *,
        discovery: RouteDiscovery,
        graph_context: ArchitectureGraphContext,
        legacy_sources: Mapping[str, str] | None = None,
    ) -> list[ThreatFinding]: ...


class ImmuneSystemSynthesizer(Protocol):
    """Optional learning capability invoked only after a confirmed local exploit."""

    async def synthesize_threat(
        self,
        project_id: str,
        red_team_result: RedTeamResult,
        original_code: str,
    ) -> LearnedThreatPattern: ...


class PipelineEvent(BaseModel):
    """Stable JSON event contract for FastAPI WebSocket consumers."""

    run_id: str
    phase: int = Field(ge=1, le=6)
    type: str
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, Any] = Field(default_factory=dict)

    def as_json(self) -> str:
        return self.model_dump_json()


async def run_pipeline(
    *,
    target_url: str,
    engagement_id: str,
    project_id: str,
    developer_task: str,
    legacy_sources: Mapping[str, str],
    threat_intel: ThreatIntelAnalyzer,
    graph_manager: GraphManager,
    fuzzer: BlackBoxFuzzer,
    architect: ArchitectAgent,
    translator: PolyglotTranslator,
    red_team: RedTeamSwarm,
    sca_agent: ScaAgent | None = None,
    sast_agent: SastAgent | None = None,
    secret_scanner: SecretScannerAgent | None = None,
    semgrep_agent: SemgrepAgent | None = None,
    sentinel_agent: SentinelAgent | None = None,
    traffic_events: list[TrafficEvent] | None = None,
    immune_system: ImmuneSystemSynthesizer | None = None,
    target_language: CodeLanguage = CodeLanguage.AUTO,
    run_id: str | None = None,
) -> AsyncGenerator[str, None]:
    """Run all remediation phases and stream operational JSON events immediately.

    The function deliberately does not expose model chain-of-thought.  Its
    ``agent_log`` events report auditable actions, decisions, and tool status;
    ``terminal_output`` events contain bounded Docker stdout/stderr chunks.
    """
    current_run_id = run_id or str(uuid.uuid4())
    discovery: RouteDiscovery | None = None
    findings: list[ThreatFinding] = []
    generated_code: GeneratedCodeBundle | None = None
    red_team_result: RedTeamResult | None = None
    mutation_plan: MutationPlan | None = None
    red_team_task: asyncio.Task[RedTeamResult] | None = None

    try:
        _validate_inputs(target_url, engagement_id, project_id, developer_task, legacy_sources)

        yield _event(current_run_id, 1, "phase_started", "Black-box fuzzing started", {"target_url": target_url, "agent": "black_box_fuzzer"})
        is_local_scan = "local-scan.internal" in target_url
        if is_local_scan and legacy_sources:
            # Static analysis mode: extract routes from source code instead of HTTP fuzzing
            discovery = _static_route_discovery(target_url, legacy_sources)
            yield _event(
                current_run_id,
                1,
                "agent_log",
                f"Static route extraction completed from {len(legacy_sources)} source files",
                {"route_count": len(discovery.routes), "agent": "static_analyzer"},
            )
        else:
            discovery = await fuzzer.discover(target_url, engagement_id=engagement_id)
            yield _event(
                current_run_id,
                1,
                "agent_log",
                "BlackBoxFuzzer completed authorized route discovery",
                {"route_count": len(discovery.routes), "agent": "black_box_fuzzer"},
            )
        yield _event(
            current_run_id,
            1,
            "graph_update",
            "Discovered routes are ready for graph synchronization",
            {"routes": [route.model_dump(mode="json") for route in discovery.routes]},
        )

        yield _event(current_run_id, 2, "phase_started", "Synchronizing discovered API and source inventory to Neo4j")
        neo4j_available = False
        graph_context = ArchitectureGraphContext.from_neo4j_snapshot(project_id, {"nodes": [], "relationships": []})
        try:
            await graph_manager.connect()
            await graph_manager.ensure_schema()
            await graph_manager.upsert_project(project_id, project_id)
            function_count, route_count = await _sync_graph(graph_manager, project_id, discovery, legacy_sources)
            snapshot = await graph_manager.project_snapshot(project_id)
            graph_context = ArchitectureGraphContext.from_neo4j_snapshot(project_id, snapshot)
            neo4j_available = True
            yield _event(
                current_run_id,
                2,
                "agent_log",
                "Neo4j graph synchronization completed",
                {"function_nodes": function_count, "route_nodes": route_count, "agent": "graph_manager"},
            )
        except Exception as graph_err:
            logger.warning("Graph synchronization failed; continuing without Neo4j", extra={"run_id": current_run_id, "error": str(graph_err)[:300]})
            if discovery:
                snapshot = _in_memory_graph_snapshot(project_id, target_url, discovery, legacy_sources)
                graph_context = ArchitectureGraphContext.from_neo4j_snapshot(project_id, snapshot)
            yield _event(
                current_run_id,
                2,
                "agent_log",
                f"Graph synchronization encountered an error: {str(graph_err)[:300]}. continuing with in-memory graph.",
                {"agent": "graph_manager", "error": str(graph_err)[:300]},
            )

        yield _event(current_run_id, 3, "phase_started", "Running Threat Intel analysis", {"agent": "threat_intel"})
        try:
            raw_findings = await threat_intel.analyze(discovery=discovery, graph_context=graph_context, legacy_sources=dict(legacy_sources))
            findings = [ThreatFinding.model_validate(item) for item in raw_findings]
        except Exception as threat_err:
            logger.warning("Threat Intel analysis failed; continuing with empty findings", extra={"run_id": current_run_id, "error": str(threat_err)[:500]})
            yield _event(
                current_run_id,
                3,
                "agent_log",
                f"Threat Intel analysis encountered an error: {str(threat_err)[:300]}. Continuing with discovery data.",
                {"agent": "threat_intel", "error": str(threat_err)[:300]},
            )

        if sca_agent is not None:
            yield _event(current_run_id, 3, "agent_log", "Running Software Composition Analysis (SCA) on uploaded codebase...", {"agent": "sca_agent"})
            try:
                sca_findings = await sca_agent.analyze(legacy_sources=legacy_sources)
                findings.extend(sca_findings)
                if sca_findings:
                    yield _event(current_run_id, 3, "agent_log", f"SCA discovered {len(sca_findings)} vulnerable dependencies.", {"agent": "sca_agent", "finding_count": len(sca_findings)})
            except Exception as sca_err:
                logger.warning("SCA analysis failed", extra={"error": str(sca_err)[:300]})

        if semgrep_agent is not None:
            yield _event(current_run_id, 3, "agent_log", "Running Semgrep Hybrid Analysis on uploaded codebase...", {"agent": "semgrep_agent"})
            try:
                semgrep_findings = await semgrep_agent.analyze(legacy_sources=legacy_sources)
                findings.extend(semgrep_findings)
                if semgrep_findings:
                    yield _event(current_run_id, 3, "agent_log", f"Semgrep discovered {len(semgrep_findings)} deterministic logic flaws.", {"agent": "semgrep_agent", "finding_count": len(semgrep_findings)})
            except Exception as semgrep_err:
                logger.warning("Semgrep analysis failed", extra={"error": str(semgrep_err)[:300]})


        if sast_agent is not None:
            yield _event(current_run_id, 3, "agent_log", "Running Static Application Security Testing (SAST) on source files...", {"agent": "sast_agent"})
            try:
                sast_findings = await sast_agent.analyze(legacy_sources=legacy_sources)
                findings.extend(sast_findings)
                if sast_findings:
                    yield _event(current_run_id, 3, "agent_log", f"SAST discovered {len(sast_findings)} logic vulnerabilities.", {"agent": "sast_agent", "finding_count": len(sast_findings)})
            except Exception as sast_err:
                logger.warning("SAST analysis failed", extra={"error": str(sast_err)[:300]})

        if secret_scanner is not None:
            yield _event(current_run_id, 3, "agent_log", "Running Secret Scanner on uploaded codebase...", {"agent": "secret_scanner"})
            try:
                secret_findings = await secret_scanner.analyze(legacy_sources=legacy_sources)
                findings.extend(secret_findings)
                if secret_findings:
                    yield _event(current_run_id, 3, "agent_log", f"Secret Scanner discovered {len(secret_findings)} exposed secrets.", {"agent": "secret_scanner", "finding_count": len(secret_findings)})
            except Exception as sec_err:
                logger.warning("Secret Scanner analysis failed", extra={"error": str(sec_err)[:300]})

        if sentinel_agent is not None and traffic_events:
            yield _event(current_run_id, 3, "agent_log", f"Running Sentinel Agent on {len(traffic_events)} live traffic events...", {"agent": "sentinel_agent"})
            try:
                for event in traffic_events:
                    sentinel_finding = await sentinel_agent.analyze_traffic(event, graph_context)
                    if sentinel_finding:
                        findings.append(sentinel_finding)
                        yield _event(current_run_id, 3, "agent_log", f"Sentinel Agent flagged authorized traffic event: {sentinel_finding.cwe}", {"agent": "sentinel_agent"})
            except Exception as sent_err:
                logger.warning("Sentinel Agent analysis failed", extra={"error": str(sent_err)[:300]})

        findings = _resolve_finding_targets(findings, graph_context)

        if neo4j_available and findings:
            try:
                await _attach_findings(graph_manager, project_id, findings, graph_context)
            except Exception as attach_err:
                logger.warning("Could not attach findings to Neo4j graph", extra={"run_id": current_run_id, "error": str(attach_err)[:300]})
        yield _event(
            current_run_id,
            3,
            "agent_log",
            "Threat Intel analysis completed",
            {"finding_count": len(findings), "findings": [item.model_dump(mode="json") for item in findings], "agent": "threat_intel"},
        )
        # Emit a structured findings summary for the dashboard
        findings_by_severity: dict[str, int] = {}
        findings_by_agent: dict[str, int] = {}
        for f in findings:
            findings_by_severity[f.severity.value] = findings_by_severity.get(f.severity.value, 0) + 1
            agent_prefix = f.finding_id.split("-")[0].lower()
            findings_by_agent[agent_prefix] = findings_by_agent.get(agent_prefix, 0) + 1
        yield _event(
            current_run_id,
            3,
            "findings_summary",
            f"Analysis complete: {len(findings)} findings across {len(findings_by_agent)} agents",
            {
                "total": len(findings),
                "by_severity": findings_by_severity,
                "by_agent": findings_by_agent,
                "details": [
                    {
                        "id": f.finding_id,
                        "severity": f.severity.value,
                        "summary": f.summary[:300],
                        "cwe": f.cwe,
                    }
                    for f in findings[:50]  # Bound for WebSocket
                ],
            },
        )

        yield _event(current_run_id, 4, "phase_started", "Creating mutation plan and secure replacement code", {"agent": "architect"})
        actionable_findings = [f for f in findings if f.affected_nodes]
        if not findings:
            yield _event(
                current_run_id,
                4,
                "agent_log",
                "No confirmed finding was returned; code rewrite is intentionally skipped",
                {"agent": "architect"},
            )
        elif not actionable_findings:
            yield _event(
                current_run_id,
                4,
                "agent_log",
                "No local code match found; producing Threat Intel report only.",
                {"agent": "architect"},
            )
            report_lines = ["# External Vulnerability Report\n", "The following vulnerabilities were discovered on the target, but could not be mapped to the local codebase:\n"]
            for f in findings:
                report_lines.append(f"## {f.finding_id} ({f.cwe}) - {f.severity.upper()}")
                report_lines.append(f"{f.summary}\n")
                report_lines.append("**Evidence:**")
                for ev in f.evidence:
                    report_lines.append(f"- {ev}")
                report_lines.append("")
            yield _event(
                current_run_id,
                4,
                "diff_ready",
                "Vulnerability Report",
                {
                    "path": "Vulnerability Report",
                    "language": "markdown",
                    "before": "No local code mapped to these endpoints.",
                    "after": "\n".join(report_lines),
                    "agent": "threat_intel",
                }
            )
        else:
            try:
                mutation_plan = await architect.create_plan(
                    graph_context=graph_context,
                    findings=actionable_findings,
                    developer_task=developer_task,
                    available_files=legacy_sources,
                    target_language=target_language,
                )
                yield _event(
                    current_run_id,
                    4,
                    "agent_log",
                    "ArchitectAgent emitted a validated mutation plan",
                    {"plan_id": mutation_plan.plan_id, "mutation_count": len(mutation_plan.mutations), "agent": "architect"},
                )
                generated_code = await translator.translate(legacy_sources=legacy_sources, mutation_plan=mutation_plan)
                yield _event(
                    current_run_id,
                    4,
                    "diff_ready",
                    "PolyglotTranslator generated statically validated secure code",
                    {**_diff_payload(generated_code, mutation_plan, legacy_sources), "agent": "polyglot"},
                )
            except Exception as rewrite_err:
                logger.warning(
                    "Code rewrite failed; continuing with findings report",
                    extra={"run_id": current_run_id, "error": str(rewrite_err)[:500]},
                )
                # Fall back to a vulnerability report when code generation fails
                report_lines = [
                    "# Security Assessment Report\n",
                    f"**Target:** {target_url}\n",
                    f"**Findings:** {len(findings)} vulnerabilities identified\n",
                ]
                for f in findings:
                    report_lines.append(f"## {f.finding_id} ({f.cwe}) — Severity: {f.severity.upper()}")
                    report_lines.append(f"{f.summary}\n")
                    report_lines.append("**Evidence:**")
                    for ev in f.evidence:
                        report_lines.append(f"- {ev}")
                    if f.affected_nodes:
                        report_lines.append(f"**Affected nodes:** {', '.join(f.affected_nodes)}")
                    report_lines.append("")
                yield _event(
                    current_run_id,
                    4,
                    "diff_ready",
                    f"Security assessment completed with {len(findings)} findings (code rewrite unavailable: {type(rewrite_err).__name__})",
                    {
                        "path": "Security Assessment Report",
                        "language": "markdown",
                        "before": "No code transformation was produced for these findings.",
                        "after": "\n".join(report_lines),
                        "agent": "threat_intel",
                        "finding_count": len(findings),
                    },
                )
                mutation_plan = None
                generated_code = None

        yield _event(current_run_id, 5, "phase_started", "Executing Red Team sandbox attack simulation", {"agent": "red_team"})
        if generated_code is None:
            yield _event(current_run_id, 5, "agent_log", "Red Team stage skipped because no code mutation was produced", {"agent": "red_team"})
        else:
            if mutation_plan is None:
                raise RuntimeError("Generated code is missing its validated mutation plan")
            try:
                for verification_attempt in range(1, 4):
                    red_team_task, terminal_events = _start_red_team(
                        current_run_id=current_run_id,
                        generated_code=generated_code,
                        findings=findings,
                        red_team=red_team,
                        mutation_plan=mutation_plan,
                    )
                    yield _event(
                        current_run_id,
                        5,
                        "agent_log",
                        f"Live verification attempt {verification_attempt}/3: launching an isolated attack harness",
                        {"agent": "red_team", "verification_attempt": verification_attempt},
                    )
                    try:
                        while not red_team_task.done() or not terminal_events.empty():
                            try:
                                yield await asyncio.wait_for(terminal_events.get(), timeout=0.25)
                            except TimeoutError:
                                continue
                        red_team_result = await red_team_task
                    except asyncio.CancelledError:
                        raise
                    finally:
                        if red_team_task.done():
                            red_team_task = None

                    yield _event(
                        current_run_id,
                        5,
                        "agent_log",
                        "Red Team sandbox assessment completed",
                        {
                            "sandbox_status": red_team_result.sandbox.status.value,
                            "exit_code": red_team_result.sandbox.exit_code,
                            "exploit_successful": red_team_result.analysis.exploit_successful,
                            "inconclusive": red_team_result.analysis.inconclusive,
                            "deployment_allowed": red_team_result.deployment_allowed,
                            "reasoning": red_team_result.analysis.reasoning,
                            "agent": "red_team",
                            "verification_attempt": verification_attempt,
                        },
                    )
                    if red_team_result.deployment_allowed:
                        yield _event(
                            current_run_id,
                            5,
                            "agent_log",
                            "Dynamic Verification Passed",
                            {
                                "agent": "red_team",
                                "verification_attempt": verification_attempt,
                                "verification_status": "passed",
                            },
                        )
                        break
                    if not red_team_result.analysis.exploit_successful:
                        yield _event(
                            current_run_id,
                            5,
                            "agent_log",
                            "Live verification was inconclusive; deployment remains blocked",
                            {
                                "agent": "red_team",
                                "verification_attempt": verification_attempt,
                                "verification_status": "inconclusive",
                            },
                        )
                        break
                    if immune_system is not None:
                        try:
                            learned_pattern = await immune_system.synthesize_threat(
                                project_id,
                                red_team_result,
                                _original_code_for_learning(mutation_plan, legacy_sources),
                            )
                        except asyncio.CancelledError:
                            raise
                        except ImmuneSystemError:
                            logger.warning("Zero-day learning failed safely", extra={"run_id": current_run_id})
                            yield _event(
                                current_run_id,
                                5,
                                "agent_log",
                                "Zero-Day learning could not be persisted; remediation will continue safely",
                                {"agent": "immune_system", "verification_attempt": verification_attempt},
                            )
                        except Exception:
                            logger.error("Unexpected zero-day learning failure", extra={"run_id": current_run_id})
                            yield _event(
                                current_run_id,
                                5,
                                "agent_log",
                                "Zero-Day learning could not be persisted; remediation will continue safely",
                                {"agent": "immune_system", "verification_attempt": verification_attempt},
                            )
                        else:
                            yield _event(
                                current_run_id,
                                5,
                                "agent_log",
                                "Zero-Day Learned: Synthesized new vulnerability pattern and updated Neo4j Threat Graph.",
                                {
                                    "agent": "immune_system",
                                    "verification_attempt": verification_attempt,
                                    "threat_name": learned_pattern.threat_name,
                                    "cwe_category": learned_pattern.cwe_category,
                                },
                            )
                    if verification_attempt == 3:
                        yield _event(
                            current_run_id,
                            5,
                            "agent_log",
                            "Active exploit persisted after three verification attempts; deployment remains blocked",
                            {
                                "agent": "red_team",
                                "verification_attempt": verification_attempt,
                                "verification_status": "failed",
                            },
                        )
                        break

                    yield _event(
                        current_run_id,
                        5,
                        "agent_log",
                        "Active exploit reproduced; PolyglotTranslator is generating a stronger fix from sandbox evidence",
                        {"agent": "polyglot", "verification_attempt": verification_attempt},
                    )
                    generated_code = await translator.repair_after_verification(
                        candidate=generated_code,
                        mutation_plan=mutation_plan,
                        verification_evidence=_verification_evidence(red_team_result),
                    )
                    yield _event(
                        current_run_id,
                        4,
                        "diff_ready",
                        "PolyglotTranslator generated a self-healed secure code revision",
                        {
                            **_diff_payload(generated_code, mutation_plan, legacy_sources),
                            "agent": "polyglot",
                            "verification_attempt": verification_attempt,
                        },
                    )

            except RedTeamError as rt_err:
                logger.warning("Red Team validation failed safely", extra={"run_id": current_run_id, "error": str(rt_err)})
                yield _event(
                    current_run_id,
                    5,
                    "agent_log",
                    f"Red Team validation encountered an error: {str(rt_err)[:500]}. Deployment remains blocked.",
                    {"agent": "red_team", "error": str(rt_err)[:500]},
                )

        yield _event(current_run_id, 6, "phase_started", "Evaluating verification gate")
        if red_team_result is not None and red_team_result.deployment_allowed:
            yield _event(
                current_run_id,
                6,
                "verification_passed",
                "Sandbox gate passed; the caller may persist a remediation artifact for reviewed deployment",
                {
                    "finding_count": len(findings),
                    "generated_files": len(generated_code.files) if generated_code is not None else 0,
                    "plan_id": mutation_plan.plan_id if mutation_plan is not None else "",
                },
            )
        else:
            reason = "no mutation was produced" if generated_code is None else (
                "red-team gate did not pass" if red_team_result is not None else "red-team validation encountered an error"
            )
            yield _event(
                current_run_id,
                6,
                "verification_blocked",
                f"Verification withheld because {reason}",
                {
                    "finding_count": len(findings),
                    "code_generated": generated_code is not None,
                    "red_team_completed": red_team_result is not None,
                },
            )
        yield _event(current_run_id, 6, "complete", "Arbalest pipeline completed")

    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.exception("Arbalest pipeline failed", extra={"run_id": current_run_id})
        yield _event(
            current_run_id,
            6,
            "error",
            f"Pipeline aborted unexpectedly: {_compact_error(exc)}",
        )
    finally:
        # The generator may be closed when a WebSocket disconnects or the API
        # process shuts down.  Red-team execution owns a Docker workload, so
        # always propagate cancellation and wait for its cleanup path.
        if red_team_task is not None:
            if not red_team_task.done():
                red_team_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await red_team_task


def _static_route_discovery(
    target_url: str,
    legacy_sources: Mapping[str, str],
) -> RouteDiscovery:
    """Extract API routes from source code for static analysis when no live server is available.

    This replaces the BlackBoxFuzzer's HTTP probing for ZIP uploads, parsing common
    framework route decorators (FastAPI, Flask, Express, Django, Spring, etc.) to
    build a synthetic RouteDiscovery that feeds the rest of the pipeline.
    """
    import re as _re

    _FLASK_ROUTE_PATTERN = _re.compile(
        r"""@(?:app|router|blueprint)\.route\s*\(\s*["']([^"']+)["'](?P<args>[^)]*)\)""",
        _re.IGNORECASE,
    )
    _ROUTE_PATTERNS = [
        # Python: FastAPI / Flask
        _re.compile(r"""@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']""", _re.IGNORECASE),
        # Python: Django urls
        _re.compile(r"""path\s*\(\s*["']([^"']+)["']""", _re.IGNORECASE),
        # JavaScript/TypeScript: Express
        _re.compile(r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']""", _re.IGNORECASE),
        # Java: Spring @RequestMapping / @GetMapping etc
        _re.compile(r"""@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']""", _re.IGNORECASE),
        # Go: gorilla/mux or gin
        _re.compile(r"""\.(?:Handle|HandleFunc|GET|POST|PUT|DELETE)\s*\(\s*["']([^"']+)["']""", _re.IGNORECASE),
    ]

    found_routes: dict[tuple[str, str], DiscoveryRoute] = {}
    scan_notes: list[str] = []

    def normalize_route_path(route_path: str) -> str:
        if not route_path.startswith("/"):
            route_path = "/" + route_path
        route_path = _re.sub(r"\{[^}]+\}", "{id}", route_path)
        return _re.sub(r":[a-zA-Z_]+", "{id}", route_path)

    def route_methods_from_flask_args(args: str) -> list[HttpMethod]:
        method_values = [item.upper() for item in _re.findall(r"""["'](GET|POST)["']""", args, flags=_re.IGNORECASE)]
        methods = [HttpMethod(value) for value in dict.fromkeys(method_values)]
        return methods or [HttpMethod.GET]

    def add_route(file_path: str, method: HttpMethod, route_path: str) -> None:
        route_path = normalize_route_path(route_path)
        key = (method.value, route_path)
        if key not in found_routes:
            found_routes[key] = DiscoveryRoute(
                path=route_path,
                methods=[method],
                auth_required=None,
                observed_status_codes=[200],
            )
            scan_notes.append(f"Static: found {method.value} {route_path} in {file_path}")

    for file_path, content in legacy_sources.items():
        for flask_match in _FLASK_ROUTE_PATTERN.finditer(content[:64_000]):
            route_path = flask_match.group(1)
            for method in route_methods_from_flask_args(flask_match.group("args") or ""):
                add_route(file_path, method, route_path)
        for pattern in _ROUTE_PATTERNS:
            for match in pattern.finditer(content[:64_000]):
                groups = match.groups()
                if len(groups) == 2:
                    method_str, route_path = groups
                    method = HttpMethod.POST if method_str.upper() == "POST" else HttpMethod.GET
                elif len(groups) == 1:
                    route_path = groups[0]
                    method = HttpMethod.GET
                else:
                    continue
                add_route(file_path, method, route_path)

    if not found_routes:
        for file_path in legacy_sources:
            normalized = file_path.replace("\\", "/")
            fake_path = f"/source/{normalized}"
            found_routes[(HttpMethod.GET.value, fake_path)] = DiscoveryRoute(
                path=fake_path,
                methods=[HttpMethod.GET],
                auth_required=None,
                observed_status_codes=[200],
            )
        scan_notes.append(f"No framework routes detected; created {len(found_routes)} source entries for analysis")

    return RouteDiscovery(
        target_url=target_url,
        routes=list(found_routes.values())[:200],
        scan_notes=scan_notes[:20],
    )


async def _sync_graph(
    graph_manager: GraphManager,
    project_id: str,
    discovery: RouteDiscovery,
    legacy_sources: Mapping[str, str],
) -> tuple[int, int]:
    functions: list[FunctionNode] = []
    routes: list[RouteNode] = []
    for path, content in legacy_sources.items():
        normalized_path = path.replace("\\", "/")
        functions.append(
            FunctionNode(
                project_id=project_id,
                file_path=normalized_path,
                qualified_name=f"source::{normalized_path}",
                language=_language_for_path(normalized_path),
                start_line=1,
                end_line=max(1, content.count("\n") + 1),
                signature=f"source inventory: {normalized_path}",
            )
        )
    for route in discovery.routes:
        for method in route.methods:
            handler = f"route::{method.value}::{route.path}"
            functions.append(
                FunctionNode(
                    project_id=project_id,
                    file_path=f"__discovered__/{_route_hash(method.value, route.path)}.route",
                    qualified_name=handler,
                    language="http",
                    start_line=1,
                    end_line=1,
                    signature=f"{method.value} {route.path}",
                )
            )
            routes.append(
                RouteNode(
                    project_id=project_id,
                    method=method.value,
                    path=route.path,
                    handler_name=handler,
                    auth_required=route.auth_required is True,
                )
            )
    await graph_manager.reconcile_project_inventory(project_id, functions, routes)
    return len(functions), len(routes)


def _in_memory_graph_snapshot(
    project_id: str,
    target_url: str,
    discovery: RouteDiscovery,
    legacy_sources: Mapping[str, str],
) -> dict[str, list[dict[str, Any]]]:
    """Build the source and route context used when Neo4j is unavailable.

    This mirrors the identities that ``_sync_graph`` persists: every legacy
    source receives a File and Function node, while every discovered
    ``(method, path)`` pair receives a Route and synthetic handler Function.
    Agents can therefore keep validating findings and mutation plans against
    stable graph IDs during a temporary Neo4j outage.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    service_node_id = f"service-{project_id}"
    nodes.append(
        {
            "id": service_node_id,
            "labels": ["Service"],
            "properties": {"project_id": project_id, "label": target_url},
        }
    )

    for path, content in legacy_sources.items():
        normalized_path = path.replace("\\", "/")
        language = _language_for_path(normalized_path)
        qualified_name = f"source::{normalized_path}"
        file_node_id = f"file-{_route_hash(normalized_path)}"
        function_node_id = f"function-{_route_hash(qualified_name)}"
        nodes.extend(
            (
                {
                    "id": file_node_id,
                    "labels": ["File"],
                    "properties": {
                        "project_id": project_id,
                        "path": normalized_path,
                        "language": language,
                        "label": normalized_path,
                    },
                },
                {
                    "id": function_node_id,
                    "labels": ["Function"],
                    "properties": {
                        "project_id": project_id,
                        "file_path": normalized_path,
                        "qualified_name": qualified_name,
                        "language": language,
                        "start_line": 1,
                        "end_line": max(1, content.count("\n") + 1),
                        "signature": f"source inventory: {normalized_path}",
                        "label": qualified_name,
                    },
                },
            )
        )
        edges.extend(
            (
                {
                    "source_id": service_node_id,
                    "target_id": file_node_id,
                    "relationship_type": "CONTAINS",
                    "properties": {},
                },
                {
                    "source_id": file_node_id,
                    "target_id": function_node_id,
                    "relationship_type": "CONTAINS",
                    "properties": {},
                },
            )
        )

    for route in discovery.routes:
        # DiscoveryRoute intentionally groups verified methods for one path,
        # while the graph models each ``(method, path)`` pair independently.
        for method in route.methods:
            method_value = method.value
            route_key = _route_hash(method_value, route.path)
            route_node_id = f"route-{route_key}"
            handler_name = f"route::{method_value}::{route.path}"
            handler_node_id = f"function-{_route_hash(handler_name)}"
            handler_path = f"__discovered__/{route_key}.route"
            nodes.extend(
                (
                    {
                        "id": route_node_id,
                        "labels": ["Route"],
                        "properties": {
                            "project_id": project_id,
                            "method": method_value,
                            "path": route.path,
                            "auth_required": route.auth_required,
                            "label": f"{method_value} {route.path}",
                        },
                    },
                    {
                        "id": handler_node_id,
                        "labels": ["Function"],
                        "properties": {
                            "project_id": project_id,
                            "file_path": handler_path,
                            "qualified_name": handler_name,
                            "language": "http",
                            "start_line": 1,
                            "end_line": 1,
                            "signature": f"{method_value} {route.path}",
                            "label": handler_name,
                        },
                    },
                )
            )
            edges.extend(
                (
                    {
                        "source_id": service_node_id,
                        "target_id": route_node_id,
                        "relationship_type": "EXPOSES",
                        "properties": {},
                    },
                    {
                        "source_id": route_node_id,
                        "target_id": handler_node_id,
                        "relationship_type": "HANDLED_BY",
                        "properties": {},
                    },
                )
            )

    return {"nodes": nodes, "edges": edges}


async def _attach_findings(
    graph_manager: GraphManager,
    project_id: str,
    findings: list[ThreatFinding],
    graph_context: ArchitectureGraphContext,
) -> None:
    """Resolve agent-visible Neo4j element IDs back to stable function names."""
    qualified_names = {
        node.id: str(node.properties["qualified_name"])
        for node in graph_context.nodes
        if isinstance(node.properties.get("qualified_name"), str)
    }
    for finding in findings:
        for target in finding.affected_nodes:
            qualified_name = qualified_names.get(target)
            if qualified_name is None:
                logger.warning("Skipping finding target without a function identity", extra={"target": target})
                continue
            await graph_manager.add_finding(
                finding_id=f"{finding.finding_id}:{_route_hash(finding.finding_id, target)}",
                project_id=project_id,
                target_qualified_name=qualified_name,
                cwe=finding.cwe,
                severity=finding.severity.value,
                summary=finding.summary,
            )


def _resolve_finding_targets(
    findings: list[ThreatFinding],
    graph_context: ArchitectureGraphContext,
) -> list[ThreatFinding]:
    """Normalize file-path finding targets into graph node IDs expected by the planner."""
    if not findings:
        return []

    node_ids = {node.id for node in graph_context.nodes}
    file_path_to_function_id: dict[str, str] = {}
    qualified_name_to_function_id: dict[str, str] = {}
    for node in graph_context.nodes:
        if "Function" not in node.labels:
            continue
        file_path = node.properties.get("file_path")
        qualified_name = node.properties.get("qualified_name")
        if isinstance(file_path, str):
            file_path_to_function_id[file_path.replace("\\", "/")] = node.id
        if isinstance(qualified_name, str):
            qualified_name_to_function_id[qualified_name] = node.id
            if qualified_name.startswith("source::"):
                file_path_to_function_id.setdefault(qualified_name.removeprefix("source::").replace("\\", "/"), node.id)

    resolved_findings: list[ThreatFinding] = []
    for finding in findings:
        resolved_targets: list[str] = []
        for target in finding.affected_nodes:
            normalized = target.replace("\\", "/").strip()
            resolved = normalized if normalized in node_ids else file_path_to_function_id.get(normalized)
            if resolved is None:
                resolved = qualified_name_to_function_id.get(normalized)
            if resolved is not None and resolved not in resolved_targets:
                resolved_targets.append(resolved)
        if resolved_targets == finding.affected_nodes:
            resolved_findings.append(finding)
        else:
            resolved_findings.append(finding.model_copy(update={"affected_nodes": resolved_targets}))
    return resolved_findings


def _start_red_team(
    *,
    current_run_id: str,
    generated_code: GeneratedCodeBundle,
    findings: list[ThreatFinding],
    red_team: RedTeamSwarm,
    mutation_plan: MutationPlan,
) -> tuple[asyncio.Task[RedTeamResult], asyncio.Queue[str]]:
    """Bridge asynchronous Docker log callbacks into ordered generator events."""
    event_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=512)

    async def log_sink(stream: str, content: str) -> None:
        event = _event(
            current_run_id,
            5,
            "terminal_output",
            content,
            {"stream": stream, "agent": "red_team"},
        )
        try:
            event_queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("Dropping red-team terminal event for slow pipeline consumer")

    task: asyncio.Task[RedTeamResult] = asyncio.create_task(
        red_team.execute(
            generated_code=generated_code,
            mutation_plan=mutation_plan,
            findings=findings,
            log_sink=log_sink,
        ),
        name=f"red-team-{current_run_id}",
    )
    return task, event_queue


def _event(run_id: str, phase: int, event_type: str, message: str, payload: dict[str, Any] | None = None) -> str:
    return PipelineEvent(run_id=run_id, phase=phase, type=event_type, message=message, payload=payload or {}).as_json()


def _validate_inputs(
    target_url: str,
    engagement_id: str,
    project_id: str,
    developer_task: str,
    legacy_sources: Mapping[str, str],
) -> None:
    if not target_url.startswith(("https://", "http://")):
        raise ValueError("target_url must be an HTTP(S) URL")
    if not engagement_id.strip() or not project_id.strip() or not developer_task.strip():
        raise ValueError("engagement_id, project_id, and developer_task are required")


def _route_hash(*values: str) -> str:
    return hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()[:16]


def _language_for_path(path: str) -> str:
    extension = path.rsplit(".", 1)[-1].lower() if "." in path else "text"
    return {"py": "python", "js": "javascript", "ts": "typescript", "java": "java", "go": "go", "rs": "rust"}.get(
        extension, extension
    )


def _diff_payload(
    generated_code: GeneratedCodeBundle,
    mutation_plan: MutationPlan,
    legacy_sources: Mapping[str, str],
) -> dict[str, Any]:
    """Publish one bounded source comparison for the dashboard diff panel."""
    import difflib
    
    primary_mutation = mutation_plan.mutations[0]
    generated_files = generated_code.file_mapping()
    
    before_content = legacy_sources.get(primary_mutation.target_file, "")
    after_content = generated_files.get(generated_code.entrypoint, "")
    
    patch_lines = list(difflib.unified_diff(
        before_content.splitlines(keepends=True),
        after_content.splitlines(keepends=True),
        fromfile=f"a/{primary_mutation.target_file}",
        tofile=f"b/{generated_code.entrypoint}",
        n=3
    ))
    patch_content = "".join(patch_lines)
    
    return {
        "language": generated_code.language.value,
        "path": generated_code.entrypoint,
        "legacy_path": primary_mutation.target_file,
        "files": [file.path for file in generated_code.files],
        # Keep WebSocket event size bounded. Full generated artifacts remain in
        # the run workspace/object store rather than the realtime transport.
        "before": before_content[:200_000],
        "after": after_content[:200_000],
        "patch": patch_content[:200_000],
    }


def _verification_evidence(result: RedTeamResult) -> dict[str, Any]:
    """Return bounded local evidence for a self-healing translator revision."""
    return {
        "exploit_successful": result.analysis.exploit_successful,
        "analysis": {
            "reasoning": result.analysis.reasoning[:4_000],
            "evidence": [item[:1_000] for item in result.analysis.evidence[:20]],
        },
        "sandbox": {
            "status": result.sandbox.status.value,
            "exit_code": result.sandbox.exit_code,
            "stdout": result.sandbox.stdout[:16_000],
            "stderr": result.sandbox.stderr[:16_000],
            "error": (result.sandbox.error or "")[:2_000],
        },
    }


def _original_code_for_learning(mutation_plan: MutationPlan, legacy_sources: Mapping[str, str]) -> str:
    """Return only mutation-target source, bounded for a threat-learning prompt."""
    chunks: list[str] = []
    seen_files: set[str] = set()
    remaining = 64_000
    for mutation in mutation_plan.mutations:
        if mutation.target_file in seen_files:
            continue
        source = legacy_sources.get(mutation.target_file)
        if source is None:
            source = next(
                (
                    content
                    for path, content in legacy_sources.items()
                    if path.replace("\\", "/") == mutation.target_file
                ),
                "",
            )
        if not source:
            continue
        header = f"Source file: {mutation.target_file}\n"
        content = source[: max(0, remaining - len(header))]
        if not content:
            break
        chunks.append(f"{header}{content}")
        seen_files.add(mutation.target_file)
        remaining -= len(header) + len(content)
        if remaining <= 0:
            break
    return "\n\n".join(chunks)


def _compact_error(error: Exception) -> str:
    return str(error).replace("\n", " ")[:1_000] or error.__class__.__name__
