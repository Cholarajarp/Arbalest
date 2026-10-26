"""Shared, fail-closed agent-swarm scan pipeline."""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import os
import re
from pathlib import Path
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any

from engine.agents.architect_agent import ThreatFinding
from engine.agents.black_box_fuzzer import RouteDiscovery
from engine.agents.finding_verifier import FindingVerifier
from engine.agents.hypothesis_agent import HypothesisAgent
from engine.agents.sast_agent import SastAgent
from engine.agents.sca_agent import ScaAgent
from engine.agents.secret_scanner import SecretScannerAgent
from engine.agents.semgrep_agent import SemgrepAgent
from engine.agents.threat_intel_rag import ThreatIntelRAG
from engine.harness.injection_defense import InjectionHit, scan_untrusted
from engine.harness.mission_ledger import MissionLedger
from engine.immune.antibody import load_antibodies
from engine.services.dispositions import load_dispositions
from engine.services.runtime import model_for
from engine.services.scan_workflow import PhaseResult, ScanOptions, ScanWorkflow
from engine.services.source_collector import ReconReport
from engine.services.source_graph import build_file_graph
from engine.services.tavily_intel import TavilyIntelClient
from engine.services.vector_memory import get_vector_memory

logger = logging.getLogger("arbalest.pipeline")
_LOCAL_SCAN_TARGET = "local-scan.internal"
_SEV_SORT = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SUMMARY_STOP = frozenset({
    "the", "and", "for", "are", "but", "not", "you", "with", "this", "that", "from",
    "into", "via", "uses", "used", "using", "allows", "allowing", "which", "user",
    "supplier", "supplied", "client", "data", "code",
})


def known_antibody_patterns(root: Path, limit: int = 8) -> list[str] | None:
    """Summaries of validated antibodies, passed to SAST as previously confirmed patterns."""
    patterns = [f"{item.rule_id} ({item.cwe}): {item.message}" for item in load_antibodies(root)]
    return patterns[:limit] or None


def _summary_tokens(summary: str) -> frozenset[str]:
    return frozenset(
        word for word in re.findall(r"[a-z0-9]+", summary.lower())
        if len(word) > 2 and word not in _SUMMARY_STOP
    )


class _null_ctx:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@dataclass
class AgentStat:
    name: str
    status: str = "ok"
    count: int = 0
    detail: str = ""
    required: bool = True
    coverage: dict[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "count": self.count,
            "detail": self.detail,
            "required": self.required,
            "coverage": self.coverage,
        }


@dataclass
class SwarmResult:
    findings: list[ThreatFinding] = field(default_factory=list)
    stats: dict[str, AgentStat] = field(default_factory=dict)
    buckets: dict[str, list[ThreatFinding]] = field(default_factory=dict)
    recon: ReconReport | None = None
    injection_hits: list[InjectionHit] = field(default_factory=list)
    memory_ingested: int = 0
    memory_detail: str = ""
    budget: dict[str, Any] = field(default_factory=dict)
    # Adversarial self-verification verdicts (finding_id -> confirmed|rejected).
    self_check: dict[str, str] = field(default_factory=dict)
    # Transparent triage ranking (finding_id -> {"score", "components"}).
    priorities: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Operator feedback loaded from <target>/.arbalest/dispositions.json.
    dispositions: dict[str, str] = field(default_factory=dict)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            key = str(finding.severity).lower()
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def agent_errors(self) -> dict[str, str]:
        return {
            name: stat.detail or f"required specialist {stat.status}"
            for name, stat in self.stats.items()
            if stat.required and stat.status != "ok"
        }

    @property
    def complete(self) -> bool:
        collection_complete = self.recon is None or self.recon.collection_complete
        return collection_complete and not self.agent_errors

    @property
    def status(self) -> str:
        return "complete" if self.complete else "incomplete"


async def run_agent_swarm(
    provider: Any,
    sources: dict[str, str],
    recon: ReconReport | None = None,
    *,
    ui: Any = None,
    on_phase: Callable[[str, list[ThreatFinding]], None] | None = None,
    ledger: MissionLedger | None = None,
    options: ScanOptions | None = None,
    checkpoint_dir: str | Path | None = None,
    resume: bool = False,
) -> SwarmResult:
    """Run bounded parallel specialists, then threat RAG.

    Checkpoints store sanitized findings/coverage, never source bodies or provider
    credentials. Resume rejects changed source/options/provider/recon/capabilities.
    Its wall-clock deadline includes downtime; reservations survive interruptions.
    The caller retains ownership of the provider and its network resources.
    """
    try:
        taint_module = importlib.import_module("engine.services.taint_analysis")
    except ModuleNotFoundError as exc:
        if exc.name != "engine.services.taint_analysis":
            raise
        taint_module = None
    workflow = ScanWorkflow(
        provider, sources, options if options is not None else ScanOptions(), checkpoint_dir, resume,
        context={
            "recon": recon.summary() if recon else None,
            "taint_available": taint_module is not None,
            "semgrep_config": os.environ.get("ARBALEST_SEMGREP_CONFIG", ""),
            "semgrep_available": SemgrepAgent().available,
            "sast_max_total_chars": os.environ.get("ARBALEST_SAST_MAX_TOTAL_CHARS", ""),
        },
    )
    try:
        result = await _run_agent_swarm(
            workflow, sources, recon, ui=ui, on_phase=on_phase, ledger=ledger, taint_module=taint_module,
        )
        result.budget = workflow.budget_summary
        return result
    finally:
        workflow.close()


async def _run_agent_swarm(
    workflow: ScanWorkflow,
    sources: dict[str, str],
    recon: ReconReport | None,
    *,
    ui: Any,
    on_phase: Callable[[str, list[ThreatFinding]], None] | None,
    ledger: MissionLedger | None,
    taint_module: Any,
) -> SwarmResult:
    provider = workflow.provider
    result = SwarmResult(recon=recon)

    for path, content in sources.items():
        for hit in scan_untrusted(content, origin=path):
            result.injection_hits.append(hit)
            if ledger is not None:
                ledger.record(
                    actor="harness.injection_defense",
                    action="detect_injection",
                    verdict="detected",
                    detail=f"{hit.rule} @ {path}: {hit.excerpt}",
                )
    if result.injection_hits:
        logger.warning("Detected %d prompt-injection signature(s); model inputs are fenced", len(result.injection_hits))
        if ui is not None:
            ui.note(
                f"PROMPT-INJECTION DEFENSE — {len(result.injection_hits)} hostile signature(s) "
                "detected in scanned sources; model inputs are fenced"
            )

    coverage_getters: dict[str, Callable[[], Any]] = {}

    def _coverage_data(coverage: Any) -> dict[str, Any]:
        if hasattr(coverage, "as_dict"):
            return coverage.as_dict()
        if is_dataclass(coverage) and not isinstance(coverage, type):
            return asdict(coverage)
        return dict(coverage)

    async def _phase(
        bucket: str,
        header: tuple[int, int, str, str] | None,
        text: str,
        operation: Callable[[], Awaitable[PhaseResult]],
        *,
        dependency: str | None = None,
    ) -> PhaseResult:
        async def execute() -> PhaseResult:
            if header and ui is not None:
                ui.phase(*header)
            # Rich's live spinners cannot safely overlap. Keep them in serial mode.
            ctx = ui.spinner(text) if ui is not None and workflow.options.concurrency == 1 else _null_ctx()
            with ctx:
                return await operation()

        def coverage_on_failure() -> dict[str, Any] | None:
            getter = coverage_getters.get(bucket)
            coverage = getter() if getter is not None else None
            return _coverage_data(coverage) if coverage is not None else None

        return await workflow.run_phase(
            bucket, execute, dependency=dependency, coverage_getter=coverage_on_failure,
        )

    def _covered(findings: list[ThreatFinding], coverage: Any) -> PhaseResult:
        data = _coverage_data(coverage)
        complete = coverage.complete if hasattr(coverage, "complete") else data.get("complete", False)
        detail = str(getattr(coverage, "detail", data.get("detail", "coverage incomplete")))
        return PhaseResult(findings, "ok" if complete else "partial", "" if complete else detail, coverage=data)

    async def _sast() -> PhaseResult:
        agent = SastAgent(
            provider, concurrency=workflow.options.concurrency, model_override=model_for("sast"),
        )
        coverage_getters["sast"] = lambda: getattr(agent, "coverage", None)
        review_priorities: list[str] | None = None
        if getattr(workflow.options, "review_hypotheses", False):
            # One bounded, failure-tolerant model call: target-specific review
            # priorities derived from what recon actually observed.
            try:
                review_priorities = await HypothesisAgent(
                    provider, model_override=model_for("hypotheses"),
                ).generate(recon.summary() if recon is not None else {})
            except Exception as exc:  # noqa: BLE001 - optional enhancement, never fatal
                logger.warning("review-hypothesis generation failed; continuing with standard instructions: %s", exc)
                review_priorities = None
        known_patterns: list[str] | None = None
        if recon is not None and recon.root_path:
            try:
                known_patterns = known_antibody_patterns(Path(recon.root_path))
            except Exception:  # noqa: BLE001 - learning memory is advisory, never fatal
                known_patterns = None
        if review_priorities and known_patterns:
            analysis = await agent.analyze(
                sources, review_priorities=review_priorities, known_patterns=known_patterns,
            )
        elif review_priorities:
            analysis = await agent.analyze(sources, review_priorities=review_priorities)
        elif known_patterns:
            analysis = await agent.analyze(sources, known_patterns=known_patterns)
        else:
            analysis = await agent.analyze(sources)
        if getattr(workflow.options, "sast_self_check", False) and analysis:
            # Adversarial self-verification annotates findings; it never
            # deletes them, and any failure leaves the findings untouched.
            try:
                verdicts = await FindingVerifier(
                    provider, model_override=model_for("verify"),
                ).verify(analysis, sources)
            except Exception as exc:  # noqa: BLE001 - optional enhancement, never fatal
                logger.warning("finding self-verification failed; keeping all findings: %s", exc)
                verdicts = {}
            for finding in analysis:
                verdict = verdicts.get(finding.finding_id)
                if verdict == "confirmed":
                    finding.evidence.append("self-check: confirmed by adversarial re-review")
                elif verdict == "rejected":
                    finding.evidence.append(
                        "self-check rejected by adversarial re-review — verify manually before acting"
                    )
                if verdict is not None:
                    result.self_check[finding.finding_id] = verdict
        return _covered(analysis, agent.coverage)

    async def _secrets() -> PhaseResult:
        return PhaseResult(await SecretScannerAgent().analyze(sources))

    async def _semgrep() -> PhaseResult:
        agent = SemgrepAgent()
        if not agent.available:
            return PhaseResult(status="skipped", required=False, detail=(
                "optional capability unavailable: install Semgrep and configure ARBALEST_SEMGREP_CONFIG"
            ))
        return PhaseResult(await agent.analyze(sources))

    async def _sca() -> PhaseResult:
        agent = ScaAgent(provider)
        coverage_getters["sca"] = lambda: getattr(agent, "coverage", None)
        try:
            return _covered(await agent.analyze(sources), agent.coverage)
        finally:
            await agent.aclose()

    async def _taint() -> PhaseResult:
        coverage_getters["taint"] = lambda: {
            "complete": False, "detail": "taint analysis did not complete",
        }
        workflow.remaining()
        analyze = taint_module.analyze_taint
        if inspect.iscoroutinefunction(analyze):
            analysis = await analyze(sources)
        else:
            # Keep CPU-bound analysis off the loop. Cancellation stops awaiting,
            # not the thread: it can finish later (and delay executor shutdown),
            # but receives no workflow/checkpoint access. Hard CPU termination
            # requires process isolation rather than asyncio's thread executor.
            analysis = await asyncio.to_thread(analyze, dict(sources))
        workflow.remaining()  # Never accept late findings or completed coverage.
        coverage_getters["taint"] = lambda: analysis.coverage
        return _covered(list(analysis.findings), analysis.coverage)

    phases = [
        ("sast", (2, 4, "AST SCAN PHASE", "🛡"), "SAST — parsing control flow & logic", _sast),
        ("secrets", None, "SECRET SWEEP — local credential detection", _secrets),
        ("semgrep", None, "SEMGREP — deterministic rule analysis", _semgrep),
        ("sca", (3, 4, "DEPENDENCY CHECK", "🧬"), "SCA — querying authoritative advisories", _sca),
    ]
    if taint_module is not None:
        phases.append(("taint", None, "TAINT — deterministic source-to-sink analysis", _taint))

    def _collect(bucket: str, phase: PhaseResult) -> None:
        stat = AgentStat(bucket, phase.status, len(phase.findings), phase.detail, phase.required, phase.coverage)
        result.stats[bucket] = stat
        result.buckets[bucket] = phase.findings
        result.findings.extend(phase.findings)
        if stat.status not in {"ok", "skipped"} and ui is not None:
            ui.error(f"{bucket.upper()} INCOMPLETE — {stat.detail}")
        elif stat.status == "ok" and on_phase is not None:
            on_phase(bucket, phase.findings)

    # TaskGroup cancels and joins siblings on checkpoint failure/cancellation;
    # no phase coroutine may write after lock release. Merge in stable order.
    async with asyncio.TaskGroup() as group:
        tasks = [group.create_task(_phase(*phase)) for phase in phases]
    for phase, task in zip(phases, tasks):
        _collect(phase[0], task.result())

    async def _threat_rag() -> PhaseResult:
        discovery = RouteDiscovery(
            target_url=_LOCAL_SCAN_TARGET,
            routes=[],
            scan_notes=[f"static-scan:{name}" for name in (recon.entrypoints if recon else [])],
        )
        graph_context = build_file_graph(
            "local-scan", sources,
            prioritize=[node for finding in result.findings for node in finding.affected_nodes],
            entrypoints=recon.entrypoints if recon else (),
        )
        tavily = TavilyIntelClient.from_env()
        rag = ThreatIntelRAG(provider=provider, tavily=tavily, model_override=model_for("rag"))
        try:
            return PhaseResult(await rag.analyze(
                discovery=discovery,
                graph_context=graph_context,
                legacy_sources=sources,
                prior_findings=tuple(result.findings),
            ))
        finally:
            await rag.aclose()

    _collect("threat_rag", await _phase(
        "threat_rag", (4, 4, "THREAT RAG", "🧠"), "THREAT RAG — correlating verified evidence",
        _threat_rag, dependency=workflow.phase_fingerprint([phase[0] for phase in phases]),
    ))

    deduplicated: list[ThreatFinding] = []
    seen_findings: set[tuple[str, str, tuple[str, ...]]] = set()
    seen_ids: set[str] = set()
    accepted: list[tuple[frozenset[str], str, tuple[str, ...]]] = []
    for finding in result.findings:
        # finding_id is the content-hash identity: two findings sharing it are
        # the same discovery (e.g. THREAT RAG restating a SAST finding with
        # its own wording), not two vulnerabilities.
        if finding.finding_id in seen_ids:
            continue
        normalized_summary = " ".join(finding.summary.lower().split())
        key = (finding.cwe.upper(), normalized_summary, tuple(sorted(finding.affected_nodes)))
        if key in seen_findings:
            continue
        # Cross-agent restatement: same CWE in the same file(s) with a
        # near-identical summary but a freshly minted id collapses to the
        # first (specialist) report. Distinct findings in the same file
        # stay separate because their summaries diverge.
        tokens = _summary_tokens(finding.summary)
        nodes = tuple(sorted(finding.affected_nodes))
        duplicate = False
        for prior_tokens, prior_cwe, prior_nodes in accepted:
            if prior_cwe == finding.cwe.upper() and prior_nodes == nodes:
                overlap = len(tokens & prior_tokens)
                if overlap and overlap / len(tokens | prior_tokens) >= 0.5:
                    duplicate = True
                    break
        if duplicate:
            continue
        seen_ids.add(finding.finding_id)
        seen_findings.add(key)
        accepted.append((tokens, finding.cwe.upper(), nodes))
        deduplicated.append(finding)
    result.findings = deduplicated

    # Transparent triage ranking: severity fused with public-surface exposure,
    # untrusted-source evidence and the adversarial self-check verdict. The
    # exit gate still counts severities; this only orders and explains.
    entrypoint_files = set(recon.entrypoints) if recon is not None else set()
    operator_dispositions: dict[str, dict[str, Any]] = {}
    if recon is not None and recon.root_path:
        try:
            operator_dispositions = load_dispositions(Path(recon.root_path))
        except Exception:  # noqa: BLE001 - feedback memory is advisory, never fatal
            operator_dispositions = {}
    _untrusted_hint = re.compile(r"request|user|client|param|token|input|cookie|header", re.I)
    _priority_base = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0}
    for finding in result.findings:
        components: dict[str, Any] = {"severity": _priority_base.get(str(finding.severity).lower(), 1.0)}
        if entrypoint_files.intersection(finding.affected_nodes):
            components["public_surface"] = 1.5
        searchable = finding.summary + " " + " ".join(finding.evidence)
        if _untrusted_hint.search(searchable):
            components["untrusted_source_evidence"] = 1.0
        verdict = result.self_check.get(finding.finding_id)
        if verdict == "confirmed":
            components["self_check_confirmed"] = 1.0
        elif verdict == "rejected":
            components["self_check_rejected"] = -2.0
        disposition = operator_dispositions.get(finding.finding_id)
        if disposition:
            components[f"operator_{disposition['verdict'].replace('-', '_')}"] = -2.5
            finding.evidence.append(
                f"operator marked this finding {disposition['verdict']} "
                f"on {str(disposition.get('updated_utc', ''))[:10]} — likely noise, verify before acting"
            )
            result.dispositions[finding.finding_id] = disposition["verdict"]
        score = max(0.0, min(10.0, sum(components.values())))
        result.priorities[finding.finding_id] = {"score": round(score, 1), "components": components}
    result.findings.sort(
        key=lambda finding: (
            -result.priorities.get(finding.finding_id, {}).get("score", 0.0),
            _SEV_SORT.get(str(finding.severity).lower(), 5),
            str(finding.affected_nodes[0]) if finding.affected_nodes else "",
        )
    )

    if result.complete:
        try:
            memory = get_vector_memory(Path(recon.root_path) if recon and recon.root_path else None)
            for finding in result.findings:
                if finding.cwe == "CWE-798" or finding.finding_id.startswith("SECRET-"):
                    continue
                context = "; ".join(finding.evidence[:3])[:1_000]
                async with asyncio.timeout(min(workflow.remaining(), workflow.options.call_timeout_seconds)):
                    if await memory.ingest_finding(finding.finding_id, finding.summary[:1_000], context):
                        result.memory_ingested += 1
        except Exception as exc:
            result.memory_detail = f"local memory unavailable: {type(exc).__name__}"
            logger.warning("Optional local memory ingestion failed: %s", exc)
    return result
