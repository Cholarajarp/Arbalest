"""Shared agent-swarm scan pipeline.

One scan core for the CLI and the MCP server: SAST + Secret sweep (AST phase),
SCA (dependency check), and Threat Intel RAG. Degrades per-agent so one failed
specialist never aborts the mission. Every agent is real and requires a live
AI provider.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from engine.agents.sast_agent import SastAgent
from engine.agents.sca_agent import ScaAgent
from engine.agents.secret_scanner import SecretScannerAgent
from engine.agents.threat_intel_rag import ThreatIntelRAG
from engine.agents.black_box_fuzzer import RouteDiscovery
from engine.agents.architect_agent import ArchitectureGraphContext, ThreatFinding
from engine.services.source_collector import ReconReport
from engine.services.tavily_intel import TavilyIntelClient
from engine.harness.injection_defense import InjectionHit, scan_untrusted
from engine.harness.mission_ledger import MissionLedger

logger = logging.getLogger("arbalest.pipeline")

_LOCAL_SCAN_TARGET = "local-scan.internal"

_SEV_SORT = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class _null_ctx:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@dataclass
class AgentStat:
    name: str
    status: str = "ok"           # ok | error
    count: int = 0
    detail: str = ""

    def as_dict(self) -> dict[str, str | int]:
        return {"status": self.status, "count": self.count, "detail": self.detail}


@dataclass
class SwarmResult:
    findings: list[ThreatFinding] = field(default_factory=list)
    stats: dict[str, AgentStat] = field(default_factory=dict)
    buckets: dict[str, list[ThreatFinding]] = field(default_factory=dict)
    recon: ReconReport | None = None
    injection_hits: list[InjectionHit] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            key = str(f.severity).lower()
            counts[key] = counts.get(key, 0) + 1
        return counts


async def run_agent_swarm(
    provider,
    sources: dict[str, str],
    recon: ReconReport | None = None,
    *,
    ui=None,
    on_phase: Callable[[str, list[ThreatFinding]], None] | None = None,
    ledger: MissionLedger | None = None,
) -> SwarmResult:
    """Execute the analysis swarm.

    ui — optional Console: renders [2/4]..[4/4] phase headers and spinners.
    on_phase — optional callback(bucket_name, findings) invoked after each
    phase completes so the caller can render structured tables in-stream.
    ledger — optional mission ledger; injection defenses are audited into it.
    """
    result = SwarmResult(recon=recon)

    # -- HARNESS: scanned sources are hostile — detect injection payloads ----
    for path, content in sources.items():
        for hit in scan_untrusted(content, origin=path):
            result.injection_hits.append(hit)
            logger.warning("Harness: injection attempt in %s (%s): %s", path, hit.rule, hit.excerpt)
            if ledger is not None:
                ledger.record(
                    actor="harness.injection_defense",
                    action="neutralize_injection",
                    verdict="logged",
                    detail=f"{hit.rule} @ {path}: {hit.excerpt}",
                )
    if result.injection_hits:
        logger.warning(
            "Harness: %d injection attempt(s) detected in scanned sources; content was data-only",
            len(result.injection_hits),
        )

    async def _phase(bucket: str, header: tuple[int, int, str, str] | None, text: str, coro):
        if header and ui is not None:
            ui.phase(*header)
        stat = AgentStat(bucket)
        try:
            ctx = ui.spinner(text) if ui is not None else _null_ctx()
            with ctx:
                findings = await coro
            result.findings.extend(findings)
            result.buckets[bucket] = findings
            stat.count = len(findings)
        except Exception as exc:  # noqa: BLE001 — specialist failure ≠ mission failure
            result.buckets[bucket] = []
            stat.status, stat.detail = "error", str(exc)
            logger.warning("%s agent failed: %s", bucket, exc)
        result.stats[bucket] = stat
        if on_phase is not None:
            on_phase(bucket, result.buckets[bucket])

    # -- [2/4] AST SCAN — SAST + secret sweep --------------------------------
    await _phase(
        "sast", (2, 4, "AST SCAN PHASE", "🛡"), "SAST — parsing control flow & logic",
        SastAgent(provider).analyze(sources),
    )
    await _phase(
        "secrets", None, "SECRET SWEEP — hunting leaked credentials",
        SecretScannerAgent(provider).analyze(sources),
    )

    # -- [3/4] DEPENDENCY CHECK — SCA ----------------------------------------
    await _phase(
        "sca", (3, 4, "DEPENDENCY CHECK", "🧬"), "SCA — cross-referencing dependency advisories",
        ScaAgent(provider).analyze(sources),
    )

    # -- [4/4] THREAT RAG — correlate with intel corpus + live Tavily intel ---
    async def _threat_rag():
        discovery = RouteDiscovery(
            target_url=_LOCAL_SCAN_TARGET,
            routes=[],
            scan_notes=[f"static-scan:{n}" for n in (recon.entrypoints if recon else [])],
        )
        graph_context = ArchitectureGraphContext(project_id="local-scan", nodes=[], edges=[])
        tavily = TavilyIntelClient.from_env()
        intel_label = "local corpus + live Tavily intel" if tavily.available else "local corpus"
        rag = ThreatIntelRAG(provider=provider, tavily=tavily)
        try:
            findings = await rag.analyze(
                discovery=discovery,
                graph_context=graph_context,
                legacy_sources=sources,
            )
            logger.info("Threat intel sources: %s (status: %s)", intel_label, tavily.last_status)
            return findings
        finally:
            await rag.aclose()

    await _phase(
        "threat_rag", (4, 4, "THREAT RAG", "🧠"), "THREAT RAG — correlating findings with intel corpus",
        _threat_rag(),
    )

    result.findings.sort(
        key=lambda f: (_SEV_SORT.get(str(f.severity).lower(), 5),
                       str(f.affected_nodes[0]) if f.affected_nodes else "")
    )
    return result
