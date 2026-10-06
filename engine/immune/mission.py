"""Immune System mission — the full autonomous flow.

    [1/3] BLAST RADIUS   — deterministic detection + topological exploitability proof
    [2/3] WARGAME        — Architect vs Red Team minimax loop in the Nebius sandbox
    [3/3] ANTIBODY       — self-tested Semgrep rule synthesized from real breaches

Stage 1 is fully deterministic (no AI core required). Stages 2-3 are real
LLM + sandbox operations and require an armed provider and Docker.
"""

from __future__ import annotations

import difflib
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from engine.agents.immune_system_agent import ImmuneSystemAgent
from engine.agents.red_team_swarm import RedTeamResult
from engine.immune.antibody import Antibody, AntibodyError, AntibodyLab, antibody_sweep, load_antibodies
from engine.immune.detection import DetectionFinding, sweep_sources
from engine.immune.topology import BlastRadius, TopologyMapper
from engine.immune.wargame import WargameEngine, WargameResult, finding_from_detection
from engine.services.graph_manager import GraphManager
from engine.services.source_collector import run_recon
from engine.ui.terminal import (
    BLOOD_RED,
    ELECTRIC_PURPLE,
    EMERALD,
    GRAY,
    LOGO,
    NEON_ORANGE,
    Console,
    palette,
    severity_tag,
    WHITE,
)

EXIT_IMMUNE = 0
EXIT_VULNERABLE = 1
EXIT_MISSION_ERROR = 2

ProviderFactory = Callable[[], object]
SandboxFactory = Callable[[], object]


@dataclass
class MissionTarget:
    finding: DetectionFinding
    radius: BlastRadius
    wargame: WargameResult | None = None
    antibody: Antibody | None = None
    applied_files: list[str] = field(default_factory=list)

    @property
    def resolved(self) -> bool:
        return bool(self.wargame and self.wargame.resolved)


async def run_immune_mission(
    console: Console,
    target: Path,
    *,
    provider_factory: ProviderFactory,
    sandbox_factory: SandboxFactory,
    max_iterations: int = 4,
    max_findings: int = 3,
    use_sandbox: bool = True,
) -> int:
    """Execute the Immune System mission and return the exit code."""
    t0 = time.perf_counter()
    run_id = uuid.uuid4().hex[:12]

    # ── HERO ──────────────────────────────────────────────────────────────
    for row in LOGO:
        console.line(row, ELECTRIC_PURPLE, bold=True)
    console.print()
    console.line("IMMUNE SYSTEM MODE — TOPOLOGICAL ▸ ADVERSARIAL ▸ SELF-LEARNING", ELECTRIC_PURPLE, bold=True)
    console.rule()
    console.kv("RUN ID", run_id, GRAY)
    console.kv("ORGANISM", str(target))
    console.kv("DOCTRINE", "The codebase is a living organism; Arbalest is the swarm of antibodies.", ELECTRIC_PURPLE)
    console.rule()

    if not target.exists() or not target.is_dir():
        console.error(f"ORGANISM REJECTED — not a directory: {target}")
        return EXIT_MISSION_ERROR

    with console.spinner("SENSING — indexing organism"):
        recon = run_recon(target)
    if not recon.files:
        console.error("No source files — nothing to defend.")
        return EXIT_MISSION_ERROR

    # ── [1/3] BLAST RADIUS (deterministic — no AI core required) ──────────
    console.phase(1, 3, "TOPOLOGICAL BLAST-RADIUS MAPPING", "🕸")
    antibodies = load_antibodies(target)
    if antibodies:
        console.success(f"{len(antibodies)} learned antibody(ies) re-armed into the sweep")
    findings: list[DetectionFinding] = sweep_sources(recon.files)
    antibody_hits: list[DetectionFinding] = []
    for rel, content in recon.files.items():
        antibody_hits.extend(antibody_sweep(rel, content, antibodies))
    findings.extend(antibody_hits)
    findings.sort(key=lambda f: f.sort_key)

    if not findings:
        console.success("ORGANISM HEALTHY — no live sinks detected.")
        console.verdict({}, 0, EXIT_IMMUNE, None, time.perf_counter() - t0)
        return EXIT_IMMUNE

    learned_count = sum(1 for f in findings if f.learned)
    console.kv("LIVE SINKS", str(len(findings)), NEON_ORANGE)
    if learned_count:
        console.kv("RECOGNIZED BY ANTIBODIES", str(learned_count), EMERALD)

    mapper = TopologyMapper(recon.files)
    console.kv("TOPOLOGY", f"{len(mapper._funcs)} nodes · {len(mapper._edges)} call edges"
               + (f" · capped ({mapper.truncated_nodes}/{mapper.truncated_edges} truncated)" if mapper.truncated_nodes or mapper.truncated_edges else ""),
               ELECTRIC_PURPLE)
    for err in mapper.parse_errors[:3]:
        console.note(f"unparsable: {err}")

    traces: list[MissionTarget] = []
    for finding in findings[: max_findings * 4]:
        radius = mapper.trace(finding)
        traces.append(MissionTarget(finding=finding, radius=radius))

    proven = [t for t in traces if t.radius.proven]
    isolated = [t for t in traces if not t.radius.proven]
    targets = (proven + isolated)[:max_findings]

    for mission_target in targets:
        _render_trace(console, mission_target)

    # ── Arm the AI core (real) ────────────────────────────────────────────
    try:
        provider = provider_factory()
    except RuntimeError as exc:
        console.rule()
        console.error(f"AI CORE NOT ARMED — {exc}")
        console.line("  Stage 1 intelligence above is real. Adversarial war-gaming requires a live model.",
                     ELECTRIC_PURPLE)
        return EXIT_MISSION_ERROR

    sandbox = sandbox_factory()
    if use_sandbox:
        try:
            with console.spinner("CRUCIBLE — negotiating with the Nebius Token Factory Sandbox"):
                await sandbox.healthcheck()
            console.success("Nebius Token Factory Sandbox — ranges hot.")
        except Exception as exc:  # noqa: BLE001
            console.error(f"Nebius Token Factory Sandbox unreachable: {exc}")
            console.line("  The Crucible refuses to certify a patch it never burned. No verification, no deployment.",
                         BLOOD_RED)
            return EXIT_MISSION_ERROR

    # ── [2/3] WARGAME ─────────────────────────────────────────────────────
    console.phase(2, 3, "ADVERSARIAL WAR-GAMING (MINIMAX LOOP)", "⚔️")
    lab = AntibodyLab(provider=provider, root=target)

    for mission_target in targets:
        tf = finding_from_detection(mission_target.finding, mission_target.radius.summary())
        readout = _new_readout(console, mission_target)
        engine = WargameEngine(
            provider=provider, sandbox=sandbox, max_iterations=max_iterations,
            left_log=readout.left, right_log=readout.right,
        )
        readout.open(f"Iteration: ARCHITECT-01 vs REDTEAM-SWARM — {mission_target.finding.cwe} @ {mission_target.finding.file}")
        try:
            wargame = await engine.run(recon.files, tf)
        except Exception as exc:  # noqa: BLE001 — war-game failure is per-target, not fatal
            console.error(f"WARGAME ABORTED for {mission_target.finding.rule_id}: {exc}")
            mission_target.wargame = WargameResult(resolved=False)
        else:
            mission_target.wargame = wargame
            if wargame.resolved:
                _render_resolution(console, mission_target)
        finally:
            await readout.close()

    # ── [3/3] ANTIBODY ────────────────────────────────────────────────────
    console.phase(3, 3, "ANTIBODY GENERATION (SELF-LEARNING)", "🧬")
    for mission_target in targets:
        wargame = mission_target.wargame
        if not (wargame and wargame.resolved and wargame.final_bundle and wargame.breach_history):
            continue
        try:
            antibody = await lab.synthesize(
                finding=mission_target.finding,
                vulnerable_code=recon.files.get(mission_target.finding.file, ""),
                patched_code=wargame.final_bundle.file_mapping().get(mission_target.finding.file, ""),
                breach_history=wargame.breach_history,
            )
        except AntibodyError as exc:
            console.note(f"antibody synthesis failed for {mission_target.finding.rule_id}: {exc}")
            continue
        mission_target.antibody = antibody
        console.line(f"  🧬 {antibody.rule_id}", EMERALD, bold=True)
        console.kv("SELF-TEST", antibody.validation_detail,
                   EMERALD if antibody.validated else NEON_ORANGE)
        lab.registry.save(antibody)
        console.kv("MEMORY", antibody.path, GRAY)
        await _learn_graph_pattern(console, target, wargame, recon.files.get(mission_target.finding.file, ""),
                                   mission_target.finding)

    # ── Deploy surviving patches (real writes, real diffs) ────────────────
    deployed = 0
    for mission_target in targets:
        wargame = mission_target.wargame
        if wargame and wargame.resolved and wargame.final_bundle:
            deployed += _deploy(console, target, mission_target)

    # ── FINAL DEBRIEF ─────────────────────────────────────────────────────
    console.section("FINAL DEBRIEF — IMMUNE RESPONSE RECORD")
    rows = []
    for t in targets:
        rows.append([
            severity_tag(t.finding.severity),
            f"{t.finding.name[:36]}",
            f"{t.finding.file}:{t.finding.line}",
            "PROVEN" if t.radius.proven else "ISOLATED",
            str(len(t.wargame.iterations)) if t.wargame else "—",
            "HEALED" if t.resolved else "UNRESOLVED",
            ("✓ " + (t.antibody.rule_id if t.antibody else "—")) if t.resolved else "—",
        ])
    console.table(["SEV", "SINK", "LOCATION", "CHAIN", "ITERS", "VERDICT", "ANTIBODY"], rows, max_col=34)
    resolved = sum(1 for t in targets if t.resolved)
    counts: dict[str, int] = {}
    for t in targets:
        if not t.resolved:
            key = t.finding.severity
            counts[key] = counts.get(key, 0) + 1
    exit_code = EXIT_IMMUNE if resolved == len(targets) else EXIT_VULNERABLE
    console.verdict(counts, len(targets) - resolved, exit_code, None, time.perf_counter() - t0)
    return exit_code


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def _render_trace(console: Console, t: MissionTarget) -> None:
    finding, radius = t.finding, t.radius
    console.line(f"  ⚠ SINK {severity_tag(finding.severity)} {finding.name} ", NEON_ORANGE, bold=True)
    console.kv("LOCATION", f"{finding.file}:{finding.line}", GRAY)
    console.kv("EVIDENCE", finding.evidence[:90], GRAY)
    if radius.chains:
        for chain in radius.chains:
            hops = []
            for hop in chain:
                label = hop["route"] if hop.get("route") else str(hop["name"])
                marker = " 💥" if hop is chain[-1] else ""
                hops.append(f"{palette(str(label), WHITE)} ({palette(str(hop['file']) + ':' + str(hop['line']), GRAY)}){marker}")
            console.line("  " + palette(" ⚭ ", ELECTRIC_PURPLE, bold=True).join(hops), ELECTRIC_PURPLE)
    color = ELECTRIC_PURPLE if radius.proven else GRAY
    console.line(f"  ⛓ {radius.verdict}", color, bold=True)
    if radius.downstream:
        console.kv("BLAST RADIUS", f"{len(radius.downstream)} downstream call(s) across "
                   f"{len(radius.downstream_files)} file(s)", ELECTRIC_PURPLE)
    if radius.roots:
        console.kv("INTERNAL ROOTS", "; ".join(radius.roots[:3]), GRAY)


def _new_readout(console: Console, t: MissionTarget) -> object:
    from engine.immune.readout import WargameReadout

    title = f"Iteration: ARCHITECT-01 vs REDTEAM-SWARM — {t.finding.cwe} @ {t.finding.file}"
    return WargameReadout(console, title=title)


def _render_resolution(console: Console, t: MissionTarget) -> None:
    wargame = t.wargame
    assert wargame is not None
    last = wargame.last_result
    console.line(
        f"  ✚ {t.finding.cwe} RESOLVED after {len(wargame.iterations)} iteration(s) — "
        f"patch held ({last.sandbox.status.value if last else 'sandbox'})",
        EMERALD, bold=True,
    )


def _deploy(console: Console, target: Path, t: MissionTarget) -> int:
    """Write the surviving bundle into the organism (guarded to the root)."""
    wargame = t.wargame
    assert wargame is not None and wargame.final_bundle is not None
    root = target.resolve()
    written = 0
    for generated in wargame.final_bundle.files:
        dest = (root / generated.path).resolve()
        if not dest.is_relative_to(root):
            console.note(f"refusing out-of-tree path from bundle: {generated.path}")
            continue
        original = recon_read(root, generated.path)
        if original is not None and original != generated.content:
            for line in _diff_lines(original, generated.content, generated.path):
                console.line(line)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(generated.content, encoding="utf-8")
        t.applied_files.append(generated.path)
        written += 1
    if written:
        console.success(f"deployed {written} healed file(s) into the organism")
    return written


def recon_read(root: Path, rel: str) -> str | None:
    path = (root / rel).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="ignore")


def _diff_lines(original: str, updated: str, rel: str) -> list[str]:
    out = [palette(f"  ⚡ real-time diff — {rel}", ELECTRIC_PURPLE, bold=True)]
    for line in difflib.unified_diff(
        original.splitlines(), updated.splitlines(),
        fromfile=f"a/{rel}", tofile=f"b/{rel} (HEALED)", lineterm="", n=2,
    ):
        if line.startswith("+") and not line.startswith("+++"):
            out.append(palette("  " + line, EMERALD))
        elif line.startswith("-") and not line.startswith("---"):
            out.append(palette("  " + line, NEON_ORANGE))
        elif line.startswith(("@", "+++ ---")):
            out.append(palette("  " + line, GRAY))
    return out


async def _learn_graph_pattern(
    console: Console, target: Path, wargame: WargameResult, original_code: str, finding: DetectionFinding
) -> None:
    """Optional Neo4j graph memory via the real ImmuneSystemAgent."""
    breach: RedTeamResult | None = wargame.last_breach
    if breach is None:
        return
    if not _graph_configured():
        console.kv("GRAPH MEMORY", "offline — local antibody registry is the source of truth", GRAY)
        return
    provider, _model = provider_for_graph()
    if provider is None:
        console.kv("GRAPH MEMORY", "offline — no AI core for pattern synthesis", GRAY)
        return
    graph = GraphManager()
    try:
        await graph.connect()
        agent = ImmuneSystemAgent(provider=provider, graph_manager=graph)
        pattern = await agent.synthesize_threat(
            project_id=f"immune-{target.name}", red_team_result=breach, original_code=original_code,
        )
        console.kv("GRAPH MEMORY", f"learned pattern {pattern.threat_name} ({pattern.cwe_category})", ELECTRIC_PURPLE)
    except Exception as exc:  # noqa: BLE001
        console.note(f"graph memory write failed: {exc}")
    finally:
        try:
            await graph.close()
        except Exception:  # noqa: BLE001
            pass


def _graph_configured() -> bool:
    import os

    return bool(os.environ.get("NEO4J_URI"))


def provider_for_graph():
    """Best-effort real provider for graph-memory synthesis; None when unarmed."""
    import os

    from engine.services.ai_provider import AIProviderSettings, create_ai_provider

    key = os.environ.get("AI_API_KEY", "").strip()
    if not key:
        return None, ""
    settings = AIProviderSettings(provider=os.environ.get("ARBALEST_PROVIDER", "custom"),
                                  api_key=key, selected_model=os.environ.get("ARBALEST_MODEL"))
    try:
        return create_ai_provider(settings), settings.selected_model
    except Exception:  # noqa: BLE001
        return None, ""
