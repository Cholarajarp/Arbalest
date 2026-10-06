"""Hive Mind mission — the organization-scale flow.

    [1/4] FEDERATED RECON        — every repository sensed; fleet-wide sink matrix
    [2/4] CROSS-REPO BLAST RADIUS— one topological map spanning microservices
    [3/4] FLEET WAR-GAMES        — parallel minimax loops in independent sandboxes,
                                   antibody broadcast + fleet re-sweep in milliseconds
    [4/4] FLEET GITOPS           — synchronized branches, commits, pull requests

Stages 1-2 are deterministic (no AI core required). Stages 3-4 require an
armed provider and Docker — the fleet never fakes a verdict.
"""

from __future__ import annotations

import asyncio
import difflib
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from engine.hive.board import FleetBoard
from engine.hive.exchange import FleetPatternExchange
from engine.hive.federation import FleetTopology
from engine.hive.fleet_commander import FleetCommanderAgent
from engine.hive.gitops import FleetGitOps
from engine.hive.registry import HiveRegistry
from engine.immune.antibody import AntibodyError, AntibodyLab, antibody_sweep, load_antibodies
from engine.immune.detection import DetectionFinding, sweep_sources
from engine.immune.wargame import WargameEngine, WargameResult, finding_from_detection
from engine.services.source_collector import collect_sources
from engine.ui.terminal import (
    BLOOD_RED,
    DIM,
    EMERALD,
    GOLD,
    GRAY,
    LOGO,
    NEON_ORANGE,
    QUANTUM_MAGENTA,
    WHITE,
    Console,
    palette,
    severity_tag,
)

EXIT_FLEET_SECURED = 0
EXIT_FLEET_VULNERABLE = 1
EXIT_MISSION_ERROR = 2

MAX_REPOS = 20


def discover_fleet(fleet_dir: Path) -> dict[str, Path]:
    """Subdirectories of *fleet_dir* that contain source code."""
    repos: dict[str, Path] = {}
    if not fleet_dir.is_dir():
        return repos
    for child in sorted(fleet_dir.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        if collect_sources(child):
            repos[child.name] = child
        if len(repos) >= MAX_REPOS:
            break
    return repos


@dataclass
class FleetTarget:
    repo: str
    finding: DetectionFinding
    radius: object = None
    wargame: WargameResult | None = None
    applied_files: list[str] = field(default_factory=list)

    @property
    def resolved(self) -> bool:
        return bool(self.wargame and self.wargame.resolved)

    @property
    def key(self) -> str:
        return f"{self.repo}:{self.finding.rule_id}"


async def run_fleet_mission(
    console: Console,
    fleet_dir: Path,
    *,
    provider_factory,
    sandbox_factory,
    max_iterations: int = 4,
    max_findings: int = 3,
    max_parallel: int = 3,
    use_sandbox: bool = True,
    gitops: bool = True,
) -> int:
    t0 = time.perf_counter()
    incident = uuid.uuid4().hex[:8]

    # ── HERO ──────────────────────────────────────────────────────────────
    for row in LOGO:
        console.line(row, QUANTUM_MAGENTA, bold=True)
    console.print()
    console.line("HIVE MIND — DISTRIBUTED THREAT INTELLIGENCE NETWORK", GOLD, bold=True)
    console.rule()
    console.kv("INCIDENT", incident, GRAY)
    console.kv("THE ORGANISM", "the organization's entire tech stack", QUANTUM_MAGENTA)
    console.rule()

    if not fleet_dir.is_dir():
        console.error(f"FLEET DIRECTORY REJECTED — not a directory: {fleet_dir}")
        return EXIT_MISSION_ERROR

    # ── [1/4] FEDERATED RECON ─────────────────────────────────────────────
    console.phase(1, 4, "FEDERATED RECON", "🌐")
    with console.spinner("FLEET SENSORS — discovering repositories"):
        repos = discover_fleet(fleet_dir)
    if not repos:
        console.error("No repositories with source code found under the fleet directory.")
        return EXIT_MISSION_ERROR

    sources_by_repo: dict[str, dict[str, str]] = {
        name: collect_sources(path) for name, path in repos.items()
    }
    total_files = sum(len(s) for s in sources_by_repo.values())
    console.kv("REPOSITORIES", f"{len(repos)} linked", QUANTUM_MAGENTA)
    console.kv("FILES UNDER WATCH", f"{total_files:,}", WHITE)

    hive = HiveRegistry(fleet_dir)
    hive_antibodies = load_antibodies(fleet_dir, directory=hive.antibody_dir)
    if hive_antibodies:
        console.kv("HIVE ANTIBODIES", f"{len(hive_antibodies)} broadcast signature(s) re-armed", GOLD)

    findings_by_repo: dict[str, list[DetectionFinding]] = {}
    with console.spinner("SWEEP — deterministic tripwire across every repository"):
        for name, sources in sources_by_repo.items():
            hits = sweep_sources(sources)
            for rel, content in sources.items():
                hits.extend(antibody_sweep(rel, content, hive_antibodies))
            hits.sort(key=lambda f: f.sort_key)
            findings_by_repo[name] = hits

    for name in sorted(findings_by_repo):
        count = len(findings_by_repo[name])
        console.line(
            f"  ⬡ {name:<26} "
            + palette(f"{count} live sink(s)", NEON_ORANGE if count else EMERALD, bold=True)
        )

    all_findings = [(repo, f) for repo, hits in findings_by_repo.items() for f in hits]
    if not all_findings:
        console.success("FLEET HEALTHY — no live sinks anywhere in the organization.")
        console.verdict({}, 0, EXIT_FLEET_SECURED, None, time.perf_counter() - t0)
        return EXIT_FLEET_SECURED

    # ── [2/4] CROSS-REPO BLAST RADIUS ─────────────────────────────────────
    console.phase(2, 4, "CROSS-REPO BLAST RADIUS", "🕸")
    with console.spinner("FEDERATION — stitching repository topologies"):
        topology = FleetTopology(sources_by_repo)
    console.kv(
        "FEDERATED GRAPH",
        f"{len(topology._funcs)} nodes · {sum(len(v) for v in topology._forward.values())} call edges · "
        f"{len(topology.cross_edges)} cross-repo link(s)",
        QUANTUM_MAGENTA,
    )
    if topology.truncated:
        console.note(f"graph capped — {topology.truncated} element(s) truncated")

    candidates = sorted(all_findings, key=lambda rf: rf[1].sort_key)[: max_findings * 3]
    traced: list[FleetTarget] = []
    for repo, finding in candidates:
        traced.append(FleetTarget(repo=repo, finding=finding, radius=topology.trace(repo, finding)))
    traced.sort(key=lambda t: (not t.radius.proven, t.finding.sort_key))
    targets = traced[:max_findings]

    for target in targets:
        radius = target.radius
        console.line(f"  ⚠ SINK {severity_tag(target.finding.severity)} {target.finding.name}", NEON_ORANGE, bold=True)
        console.kv("ORIGIN", f"[{target.repo}] {target.finding.file}:{target.finding.line}", GRAY)
        for chain in radius.chains:
            hops = []
            for hop in chain:
                label = hop.get("route") or str(hop["name"])
                marker = " 💥" if hop is chain[-1] else ""
                hops.append(
                    f"{palette('[' + str(hop['repo']) + ']', QUANTUM_MAGENTA, bold=True)} "
                    f"{palette(label, WHITE)} ({palette(str(hop['file']) + ':' + str(hop['line']), GRAY)}){marker}"
                )
            console.line("  " + palette(" ⛓ ", QUANTUM_MAGENTA, bold=True).join(hops), QUANTUM_MAGENTA)
        console.line(f"  ⛓ {radius.verdict}", QUANTUM_MAGENTA if radius.proven else GRAY, bold=True)

    # ── Arm the AI core (real) ────────────────────────────────────────────
    try:
        provider = provider_factory()
    except RuntimeError as exc:
        console.rule()
        console.error(f"AI CORE NOT ARMED — {exc}")
        console.line("  Fleet detection and federated topology above are real. War-games require a live model.",
                     QUANTUM_MAGENTA)
        return EXIT_MISSION_ERROR

    # ── [3/4] FLEET WAR-GAMES + ANTIBODY BROADCAST ────────────────────────
    console.phase(3, 4, "FLEET WAR-GAMES + ANTIBODY BROADCAST", "⚔️")
    commander = FleetCommanderAgent()
    board = FleetBoard(console, rows=[t.key for t in targets])

    semaphore = asyncio.Semaphore(max(1, max_parallel))

    async def fight(target: FleetTarget) -> WargameResult | None:
        async with semaphore:
            board.update(target.repo, cwe=target.finding.cwe,
                         sink=f"{target.finding.file}:{target.finding.line}",
                         status="WARGAMING", sandbox="docker")
            try:
                sandbox = sandbox_factory()
                engine = WargameEngine(
                    provider=provider, sandbox=sandbox, max_iterations=max_iterations,
                    left_log=lambda line, _r=target.repo: console.line(f"  ▣ [{_r}] ARCH ▸ {line}", DIM),
                    right_log=lambda line, _r=target.repo: console.line(f"  ▣ [{_r}] REDTEAM ▸ {line}", BLOOD_RED),
                )
                wargame = await engine.run(
                    sources_by_repo[target.repo], finding_from_detection(target.finding),
                )
            except Exception as exc:  # noqa: BLE001 — one lost duel never aborts the fleet
                console.error(f"WARGAME FAILED [{target.repo}]: {exc}")
                board.update(target.repo, status="HELD", sandbox="docker")
                return None
            board.update(
                target.repo,
                iter=str(len(wargame.iterations)),
                status="HEALED" if wargame.resolved else "BREACHED",
                sandbox="docker",
            )
            return wargame

    for target in targets:
        plan = commander.plan_response(topology, target.repo, target.finding, target.radius, findings_by_repo)
        for order in plan.orders:
            console.line(f"  ⬡ DISPATCH [{order.kind}] {order.repo} — {order.rationale}", QUANTUM_MAGENTA)

        target.wargame = await fight(target)
        if target.resolved and target.wargame.final_bundle:
            target.applied_files = _deploy(console, repos[target.repo], target.wargame)

        downstream = [o for o in plan.orders if o.kind == "downstream" and o.finding]
        if downstream:
            outcomes = await asyncio.gather(
                *(fight(FleetTarget(repo=o.repo, finding=o.finding)) for o in downstream),
                return_exceptions=True,
            )
            for order, outcome in zip(downstream, outcomes):
                if isinstance(outcome, BaseException):
                    console.error(f"WARGAME FAILED [{order.repo}]: {outcome}")
                elif outcome and outcome.resolved and outcome.final_bundle:
                    applied_files = _deploy(console, repos[order.repo], outcome)
                    sibling = next(
                        (t for t in traced if t.repo == order.repo and t.finding.rule_id == order.finding.rule_id),
                        None,
                    )
                    if sibling is None:
                        sibling = FleetTarget(repo=order.repo, finding=order.finding, wargame=outcome,
                                              applied_files=applied_files)
                        traced.append(sibling)
                        targets.append(sibling)
                    else:
                        sibling.wargame = outcome
                        sibling.applied_files = applied_files

    # Antibody broadcast — the origin cure immunizes the entire fleet (gold).
    origin = next((t for t in targets if t.resolved and t.wargame.breach_history), None)
    if origin is not None:
        lab = AntibodyLab(provider=provider, root=repos[origin.repo])
        try:
            antibody = await lab.synthesize(
                finding=origin.finding,
                vulnerable_code=sources_by_repo[origin.repo].get(origin.finding.file, ""),
                patched_code=(
                    origin.wargame.final_bundle.file_mapping().get(origin.finding.file, "")
                    if origin.wargame.final_bundle else ""
                ),
                breach_history=origin.wargame.breach_history,
            )
            lab.registry.save(antibody)
            hive.broadcast_antibody(antibody, origin_repo=origin.repo)
            hive_antibodies = hive_antibodies + load_antibodies(fleet_dir, directory=hive.antibody_dir)
            t_broadcast = time.perf_counter()
            new_hits: list[tuple[str, DetectionFinding]] = []
            for name, sources in sources_by_repo.items():
                for rel, content in sources.items():
                    for hit in antibody_sweep(rel, content, hive_antibodies):
                        new_hits.append((name, hit))
            sweep_ms = (time.perf_counter() - t_broadcast) * 1000
            console.line(
                f"  📡 [HIVE] Broadcasting {palette(antibody.rule_id, GOLD, bold=True)} to {len(repos)} repositories — "
                f"re-swept in {sweep_ms:.1f}ms · "
                f"{palette(str(len(new_hits)) + ' previously-invisible sink(s)', GOLD, bold=True)} confirmed",
                GOLD, bold=True,
            )
            await _publish_graph_pattern(console, fleet_dir, origin, hive)
        except AntibodyError as exc:
            console.note(f"antibody synthesis failed: {exc}")
    else:
        console.note("no surviving patch — no antibody broadcast this incident.")

    board.close()

    # ── [4/4] FLEET GITOPS ─────────────────────────────────────────────────
    console.phase(4, 4, "FLEET GITOPS — SYNCHRONIZED REMEDIATION", "⎇")
    applied_repos = {t.repo: t.applied_files for t in targets if t.applied_files}
    if not gitops:
        console.note("gitops disabled — healed files are already written to working trees.")
    elif not applied_repos:
        console.note("no verified patches to commit.")
    else:
        git = FleetGitOps(incident=incident)
        outcomes = await asyncio.gather(
            *(
                asyncio.to_thread(
                    git.commit_heal,
                    repos[repo],
                    cwe=origin_finding_cwe(targets),
                    files=files,
                    summary=f"Fleet auto-heal propagated by the Arbalest Hive Mind (incident {incident}).",
                    evidence=[f"{t.finding.rule_id}: {t.finding.evidence}" for t in targets if t.finding],
                )
                for repo, files in applied_repos.items()
            ),
            return_exceptions=True,
        )
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                console.error(f"GITOPS FAILED: {outcome}")
                continue
            url = outcome.pr_url or outcome.summary_path
            console.line(
                f"  ⎇ [{outcome.repo}] branch {palette(outcome.branch, WHITE, bold=True)} · "
                f"commit {palette(outcome.commit, GOLD)} · PR {url}",
                GOLD,
            )
            if outcome.pr_error and not outcome.pr_url:
                console.line(f"      {outcome.pr_error}", GRAY)

    # ── FINAL DEBRIEF ──────────────────────────────────────────────────────
    console.section("FINAL DEBRIEF — FLEET RESPONSE RECORD")
    rows = []
    unresolved = 0
    for target in targets:
        resolved = target.resolved
        if not resolved:
            unresolved += 1
        rows.append([
            severity_tag(target.finding.severity),
            target.repo,
            target.finding.rule_id,
            str(len(target.wargame.iterations)) if target.wargame else "—",
            "HEALED" if resolved else "UNRESOLVED",
        ])
    console.table(["SEV", "REPO", "RULE", "ITERS", "VERDICT"], rows, max_col=30)
    exit_code = EXIT_FLEET_SECURED if unresolved == 0 and targets else EXIT_FLEET_VULNERABLE
    console.verdict({}, unresolved, exit_code, None, time.perf_counter() - t0)
    return exit_code


def origin_finding_cwe(targets: list[FleetTarget]) -> str:
    return targets[0].finding.cwe if targets else "CWE-Unknown"


def _deploy(console: Console, repo_path: Path, wargame: WargameResult) -> list[str]:
    """Guarded deployment of a surviving bundle into one repository."""
    root = repo_path.resolve()
    written: list[str] = []
    bundle = wargame.final_bundle
    if bundle is None:
        return written
    for generated in bundle.files:
        dest = (root / generated.path).resolve()
        if not dest.is_relative_to(root):
            console.note(f"refusing out-of-tree bundle path: {generated.path}")
            continue
        original = dest.read_text(encoding="utf-8", errors="ignore") if dest.is_file() else None
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(generated.content, encoding="utf-8")
        written.append(generated.path)
        if original is not None and original != generated.content:
            diff = difflib.unified_diff(
                original.splitlines(), generated.content.splitlines(),
                fromfile=f"a/{generated.path}", tofile=f"b/{generated.path} (HEALED)",
                lineterm="", n=2,
            )
            for line in list(diff)[:14]:
                if line.startswith("+") and not line.startswith("+++"):
                    console.line("  " + line, EMERALD)
                elif line.startswith("-") and not line.startswith("---"):
                    console.line("  " + line, NEON_ORANGE)
    return written


async def _publish_graph_pattern(console: Console, fleet_dir: Path, origin: FleetTarget, hive: HiveRegistry) -> None:
    """Optional Neo4j fan-out of the learned pattern via the real ImmuneSystemAgent."""
    breach = origin.wargame.last_breach if origin.wargame else None
    if breach is None or not os.environ.get("NEO4J_URI"):
        console.kv("GRAPH MEMORY", "offline — hive antibody registry is the source of truth", GRAY)
        return
    from engine.agents.immune_system_agent import ImmuneSystemAgent
    from engine.services.ai_provider import AIProviderSettings, create_ai_provider
    from engine.services.graph_manager import GraphManager

    key = os.environ.get("AI_API_KEY", "").strip()
    if not key:
        console.kv("GRAPH MEMORY", "offline — no AI core for pattern synthesis", GRAY)
        return
    settings = AIProviderSettings(
        provider=os.environ.get("ARBALEST_PROVIDER", "custom"),
        api_key=key, selected_model=os.environ.get("ARBALEST_MODEL"),
    )
    try:
        provider = create_ai_provider(settings)
    except Exception as exc:  # noqa: BLE001
        console.note(f"graph memory synthesis unavailable: {exc}")
        return
    graph = GraphManager()
    exchange = FleetPatternExchange(hive)
    try:
        await graph.connect()
        agent = ImmuneSystemAgent(provider=provider, graph_manager=graph)
        pattern = await agent.synthesize_threat(
            project_id=f"fleet:{origin.repo}",
            red_team_result=breach,
            original_code=origin.finding.evidence,
        )
        receipt = await exchange.publish(
            threat_name=pattern.threat_name,
            cwe_category=pattern.cwe_category,
            cypher_pattern=pattern.cypher_pattern,
            origin_repo=origin.repo,
            source_finding=f"{origin.finding.rule_id} @ {origin.finding.file}:{origin.finding.line}",
            graph_managers=[("primary", graph)],
        )
        console.kv("GRAPH MEMORY", f"pattern {pattern.threat_name} broadcast ({receipt.pattern_id})",
                   QUANTUM_MAGENTA)
    except Exception as exc:  # noqa: BLE001
        console.note(f"graph memory write failed: {exc}")
    finally:
        try:
            await graph.close()
        except Exception:  # noqa: BLE001
            pass
