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
from engine.hive.federation import FleetRadius, FleetTopology
from engine.hive.fleet_commander import DispatchOrder, FleetCommanderAgent
from engine.hive.gitops import FleetGitOps
from engine.hive.registry import HiveRegistry
from engine.immune.antibody import AntibodyError, AntibodyLab, antibody_sweep, load_antibodies
from engine.immune.detection import DetectionFinding, sweep_sources
from engine.immune.wargame import WargameEngine, WargameResult, finding_from_detection
from engine.services.source_collector import collect_sources
from engine.services.remediation_artifact import atomic_apply_mapping
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
    radius: FleetRadius
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
    deploy: bool = False,
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
    if gitops:
        non_git = sorted(name for name, path in repos.items() if not FleetGitOps.is_repo(path))
        if non_git:
            console.note(f"non-Git repositories will be analyzed but cannot enter GitOps: {', '.join(non_git[:8])}")
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

    if not use_sandbox:
        console.note("analysis-only mode: sandbox verification was disabled; no fleet patch, learning, or GitOps is permitted")
        console.verdict({}, len(targets), EXIT_FLEET_VULNERABLE, None, time.perf_counter() - t0)
        return EXIT_FLEET_VULNERABLE

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
            sandbox = None
            try:
                sandbox = sandbox_factory()
                await sandbox.healthcheck()
                def left_log(line: str, repo: str = target.repo) -> None:
                    console.line(f"  ▣ [{repo}] ARCH ▸ {line}", DIM)

                def right_log(line: str, repo: str = target.repo) -> None:
                    console.line(f"  ▣ [{repo}] REDTEAM ▸ {line}", BLOOD_RED)

                engine = WargameEngine(
                    provider=provider, sandbox=sandbox, max_iterations=max_iterations,
                    left_log=left_log, right_log=right_log,
                )
                wargame = await engine.run(
                    sources_by_repo[target.repo], finding_from_detection(target.finding),
                )
            except Exception as exc:  # noqa: BLE001 — one lost duel never aborts the fleet
                console.error(f"WARGAME FAILED [{target.repo}]: {exc}")
                board.update(target.repo, status="HELD", sandbox="offline")
                return None
            finally:
                if sandbox is not None:
                    await sandbox.aclose()
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
        if target.wargame is not None and target.wargame.resolved and target.wargame.final_bundle:
            if deploy:
                target.applied_files = _deploy(console, repos[target.repo], target.wargame)
            else:
                _stage_heal(console, repos[target.repo], target.wargame)

        downstream: list[tuple[DispatchOrder, DetectionFinding]] = []
        for order in plan.orders:
            if order.kind == "downstream" and order.finding is not None:
                downstream.append((order, order.finding))
        if downstream:
            wargame_outcomes = await asyncio.gather(
                *(
                    fight(FleetTarget(repo=order.repo, finding=finding, radius=topology.trace(order.repo, finding)))
                    for order, finding in downstream
                ),
                return_exceptions=True,
            )
            for (order, finding), outcome in zip(downstream, wargame_outcomes):
                if isinstance(outcome, BaseException):
                    console.error(f"WARGAME FAILED [{order.repo}]: {outcome}")
                elif outcome and outcome.resolved and outcome.final_bundle:
                    if deploy:
                        applied_files = _deploy(console, repos[order.repo], outcome)
                    else:
                        applied_files = []
                        _stage_heal(console, repos[order.repo], outcome)
                    sibling = next(
                        (item for item in traced if item.repo == order.repo and item.finding.rule_id == finding.rule_id),
                        None,
                    )
                    if sibling is None:
                        sibling = FleetTarget(
                            repo=order.repo, finding=finding, radius=topology.trace(order.repo, finding),
                            wargame=outcome, applied_files=applied_files,
                        )
                        traced.append(sibling)
                        targets.append(sibling)
                    else:
                        sibling.wargame = outcome
                        sibling.applied_files = applied_files

    origin = next(
        (item for item in targets if item.wargame is not None and item.wargame.resolved and item.wargame.breach_history),
        None,
    )
    if origin is not None and origin.wargame is not None:
        origin_wargame = origin.wargame
        lab = AntibodyLab(provider=provider, root=repos[origin.repo])
        try:
            antibody = await lab.synthesize(
                finding=origin.finding,
                vulnerable_code=sources_by_repo[origin.repo].get(origin.finding.file, ""),
                patched_code=(
                    origin_wargame.final_bundle.file_mapping().get(origin.finding.file, "")
                    if origin_wargame.final_bundle else ""
                ),
                breach_history=origin_wargame.breach_history,
            )
            if not antibody.validated:
                raise AntibodyError(f"antibody self-test failed: {antibody.validation_detail}")
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
            await _publish_graph_pattern(console, fleet_dir, origin, hive, provider)
        except AntibodyError as exc:
            console.note(f"antibody synthesis failed: {exc}")
    else:
        console.note("no surviving patch — no antibody broadcast this incident.")

    board.close()

    # ── [4/4] FLEET GITOPS ─────────────────────────────────────────────────
    console.phase(4, 4, "FLEET GITOPS — SYNCHRONIZED REMEDIATION", "⎇")
    applied_repos = {t.repo: t.applied_files for t in targets if t.applied_files}
    gitops_failed = False
    if not deploy:
        console.note(
            "dry-run — verified bundles staged under .arbalest/proposed-heals in each repo; "
            "rerun with --deploy to write working trees, commit and open PRs"
        )
    elif not gitops:
        console.note("gitops disabled — healed files are already written to working trees.")
    elif not applied_repos:
        console.note("no verified patches to commit.")
    else:
        git = FleetGitOps(incident=incident)
        gitops_outcomes = await asyncio.gather(
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
        for gitops_outcome in gitops_outcomes:
            if isinstance(gitops_outcome, BaseException):
                gitops_failed = True
                console.error(f"GITOPS FAILED: {gitops_outcome}")
                continue
            url = gitops_outcome.pr_url or gitops_outcome.summary_path
            console.line(
                f"  ⎇ [{gitops_outcome.repo}] branch {palette(gitops_outcome.branch, WHITE, bold=True)} · "
                f"commit {palette(gitops_outcome.commit, GOLD)} · PR {url}",
                GOLD,
            )
            if gitops_outcome.pr_error and not gitops_outcome.pr_url:
                gitops_failed = True
                console.line(f"      {gitops_outcome.pr_error}", GRAY)

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
    exit_code = EXIT_FLEET_SECURED if unresolved == 0 and targets and not gitops_failed else EXIT_FLEET_VULNERABLE
    await provider.aclose()
    console.verdict({}, unresolved + int(gitops_failed), exit_code, None, time.perf_counter() - t0)
    return exit_code


def origin_finding_cwe(targets: list[FleetTarget]) -> str:
    return targets[0].finding.cwe if targets else "CWE-Unknown"


def _stage_heal(console: Console, repo_path: Path, wargame: WargameResult) -> None:
    """Write a conclusively verified bundle as a reviewable patch; source untouched."""
    bundle = wargame.final_bundle
    if bundle is None or not wargame.resolved:
        return
    root = repo_path.resolve()
    sections: list[str] = []
    for relative, content in bundle.file_mapping().items():
        destination = (root / relative).resolve()
        if not destination.is_file():
            continue
        original = destination.read_text(encoding="utf-8", errors="replace")
        if original == content:
            continue
        sections.extend(difflib.unified_diff(
            original.splitlines(), content.splitlines(),
            fromfile=f"a/{relative}", tofile=f"b/{relative} (VERIFIED HEAL)", lineterm="", n=3,
        ))
    if not sections:
        return
    directory = root / ".arbalest" / "proposed-heals"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"hive-{wargame.finding.cwe if hasattr(wargame, 'finding') else 'heal'}-{uuid.uuid4().hex[:6]}.patch"
        path.write_text("\n".join(sections) + "\n", encoding="utf-8")
    except OSError as exc:
        console.error(f"staging verified heal failed: {exc}")
        return
    console.kv("STAGED HEAL", str(path), GOLD)


def _deploy(console: Console, repo_path: Path, wargame: WargameResult) -> list[str]:
    """Transactionally deploy a conclusively verified bundle."""
    bundle = wargame.final_bundle
    if bundle is None or not wargame.resolved:
        return []
    root = repo_path.resolve()
    mapping = bundle.file_mapping()
    for relative, content in mapping.items():
        destination = (root / relative).resolve()
        original = destination.read_text(encoding="utf-8", errors="replace") if destination.is_file() else None
        if original is not None and original != content:
            diff = difflib.unified_diff(
                original.splitlines(), content.splitlines(), fromfile=f"a/{relative}",
                tofile=f"b/{relative} (HEALED)", lineterm="", n=2,
            )
            for line in list(diff)[:14]:
                if line.startswith("+") and not line.startswith("+++"):
                    console.line("  " + line, EMERALD)
                elif line.startswith("-") and not line.startswith("---"):
                    console.line("  " + line, NEON_ORANGE)
    try:
        atomic_apply_mapping(root, mapping)
    except (OSError, ValueError) as exc:
        console.error(f"transactional deployment failed: {exc}")
        return []
    return list(mapping)


async def _publish_graph_pattern(
    console: Console, fleet_dir: Path, origin: FleetTarget, hive: HiveRegistry, provider
) -> None:
    """Optional Neo4j fan-out of the learned pattern via the real ImmuneSystemAgent."""
    breach = origin.wargame.last_breach if origin.wargame else None
    if breach is None or not os.environ.get("NEO4J_URI"):
        console.kv("GRAPH MEMORY", "offline — hive antibody registry is the source of truth", GRAY)
        return
    from engine.agents.immune_system_agent import ImmuneSystemAgent
    from engine.services.graph_manager import GraphManager

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
