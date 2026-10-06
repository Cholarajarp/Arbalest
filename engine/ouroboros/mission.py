"""The Ouroboros Protocol — Arbalest evolving Arbalest.

    [1/4] 🧬 META-GRAPH CONSTRUCTION — the federation engine maps the organism inward
    [2/4] ⚡ CAPABILITY SYNTHESIS      — the Architect writes the feature into the
                                         organism; the constitution reviews every byte
    [3/4] 🪞 RECURSIVE WARGAMING       — the mutated organism boots inside the Nebius
                                         Token Factory Sandbox and must prove it still
                                         lives; the Red Team attacks the new surface
    [4/4] ♻ AUTO-EVOLUTION             — verified mutations are committed to the
                                         organism's own repository

Stage 1 is deterministic. Stages 2-4 are real LLM + sandbox operations. The
governor (engine/ouroboros/) can never mutate itself.
"""

from __future__ import annotations

import asyncio
import re
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from engine.agents.architect_agent import (
    ArchitectureGraphContext,
    ArchitectAgent,
    CodeLanguage,
    MutationPlan,
    Severity,
    ThreatFinding,
)
from engine.agents.polyglot_translator import PolyglotTranslator
from engine.agents.red_team_swarm import RedTeamSwarm
from engine.hive.federation import FleetTopology
from engine.hive.gitops import FleetGitOps
from engine.immune.detection import sweep_sources
from engine.ouroboros.mirror import (
    BATTERY_SEEDS,
    MARKER_PASSED,
    build_mirror_workspace,
    conservative_verdict,
)
from engine.ouroboros.metacognitive import MetacognitiveAgent
from engine.services.ai_provider import StructuredOutputRequest
from engine.services.docker_manager import SandboxRunSpec, SandboxRuntime
from engine.ui.terminal import (
    ELECTRIC_GOLD,
    GRAY,
    MATRIX_GREEN,
    PLATINUM,
    STARK_WHITE,
    WHITE,
    Console,
    palette,
)

EXIT_EVOLVED = 0
EXIT_REJECTED = 1
EXIT_MISSION_ERROR = 2

MAX_SEEDS = 4
_TRANSCRIPT_TAIL = 12


def sierpinski(rows: int = 12) -> list[str]:
    """The recursive fractal — the mission's own signature, generated recursively."""
    out = []
    width = rows
    for i in range(rows):
        cells = "".join(
            "▲" if (j & (i - j)) == 0 else " "
            for j in range(i + 1)
        )
        out.append(" " * (width - i) + " ".join(cells))
    return out


@dataclass
class EvolutionRequest:
    issue: str
    slug: str
    summary: str
    detail: str = ""


@dataclass
class EvolutionOutcome:
    targets: list[str] = field(default_factory=list)
    mutation_hash: str = ""
    mirror_passed: bool = False
    redteam_allowed: bool = False
    committed: bool = False
    generation: int = 0
    branch: str = ""
    pr_url: str = ""


def resolve_issue(self_root: Path, issue: str) -> EvolutionRequest:
    """`--issue 42` → gh issue or local issue file; text → literal request."""
    text = issue.strip()
    if not re.fullmatch(r"\d+", text):
        return EvolutionRequest(
            issue=text,
            slug=_slugify(text),
            summary=text,
        )
    gh = _which("gh") or _which("gh.exe")
    if gh:
        proc = subprocess.run(
            [gh, "issue", "view", text, "--json", "title,body",
             "--template", "{{.title}}::{{.body}}"],
            cwd=str(self_root), capture_output=True, text=True, timeout=60,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            title, _, body = proc.stdout.strip().partition("::")
            summary = title or text
            return EvolutionRequest(issue=text, slug=f"issue-{text}", summary=summary, detail=body[:4000])
    local = self_root / ".arbalest" / "issues" / f"{text}.md"
    if local.is_file():
        body = local.read_text(encoding="utf-8", errors="ignore")
        summary = body.splitlines()[0].lstrip("# ").strip() if body.strip() else f"Issue {text}"
        return EvolutionRequest(issue=text, slug=f"issue-{text}", summary=summary, detail=body[:4000])
    raise RuntimeError(
        f"issue {text} could not be resolved: install/authenticate the gh CLI, "
        f"or place the request in .arbalest/issues/{text}.md"
    )


def _which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


def _slugify(text: str, cap: int = 40) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:cap].strip("-") or "evolution"


async def run_evolution_mission(
    console: Console,
    self_root: Path,
    *,
    issue: str,
    provider_factory,
    sandbox_factory,
    use_sandbox: bool = True,
    gitops: bool = True,
) -> int:
    t0 = time.perf_counter()
    run_id = uuid.uuid4().hex[:8]

    # ── HERO ──────────────────────────────────────────────────────────────
    for row in sierpinski():
        console.line("  " + row, ELECTRIC_GOLD)
    console.meta_band("OUROBOROS PROTOCOL — ARBALEST EXAMINING ARBALEST")
    console.kv("RUN ID", run_id, GRAY)
    console.kv("SUBJECT", "this organism's own source code", ELECTRIC_GOLD)
    console.kv("DOCTRINE", "no upgrade without a mathematical mirror proof", STARK_WHITE)
    console.rule()

    if not self_root.is_dir():
        console.error(f"ORGANISM NOT FOUND — {self_root}")
        return EXIT_MISSION_ERROR

    try:
        request = resolve_issue(self_root, issue)
    except RuntimeError as exc:
        console.error(str(exc))
        return EXIT_MISSION_ERROR
    console.kv("CAPABILITY REQUEST", request.summary, PLATINUM)
    if request.detail:
        console.kv("ISSUE DETAIL", f"{len(request.detail)} chars", GRAY)

    # ── [1/4] META-GRAPH CONSTRUCTION (deterministic) ─────────────────────
    console.phase(1, 4, "META-GRAPH CONSTRUCTION", "🧬")
    agent = MetacognitiveAgent(self_root)
    with console.spinner("INTROSPECTION — the federation engine mapping the organism inward"):
        sources = agent.self_sources()
        topology = FleetTopology({"arbalest": sources})
    console.kv("ORGANISM", f"{len(sources)} source files ingested by its own collector", PLATINUM)
    console.kv("META-GRAPH", f"{len(topology._funcs)} nodes · "
               f"{sum(len(v) for v in topology._forward.values())} internal call edges",
               ELECTRIC_GOLD)

    targets = agent.map_meta_graph(sources, f"{request.summary} {request.detail}")
    if not targets:
        console.error("No module of the organism maps to this capability request.")
        return EXIT_MISSION_ERROR
    rows = [
        [t.file, f"{t.score:.0f}", ", ".join(t.matches[:4])]
        for t in targets[:6]
    ]
    console.table(["MODULE", "RELEVANCE", "SYMBOL MATCHES"], rows, max_col=44)
    console.line("  [OUROBOROS] 🧬 Arbalest is mapping its own internal architecture...", ELECTRIC_GOLD, bold=True)

    seeds = [t.file for t in targets[:MAX_SEEDS]]
    closure, external_deps = agent.import_closure(
        list(BATTERY_SEEDS) + seeds, sources,
    )
    console.kv("MIRROR INSTALL", f"{len(closure)} file(s) in dependency closure", GRAY)
    if external_deps:
        console.kv("SANDBOX SHIMS", ", ".join(sorted(external_deps)[:8]), GRAY)

    # ── Arm the AI core (real) ────────────────────────────────────────────
    try:
        provider = provider_factory()
    except RuntimeError as exc:
        console.rule()
        console.error(f"AI CORE NOT ARMED — {exc}")
        console.line("  The meta-graph above is real introspection. Capability synthesis requires a live model.",
                     ELECTRIC_GOLD)
        return EXIT_MISSION_ERROR

    # ── [2/4] CAPABILITY SYNTHESIS ────────────────────────────────────────
    console.phase(2, 4, "CAPABILITY SYNTHESIS", "⚡")
    capability_finding = ThreatFinding(
        finding_id=f"EVO-{request.slug}",
        cwe="CWE-Enhancement",
        severity=Severity.MEDIUM,
        summary=f"Capability request: {request.summary}",
        affected_nodes=seeds,
        evidence=[f"relevance: {', '.join(t.file for t in targets[:3])}"],
    )
    architect = ArchitectAgent(provider=provider)
    try:
        with console.spinner("META-ARCHITECT — drafting the self-modification plan"):
            plan: MutationPlan = await architect.create_plan(
                graph_context=ArchitectureGraphContext(project_id="ouroboros", nodes=[], edges=[]),
                findings=[capability_finding],
                developer_task=(
                    f"Implement this capability in Arbalest itself: {request.summary}. "
                    f"{request.detail}".strip()
                ),
                available_files={path: sources[path] for path in closure if path in sources},
                target_language=CodeLanguage.PYTHON,
            )
        for mutation in plan.mutations[:6]:
            console.line(f"  ⚡ {mutation.action.value} → {mutation.target_file}: {mutation.rationale[:90]}", PLATINUM)
        with console.spinner("POLYGLOT — forging the mutated organism"):
            bundle = await PolyglotTranslator(provider=provider).translate(
                legacy_sources={path: sources[path] for path in closure if path in sources},
                mutation_plan=plan,
            )
    except Exception as exc:  # noqa: BLE001
        console.error(f"SYNTHESIS FAILED: {exc}")
        return EXIT_REJECTED

    if bundle.language is not CodeLanguage.PYTHON:
        console.error(f"constitution: the organism is Python — refusing {bundle.language.value} mutation")
        return EXIT_REJECTED

    decision = agent.review_mutation(bundle, plan, sources)
    console.kv("MUTATION HASH", decision.mutation_hash, GRAY)
    if not decision.approved:
        for veto in decision.vetoes:
            console.error(veto)
        console.line("  EVOLUTION VETOED — the organism is unchanged.", MATRIX_GREEN, bold=True)
        return EXIT_REJECTED
    console.success(f"constitution satisfied — {len(bundle.files)} mutated file(s) accepted")

    # Capability test: generated, then governed.
    try:
        with console.spinner("META-ARCHITECT — writing the capability proof"):
            raw = await provider.generate_structured(StructuredOutputRequest(
                instructions=(
                    "Write a dependency-light Python test that proves the requested capability now works "
                    "against the mutated modules available in the workspace (import them by their normal "
                    "module paths). Deterministic asserts only, no network, no processes, no dynamic "
                    "execution. Return JSON only."
                ),
                input_text=f"request: {request.summary}\nmutated files: {sorted(bundle.file_mapping())}\n"
                           f"closure: {closure}",
                schema_name="ouroboros_capability_test",
                json_schema={
                    "type": "object", "additionalProperties": False,
                    "required": ["test_code"],
                    "properties": {"test_code": {"type": "string"}},
                },
                max_output_tokens=2_000,
            ))
            import json as _json

            capability_test = str(_json.loads(raw).get("test_code", ""))
    except Exception as exc:  # noqa: BLE001
        console.error(f"capability test generation failed: {exc}")
        return EXIT_REJECTED
    test_vetoes = agent.review_capability_test(capability_test)
    if test_vetoes:
        for veto in test_vetoes:
            console.error(f"capability test veto: {veto}")
        return EXIT_REJECTED
    console.success("capability test generated and constitution-reviewed")

    # ── [3/4] RECURSIVE WARGAMING (MIRROR SANDBOX) ────────────────────────
    console.phase(3, 4, "RECURSIVE WARGAMING — THE MIRROR SANDBOX", "🪞")
    sandbox = sandbox_factory()
    if use_sandbox:
        try:
            with console.spinner("MIRROR BOOT — negotiating with the Nebius Token Factory Sandbox"):
                await sandbox.healthcheck()
            console.line("  [OUROBOROS] 🪞 Recursive Sandbox Boot — installing the mutated organism...",
                         STARK_WHITE, bold=True)
        except Exception as exc:  # noqa: BLE001
            console.error(f"Nebius Token Factory Sandbox unreachable: {exc}")
            console.line("  The mirror refuses to certify what it never ran. Organism unchanged.", ELECTRIC_GOLD)
            return EXIT_REJECTED

        workspace = build_mirror_workspace(
            mutated=bundle.file_mapping(),
            closure=closure,
            original_sources=sources,
            capability_test=capability_test,
        )
        outcome = EvolutionOutcome(
            targets=list(bundle.file_mapping()),
            mutation_hash=decision.mutation_hash,
        )
        try:
            with console.spinner("MIRROR RUN — the sandboxed Arbalest testing itself"):
                mirror_result = await sandbox.run(SandboxRunSpec(
                    runtime=SandboxRuntime.PYTHON,
                    command=("python", "mirror_harness.py"),
                    files=workspace,
                    name_hint="ouroboros-mirror",
                ))
        except Exception as exc:  # noqa: BLE001
            console.error(f"MIRROR SANDBOX FAILED: {exc}")
            return EXIT_REJECTED

        transcript = f"{mirror_result.stdout}\n{mirror_result.stderr}"
        outcome.mirror_passed = conservative_verdict(mirror_result.succeeded, mirror_result.exit_code, transcript)
        for line in transcript.strip().splitlines()[-_TRANSCRIPT_TAIL:]:
            console.line(f"    {line[:130]}", GRAY)
        if outcome.mirror_passed:
            console.success("MIRROR PROOF — the mutated organism passes every regression + the capability test")
        else:
            console.error("MIRROR PROOF FAILED — the mutation did not survive its own sandbox")
            return EXIT_REJECTED

        # Red Team repurposed: attack the new surface of the organism itself.
        with console.spinner("REDTEAM-SWARM — attacking Arbalest's own new surface"):
            red_team = RedTeamSwarm(sandbox=sandbox, provider=provider)
            mutated_findings = sweep_sources(bundle.file_mapping())
            findings = [capability_finding, *mutated_findings[:5]]
            red_team_result = await red_team.execute(
                generated_code=bundle, mutation_plan=plan, findings=findings,
            )
        outcome.redteam_allowed = red_team_result.deployment_allowed
        if outcome.redteam_allowed:
            console.success("meta-vulnerability sweep — the swarm could not breach the mutation")
        else:
            console.error("the swarm breached the mutation — evolution rejected")
            return EXIT_REJECTED
    else:
        console.note("--no-sandbox: mirror proof skipped; patches can NOT be certified")
        outcome = EvolutionOutcome(targets=list(bundle.file_mapping()), mutation_hash=decision.mutation_hash)
        return EXIT_REJECTED

    # ── [4/4] AUTO-EVOLUTION ──────────────────────────────────────────────
    console.phase(4, 4, "AUTO-EVOLUTION", "♻")
    for path in outcome.targets:
        dest = (self_root / path).resolve()
        if not dest.is_relative_to(self_root.resolve()):
            console.error(f"constitution breach at deploy: {path}")
            return EXIT_REJECTED
    if gitops:
        git = FleetGitOps(incident=run_id)
        try:
            pr = await asyncio.to_thread(
                git.commit_heal,
                self_root,
                cwe=request.slug or "evolution",
                files=outcome.targets,
                summary=f"Self-evolution generation {agent.state.generation + 1}: {request.summary}",
                evidence=[f"mirror proof: {MARKER_PASSED}", f"mutation hash: {outcome.mutation_hash}"],
                branch_prefix="arbalest/evolve",
            )
            outcome.committed = pr.ok
            outcome.branch = pr.branch
            outcome.pr_url = pr.pr_url or pr.summary_path
            console.line(
                f"  ♻ committed {palette(pr.branch, WHITE, bold=True)} · {palette(pr.commit, ELECTRIC_GOLD)} · "
                f"PR {palette(pr.pr_url or pr.summary_path, GRAY)}",
                MATRIX_GREEN,
            )
        except Exception as exc:  # noqa: BLE001
            console.error(f"self-commit failed: {exc}")
            return EXIT_REJECTED
    else:
        for path, content in bundle.file_mapping().items():
            dest = (self_root / path).resolve()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
        console.note("gitops disabled — mutated files written to the working tree")

    outcome.generation = agent.record_commit(outcome.mutation_hash, request.summary, outcome.targets)
    console.rule()
    console.line(
        f"  🧬 GENERATION {palette(str(outcome.generation), MATRIX_GREEN, bold=True)} — "
        f"the organism upgraded itself: {len(outcome.targets)} file(s), mirror-proven, swarm-attested",
        MATRIX_GREEN, bold=True,
    )
    console.kv("ELAPSED", f"{time.perf_counter() - t0:.1f}s", GRAY)
    console.line(f"  EXIT CODE: {palette('0', MATRIX_GREEN, bold=True)} (0 = EVOLVED, 1 = REJECTED, 2 = ERROR)")
    console.rule()
    return EXIT_EVOLVED
