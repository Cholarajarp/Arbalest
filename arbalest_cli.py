#!/usr/bin/env python3
"""
Arbalest CLI — Tier-1 DevSecOps Strike Platform.

Autonomous, real, AI-driven security operations against a local codebase:
  [1/4] 🔍 RECON PHASE        — index sources, map the static attack surface
  [2/4] 🛡 AST SCAN PHASE     — SAST logic-flaw analysis + secret sweep
  [3/4] 🧬 DEPENDENCY CHECK   — SCA against known CVEs
  [4/4] 🧠 THREAT RAG         — correlate findings with the threat-intel corpus
  AGENT PROFILES              — ArchitectAgent writes, PolyglotTranslator forges,
                                RedTeamSwarm breaks (Nebius Token Factory Sandbox)
  FINAL DEBRIEF               — SARIF report + exit code (0 SECURED, 1 VULNERABLE)

Provider: nebius (Nebius Token Factory / NVIDIA Nemotron), or custom
(OpenAI-compatible endpoint via AI_BASE_URL).

Usage:
  python arbalest_cli.py scan ./my-repo
  python arbalest_cli.py scan ./my-repo --provider nebius -m NVIDIA-Nemotron-3-Nano-30B-A3B
  python arbalest_cli.py scan ./my-repo -f sarif -o -          # strict SARIF to stdout
  python arbalest_cli.py fix   ./my-repo --finding CWE-89
  python arbalest_cli.py verify ./my-repo --finding CWE-89     # adversarial verification
"""

from __future__ import annotations

import argparse
import asyncio
import difflib
import json
import logging
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Resolve backend imports
# ---------------------------------------------------------------------------
_BACKEND_DIR = Path(__file__).resolve().parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from engine.services.ai_provider import AIProviderSettings, create_ai_provider  # noqa: E402
from engine.services.source_collector import run_recon  # noqa: E402
from engine.services.scan_pipeline import SwarmResult, run_agent_swarm  # noqa: E402
from engine.services.sarif_export import findings_to_sarif, sarif_to_pretty_json  # noqa: E402
from engine.services.html_report import findings_to_html  # noqa: E402
from engine.immune.mission import run_immune_mission  # noqa: E402
from engine.hive.mission import run_fleet_mission  # noqa: E402
from engine.ouroboros.mission import run_evolution_mission  # noqa: E402
from engine.agents.architect_agent import (  # noqa: E402
    ArchitectureGraphContext,
    ArchitectAgent,
    CodeLanguage,
    MutationPlan,
    Severity,
    ThreatFinding,
)
from engine.agents.polyglot_translator import GeneratedCodeBundle, PolyglotTranslator  # noqa: E402
from engine.agents.red_team_swarm import RedTeamSwarm  # noqa: E402
from engine.services.docker_manager import DockerSandboxManager, SandboxRuntime  # noqa: E402
from engine.ui.terminal import (  # noqa: E402
    ELECTRIC_BLUE,
    EMERALD,
    GRAY,
    NEON_ORANGE,
    SEV_ORDER,
    Console,
    severity_tag,
)

_VERSION = "1.0.0"
_LOG_FMT = "%(asctime)s | %(levelname)-7s | %(message)s"
_DATE_FMT = "%H:%M:%S"

_PROVIDER_KEY_ENV: dict[str, list[str]] = {
    "custom": ["AI_API_KEY"],
    "nebius": ["NEBIUS_API_KEY", "AI_API_KEY"],
}

_DEFAULT_MODELS: dict[str, str] = {
    "custom": "gpt-4o",
    "nebius": "NVIDIA-Nemotron-3-Nano-30B-A3B",
}

EXIT_SECURED = 0
EXIT_VULNERABLE = 1
EXIT_MISSION_ERROR = 2


def _load_env_file() -> None:
    """Load `.env` from the script directory or CWD. Existing env vars win."""
    for candidate in (_BACKEND_DIR / ".env", Path.cwd() / ".env"):
        if not candidate.is_file():
            continue
        try:
            for raw in candidate.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = value
        except OSError:
            continue
        break


def _resolve_api_key(provider: str) -> str | None:
    """Try each candidate env-var for the chosen provider."""
    for var in _PROVIDER_KEY_ENV.get(provider, ["AI_API_KEY"]):
        val = os.environ.get(var, "").strip()
        if val:
            return val
    return None


def _build_provider(provider_name: str, model_name: str | None):
    """Build the real AI core or raise with an actionable message."""
    api_key = _resolve_api_key(provider_name)
    if not api_key:
        candidates = _PROVIDER_KEY_ENV.get(provider_name, ["AI_API_KEY"])
        raise RuntimeError(
            f"No API key armed for provider '{provider_name}'. "
            f"Set one of: {', '.join(candidates)} (see .env.example)."
        )
    effective_model = model_name or os.environ.get("ARBALEST_MODEL") or _DEFAULT_MODELS.get(provider_name, "gpt-4o")
    settings = AIProviderSettings(
        provider=provider_name,
        api_key=api_key,
        selected_model=effective_model,
    )
    return create_ai_provider(settings), effective_model


def _probe_sandbox() -> str:
    """Real Docker Engine probe for the Nebius Token Factory Sandbox hero line."""
    try:
        import docker  # type: ignore[import-untyped]

        client = docker.from_env(timeout=2)
        version = client.version().get("Version", "unknown")
        client.close()
        return f"ARMED (engine {version})"
    except Exception:
        return "STANDBY (engine unreachable — staging mode)"


def _sandbox_manager() -> DockerSandboxManager:
    """Build the real Nebius Token Factory Sandbox manager."""
    os.environ.setdefault("ARBALEST_ENVIRONMENT", "staging")
    return DockerSandboxManager(images={
        SandboxRuntime.PYTHON: "python:3.12-slim",
        SandboxRuntime.TYPESCRIPT: "node:20-alpine",
        SandboxRuntime.RUST: "rust:1.77-slim",
        SandboxRuntime.GO: "golang:1.22-alpine",
    })


def _gate_exit_code(counts: dict[str, int], fail_on: str, strict: bool) -> int:
    """0 = SECURED, 1 = VULNERABLE. --strict drops the floor to INFO."""
    floor = "info" if strict else fail_on
    if floor == "none":
        return EXIT_SECURED
    try:
        idx = SEV_ORDER.index(floor)
    except ValueError:
        return EXIT_SECURED
    return EXIT_VULNERABLE if any(counts.get(s, 0) for s in SEV_ORDER[:idx + 1]) else EXIT_SECURED


def _findings_table(ui: Console, findings: list[ThreatFinding], empty_msg: str) -> None:
    """Vulnerabilities are the main subject; everything else is suppressed."""
    if not findings:
        ui.success(empty_msg)
        return
    rows: list[list[str]] = []
    for f in findings[:25]:
        location = f.affected_nodes[0] if f.affected_nodes else "—"
        rows.append([severity_tag(f.severity), f.summary, f.cwe, location])
    ui.table(["SEV", "FINDING", "CWE", "LOCATION"], rows, max_col=34)
    if len(findings) > 25:
        ui.note(f"+{len(findings) - 25} more — full set preserved in the SARIF report")


def _agent_status_table(ui: Console, swarm: SwarmResult) -> None:
    rows = [
        [name.upper(), stat.status.upper(), str(stat.count), stat.detail[:40] or "—"]
        for name, stat in swarm.stats.items()
    ]
    ui.table(["AGENT", "STATUS", "FINDINGS", "DETAIL"], rows,
             aligns=["<", "<", ">", "<"], max_col=44)


def _unified_diff(original: str, updated: str, rel_path: str) -> str:
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True),
        updated.splitlines(keepends=True),
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path} (SECURED)",
    ))


def _machine_payload(
    swarm: SwarmResult, run_id: str, target: Path,
    provider: str, model: str, elapsed: float,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "target": str(target),
        "provider": provider,
        "model": model,
        "elapsed_s": round(elapsed, 2),
        "total_findings": len(swarm.findings),
        "severity_counts": swarm.severity_counts,
        "agents": {k: v.as_dict() for k, v in swarm.stats.items()},
        "findings": [f.model_dump(mode="json") for f in swarm.findings],
        "harness": {
            "injection_hits": [hit.model_dump(mode="json") for hit in swarm.injection_hits],
        },
    }


# ---------------------------------------------------------------------------
# SCAN — the curriculum
# ---------------------------------------------------------------------------
async def _run_scan(
    target: Path,
    provider_name: str,
    model_name: str | None,
    output_format: str,
    output_file: Path | None,
    strict_mode: bool,
    verbose: bool,
    fail_on: str,
) -> int:
    """Execute the full curriculum and return the mission exit code."""
    t0 = time.perf_counter()
    run_id = uuid.uuid4().hex[:12]
    machine_mode = output_file is not None and str(output_file) == "-" and output_format in ("json", "sarif")
    ui = Console(silent=machine_mode)
    logging.basicConfig(level=logging.DEBUG if verbose else logging.CRITICAL,
                        format=_LOG_FMT, datefmt=_DATE_FMT, stream=sys.stderr)

    # ── Validate target ──────────────────────────────────────────────────
    if not target.exists() or not target.is_dir():
        ui.error(f"TARGET REJECTED — not a directory: {target}")
        return EXIT_MISSION_ERROR

    # ── Arm the AI core (real provider required) ─────────────────────────
    try:
        provider, effective_model = _build_provider(provider_name, model_name)
    except RuntimeError as exc:
        ui.hero(_VERSION, provider_name, "—", _probe_sandbox(), str(target))
        ui.error(str(exc))
        ui.line("  ARM THE AI CORE AND RE-RUN. NO SIMULATIONS. NO EXCUSES.", NEON_ORANGE)
        return EXIT_MISSION_ERROR

    ui.hero(_VERSION, provider_name, effective_model, _probe_sandbox(), str(target))

    # ── [1/4] RECON ──────────────────────────────────────────────────────
    ui.phase(1, 4, "RECON PHASE", "🔍")
    with ui.spinner("RECON — indexing source tree & mapping attack surface"):
        recon = run_recon(target)
    if not recon.files:
        ui.error("No source files found — nothing to defend.")
        return EXIT_MISSION_ERROR
    langs = "  ".join(f"{k}:{v}" for k, v in sorted(recon.language_counts.items(), key=lambda x: -x[1]))
    ui.kv("FILES INDEXED", str(recon.total_files), ELECTRIC_BLUE)
    ui.kv("LANGUAGES", langs or "—")
    ui.kv("MANIFESTS", ", ".join(recon.manifests) or "—")
    ui.kv("ENTRYPOINTS", f"{len(recon.entrypoints)} mapped", ELECTRIC_BLUE)
    ui.kv("SINK SIGNATURES", f"{recon.sink_hits} hits", NEON_ORANGE if recon.sink_hits else "—")

    # ── [2/4]..[4/4] — streamed swarm with per-phase tables ──────────────
    def on_phase(bucket: str, findings: list[ThreatFinding]) -> None:
        label = {
            "sast": "SAST — logic flaws",
            "secrets": "SECRET SWEEP — leaked credentials",
            "sca": "SCA — vulnerable dependencies",
            "threat_rag": "THREAT RAG — intel-enriched findings",
        }.get(bucket, bucket)
        _findings_table(ui, findings, f"{label}: clean.")

    from engine.harness.mission_ledger import MissionLedger

    ledger = MissionLedger(target / ".arbalest" / "harness-ledger.jsonl")
    swarm = await run_agent_swarm(provider, recon.files, recon, ui=ui, on_phase=on_phase, ledger=ledger)
    if swarm.injection_hits:
        ledger.record(
            actor="harness.injection_defense",
            action="scan_summary",
            verdict="neutralized",
            detail=f"{len(swarm.injection_hits)} injection attempt(s) across scanned sources",
        )

    # ── FINAL DEBRIEF ────────────────────────────────────────────────────
    counts = swarm.severity_counts
    exit_code = _gate_exit_code(counts, fail_on, strict_mode)
    elapsed = time.perf_counter() - t0

    if machine_mode:
        payload = _machine_payload(swarm, run_id, target, provider_name, effective_model, elapsed)
        if output_format == "sarif":
            print(sarif_to_pretty_json(findings_to_sarif(swarm.findings, run_id=run_id, target_url=str(target))))
        else:
            print(json.dumps(payload, indent=2, default=str))
        return exit_code

    ui.section("SWARM STATUS")
    _agent_status_table(ui, swarm)

    out_path = output_file or Path(f"arbalest-report.{output_format}")
    if output_format == "sarif":
        sarif = findings_to_sarif(swarm.findings, run_id=run_id, target_url=str(target))
        out_path.write_text(sarif_to_pretty_json(sarif), encoding="utf-8")
    elif output_format == "html":
        out_path.write_text(findings_to_html(swarm.findings), encoding="utf-8")
    else:
        out_path.write_text(
            json.dumps(_machine_payload(swarm, run_id, target, provider_name, effective_model, elapsed),
                       indent=2, default=str),
            encoding="utf-8",
        )

    ui.section("FINAL DEBRIEF")
    ui.kv("RUN ID", run_id, GRAY)
    ui.verdict(counts, len(swarm.findings), exit_code, str(out_path.resolve()), elapsed)
    return exit_code


# ---------------------------------------------------------------------------
# FIX — AGENT PROFILE: ARCHITECT
# ---------------------------------------------------------------------------
async def _run_fix(
    target: Path,
    finding_id: str,
    provider_name: str,
    model_name: str | None,
    verbose: bool,
) -> int:
    t0 = time.perf_counter()
    ui = Console(silent=False)
    logging.basicConfig(level=logging.DEBUG if verbose else logging.CRITICAL,
                        format=_LOG_FMT, datefmt=_DATE_FMT, stream=sys.stderr)

    if not target.exists() or not target.is_dir():
        ui.error(f"TARGET REJECTED — not a directory: {target}")
        return EXIT_MISSION_ERROR

    try:
        provider, effective_model = _build_provider(provider_name, model_name)
    except RuntimeError as exc:
        ui.hero(_VERSION, provider_name, "—", _probe_sandbox(), str(target))
        ui.error(str(exc))
        return EXIT_MISSION_ERROR

    ui.hero(_VERSION, provider_name, effective_model, _probe_sandbox(), str(target))

    with ui.spinner("RECON — indexing source tree"):
        recon = run_recon(target)
    if not recon.files:
        ui.error("No source files found.")
        return EXIT_MISSION_ERROR

    finding = ThreatFinding(
        finding_id=f"CLI-{finding_id}",
        cwe=finding_id if finding_id.upper().startswith("CWE") else "CWE-Unknown",
        severity=Severity.HIGH,
        summary=f"Remediation requested via CLI for {finding_id}",
        affected_nodes=[],
        evidence=[],
    )

    # ── AGENT PROFILE: ARCHITECT-01 — writes the code ────────────────────
    ui.section("AGENT PROFILE ▸ ARCHITECT-01 — WRITES THE CODE")
    architect = ArchitectAgent(provider=provider)
    try:
        with ui.spinner("ARCHITECT-01 — formulating mutation plan"):
            plan: MutationPlan = await architect.create_plan(
                graph_context=ArchitectureGraphContext(project_id="cli-fix", nodes=[], edges=[]),
                findings=[finding],
                developer_task=f"Fix the {finding_id} vulnerability in this codebase",
                available_files=recon.files,
                target_language=CodeLanguage.AUTO,
            )
    except Exception as exc:
        ui.error(f"ARCHITECT-01 failed: {exc}")
        return EXIT_VULNERABLE

    ui.table(
        ["ACTION", "TARGET FILE", "RATIONALE"],
        [[m.action.value, m.target_file, m.rationale] for m in plan.mutations],
        max_col=38,
    )
    ui.kv("PLAN ID", plan.plan_id, ELECTRIC_BLUE)
    ui.kv("TARGET LANGUAGE", plan.target_language.value, ELECTRIC_BLUE)
    ui.kv("SECURITY INVARIANTS", f"{len(plan.security_invariants)} declared")

    # ── AGENT PROFILE: POLYGLOT-02 — forges the translation ──────────────
    ui.section("AGENT PROFILE ▸ POLYGLOT-02 — FORGES THE TRANSLATION")
    translator = PolyglotTranslator(provider=provider)
    try:
        with ui.spinner("POLYGLOT-02 — generating secure code bundle"):
            bundle: GeneratedCodeBundle = await translator.translate(
                legacy_sources=recon.files, mutation_plan=plan,
            )
    except Exception as exc:
        ui.error(f"POLYGLOT-02 failed: {exc}")
        return EXIT_VULNERABLE

    # ── APPLY — real writes, real diffs ──────────────────────────────────
    ui.section("PATCH DEPLOYMENT")
    patch_path = target / f"arbalest-fix-{finding_id}.patch"
    diff_blocks: list[str] = []
    for generated in bundle.files:
        file_path = target / generated.path
        original = recon.files.get(generated.path, "")
        if not file_path.parent.exists():
            file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(generated.content, encoding="utf-8")
        diff = _unified_diff(original, generated.content, generated.path)
        diff_blocks.append(diff if diff else f"--- /dev/null\n+++ b/{generated.path} (NEW FILE)\n")
        ui.success(f"deployed {generated.path} ({len(generated.content)} bytes)")
    patch_path.write_text(
        f"# Arbalest Auto-Remediation — {finding_id}\n"
        f"# plan: {plan.plan_id}  language: {bundle.language.value}\n\n" + "\n".join(diff_blocks),
        encoding="utf-8",
    )
    ui.kv("PATCH FILE", str(patch_path), ELECTRIC_BLUE)

    ui.section("FINAL DEBRIEF")
    ui.verdict({}, 0, EXIT_SECURED, str(patch_path), time.perf_counter() - t0)
    return EXIT_SECURED


# ---------------------------------------------------------------------------
# VERIFY — MEMBER STORIES: adversarial case studies against patched code
# ---------------------------------------------------------------------------
async def _run_verify(
    target: Path,
    finding_id: str,
    provider_name: str,
    model_name: str | None,
    verbose: bool,
) -> int:
    t0 = time.perf_counter()
    ui = Console(silent=False)
    logging.basicConfig(level=logging.DEBUG if verbose else logging.CRITICAL,
                        format=_LOG_FMT, datefmt=_DATE_FMT, stream=sys.stderr)

    if not target.exists() or not target.is_dir():
        ui.error(f"TARGET REJECTED — not a directory: {target}")
        return EXIT_MISSION_ERROR

    ui.hero(_VERSION, provider_name, model_name or "auto", _probe_sandbox(), str(target))

    sandbox = _sandbox_manager()
    try:
        with ui.spinner("SANDBOX — negotiating with Docker engine"):
            await sandbox.healthcheck()
        ui.success("Nebius Token Factory Sandbox — engine reachable, ranges hot.")
    except Exception as exc:
        ui.error("Nebius Token Factory Sandbox requires a running Docker Engine.")
        ui.line(f"    {exc}", GRAY)
        return EXIT_VULNERABLE

    try:
        provider, effective_model = _build_provider(provider_name, model_name)
    except RuntimeError as exc:
        ui.error(str(exc))
        return EXIT_MISSION_ERROR

    with ui.spinner("RECON — indexing source tree"):
        recon = run_recon(target)
    if not recon.files:
        ui.error("No source files found.")
        return EXIT_MISSION_ERROR

    finding = ThreatFinding(
        finding_id=f"CLI-{finding_id}",
        cwe=finding_id if finding_id.upper().startswith("CWE") else "CWE-Unknown",
        severity=Severity.HIGH,
        summary=f"Adversarial verification requested for {finding_id}",
        affected_nodes=[],
        evidence=[],
    )

    try:
        with ui.spinner("ARCHITECT-01 — formulating mutation plan"):
            plan = await ArchitectAgent(provider=provider).create_plan(
                graph_context=ArchitectureGraphContext(project_id="cli-verify", nodes=[], edges=[]),
                findings=[finding],
                developer_task=f"Fix {finding_id}",
                available_files=recon.files,
                target_language=CodeLanguage.AUTO,
            )
        with ui.spinner("POLYGLOT-02 — generating patch candidate"):
            bundle = await PolyglotTranslator(provider=provider).translate(
                legacy_sources=recon.files, mutation_plan=plan,
            )
    except Exception as exc:
        ui.error(f"Patch generation failed: {exc}")
        return EXIT_VULNERABLE

    # ── AGENT PROFILE: REDTEAM-SWARM — breaks the code ───────────────────
    ui.section("AGENT PROFILE ▸ REDTEAM-SWARM — BREAKS THE CODE")

    async def log_sink(stream: str, chunk: str) -> None:
        for line in chunk.rstrip().splitlines():
            ui.line(f"    [{stream}] {line}", GRAY)

    red_team = RedTeamSwarm(sandbox=sandbox, provider=provider)
    try:
        with ui.spinner("REDTEAM-SWARM — live-fire adversarial engagement"):
            result = await red_team.execute(
                generated_code=bundle, mutation_plan=plan, findings=[finding], log_sink=log_sink,
            )
    except Exception as exc:
        ui.error(f"REDTEAM-SWARM engagement failed: {exc}")
        return EXIT_VULNERABLE

    # ── MEMBER STORY — the case file ─────────────────────────────────────
    ui.section("MEMBER STORY ▸ ADVERSARIAL CASE FILE")
    held = result.deployment_allowed
    verdict_txt = "PATCH HELD — CODE SURVIVED THE SWARM" if held else "PATCH BREACHED — CODE FAILED VERIFICATION"
    ui.kv("CASE SUBJECT", f"{finding_id} @ {target}", ELECTRIC_BLUE)
    ui.kv("ATTACK OBJECTIVE", result.attack.objective)
    ui.kv("EXPLOIT RESULT", "SUCCEEDED (breach)" if result.analysis.exploit_successful else "REPELLED")
    ui.kv("SANDBOX RUN", f"{result.sandbox.status.value} / exit {result.sandbox.exit_code}",
          EMERALD if result.sandbox.succeeded else NEON_ORANGE)
    ui.kv("CONFIDENCE", f"{result.analysis.confidence:.2f}")
    ui.print()
    ui.line(f"  VERDICT: {verdict_txt}", EMERALD if held else NEON_ORANGE, bold=True)
    ui.print()
    ui.bullet(result.analysis.reasoning, GRAY)
    for ev in result.analysis.evidence[:5]:
        ui.bullet(f"evidence: {ev}", GRAY)

    if held:
        patch_path = target / f"arbalest-verified-{finding_id}.patch"
        diff_blocks: list[str] = []
        for generated in bundle.files:
            original = recon.files.get(generated.path, "")
            file_path = target / generated.path
            if not file_path.parent.exists():
                file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(generated.content, encoding="utf-8")
            diff = _unified_diff(original, generated.content, generated.path)
            diff_blocks.append(diff if diff else f"--- /dev/null\n+++ b/{generated.path} (NEW FILE)\n")
            ui.success(f"verified patch deployed: {generated.path}")
        patch_path.write_text(
            f"# Arbalest Verified Patch — {finding_id}\n"
            f"# plan: {plan.plan_id}  red-team: PASSED\n\n" + "\n".join(diff_blocks),
            encoding="utf-8",
        )
        ui.section("FINAL DEBRIEF")
        ui.verdict({}, 0, EXIT_SECURED, str(patch_path), time.perf_counter() - t0)
        return EXIT_SECURED

    ui.error("Patch REJECTED by the swarm. Nothing was written to the target.")
    ui.section("FINAL DEBRIEF")
    ui.verdict({"critical": 1}, 1, EXIT_VULNERABLE, None, time.perf_counter() - t0)
    return EXIT_VULNERABLE


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    providers = ", ".join(_PROVIDER_KEY_ENV)
    parser = argparse.ArgumentParser(
        prog="arbalest",
        description=(
            "Arbalest — Tier-1 DevSecOps Strike Platform. "
            f"Providers: {providers}. Exit codes: 0 SECURED, 1 VULNERABLE, 2 MISSION ERROR."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"arbalest {_VERSION}")

    sub = parser.add_subparsers(dest="command", required=True)

    def _add_provider_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--provider", "-p", choices=sorted(_PROVIDER_KEY_ENV),
                       default=os.environ.get("ARBALEST_PROVIDER", "nebius"),
                       help="AI provider (default: ARBALEST_PROVIDER or nebius)")
        p.add_argument("--model", "-m", type=str, default=None,
                       help="Model override (default: per-provider default)")
        p.add_argument("--verbose", "-v", action="store_true", help="Verbose engine logs to stderr")

    scan_p = sub.add_parser("scan", help="Run the full curriculum against a repository")
    scan_p.add_argument("target", type=str, help="Repository directory to scan")
    scan_p.add_argument("--format", "-f", choices=["sarif", "json", "html"], default="sarif",
                        help="Final report format (default: sarif)")
    scan_p.add_argument("--output", "-o", type=str, default=None,
                        help="Report path ('-' streams strict JSON/SARIF to stdout)")
    scan_p.add_argument("--strict", action="store_true",
                        help="Strict enterprise mode — INFO findings also fail the gate")
    scan_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                        default="low",
                        help="Exit 1 when findings at/above this severity exist (default: low → 0 safe, 1 vulnerable)")
    _add_provider_args(scan_p)

    fix_p = sub.add_parser("fix", help="Autonomously remediate a vulnerability (Architect writes)")
    fix_p.add_argument("target", type=str, help="Repository directory to fix")
    fix_p.add_argument("--finding", "-f", type=str, required=True,
                       help="Vulnerability ID or CWE to remediate (e.g. CWE-89)")
    _add_provider_args(fix_p)

    verify_p = sub.add_parser("verify", help="Adversarially verify a patch (RedTeamSwarm breaks)")
    verify_p.add_argument("target", type=str, help="Repository directory to verify")
    verify_p.add_argument("--finding", "-f", type=str, required=True,
                          help="Vulnerability ID or CWE to verify against (e.g. CWE-89)")
    _add_provider_args(verify_p)

    immune_p = sub.add_parser(
        "immune",
        help="Immune System mode — blast-radius topology, adversarial war-game, antibody synthesis",
        description=(
            "Immune System mode — the codebase is a living organism; Arbalest is the swarm of antibodies.\n"
            "[1/3] Topological blast-radius mapping proves the attack chain from public API to sink.\n"
            "[2/3] Adversarial war-game: ArchitectAgent vs RedTeamSwarm minimax loop in the Nebius Sandbox.\n"
            "[3/3] Antibody generation: a self-tested Semgrep rule is synthesized from real breaches."
        ),
    )
    immune_p.add_argument("target", type=str, help="Repository directory to defend")
    immune_p.add_argument("--iterations", type=int, default=4,
                          help="Max war-game iterations per finding (default: 4)")
    immune_p.add_argument("--max-findings", type=int, default=3,
                          help="Max sinks to defend in one mission (default: 3)")
    immune_p.add_argument("--no-sandbox", action="store_true",
                          help="Skip Docker verification (patches will NOT be certified)")
    _add_provider_args(immune_p)

    fleet_p = sub.add_parser(
        "fleet",
        help="Hive Mind — distributed threat intelligence across every repository in a directory",
        description=(
            "Hive Mind mode — the organization's entire tech stack is the organism; Arbalest is the\n"
            "global immune network.\n"
            "[1/4] Federated recon: every repository sensed, fleet-wide sink matrix.\n"
            "[2/4] Cross-repo blast radius: one topological map spanning microservices.\n"
            "[3/4] Fleet war-games: parallel Architect vs RedTeam minimax loops in independent\n"
            "      Nebius Sandboxes, then antibody broadcast + fleet re-sweep in milliseconds.\n"
            "[4/4] Fleet GitOps: synchronized branches, commits and pull requests."
        ),
    )
    fleet_p.add_argument("--target-dir", type=str, required=True,
                         help="Directory containing the organization's repositories (one subdir per repo)")
    fleet_p.add_argument("--iterations", type=int, default=4,
                         help="Max war-game iterations per finding (default: 4)")
    fleet_p.add_argument("--max-findings", type=int, default=3,
                         help="Max sinks to defend in one mission (default: 3)")
    fleet_p.add_argument("--max-parallel", type=int, default=3,
                         help="Max concurrent fleet war-games (default: 3)")
    fleet_p.add_argument("--no-sandbox", action="store_true",
                         help="Skip Docker verification (patches will NOT be certified)")
    fleet_p.add_argument("--no-gitops", action="store_true",
                         help="Skip synchronized branch/commit/PR flow")
    _add_provider_args(fleet_p)

    evolve_p = sub.add_parser(
        "evolve",
        help="Ouroboros Protocol — Arbalest rewrites, mirror-proofs, and commits its own source",
        description=(
            "Ouroboros Protocol — the singularity leap. Arbalest turns its engine inward.\n"
            "[1/4] Meta-graph construction: the federation engine maps the organism inward.\n"
            "[2/4] Capability synthesis: the Architect writes the feature into Arbalest itself;\n"
            "      the constitution reviews every byte (protected paths, bounds, loop guard).\n"
            "[3/4] Recursive wargaming: the mutated organism boots inside the Nebius Sandbox and\n"
            "      must pass a regression battery + the capability proof; the Red Team attacks it.\n"
            "[4/4] Auto-evolution: verified mutations are committed to Arbalest's own repository."
        ),
    )
    evolve_p.add_argument("--issue", type=str, required=True,
                          help="Feature request text, or an issue number (gh issue view / .arbalest/issues/N.md)")
    evolve_p.add_argument("--no-sandbox", action="store_true",
                          help="Skip the mirror sandbox (evolution can NOT be certified — will be rejected)")
    evolve_p.add_argument("--no-gitops", action="store_true",
                          help="Write mutated files to the working tree instead of a verified branch")
    _add_provider_args(evolve_p)

    return parser


def main() -> None:
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    _load_env_file()
    args = _build_parser().parse_args()
    try:
        if args.command == "scan":
            rc = asyncio.run(_run_scan(
                target=Path(args.target),
                provider_name=args.provider,
                model_name=args.model,
                output_format=args.format,
                output_file=Path(args.output) if args.output else None,
                strict_mode=args.strict,
                verbose=args.verbose,
                fail_on=args.fail_on,
            ))
        elif args.command == "fix":
            rc = asyncio.run(_run_fix(
                target=Path(args.target), finding_id=args.finding,
                provider_name=args.provider, model_name=args.model, verbose=args.verbose,
            ))
        elif args.command == "immune":
            def _provider_factory():
                provider, _model = _build_provider(args.provider, args.model)
                return provider

            rc = asyncio.run(run_immune_mission(
                Console(silent=False),
                Path(args.target),
                provider_factory=_provider_factory,
                sandbox_factory=_sandbox_manager,
                max_iterations=max(args.iterations, 1),
                max_findings=max(args.max_findings, 1),
                use_sandbox=not args.no_sandbox,
            ))
        elif args.command == "fleet":
            def _fleet_provider_factory():
                provider, _model = _build_provider(args.provider, args.model)
                return provider

            rc = asyncio.run(run_fleet_mission(
                Console(silent=False),
                Path(args.target_dir),
                provider_factory=_fleet_provider_factory,
                sandbox_factory=_sandbox_manager,
                max_iterations=max(args.iterations, 1),
                max_findings=max(args.max_findings, 1),
                max_parallel=max(args.max_parallel, 1),
                use_sandbox=not args.no_sandbox,
                gitops=not args.no_gitops,
            ))
        elif args.command == "evolve":
            def _evolve_provider_factory():
                provider, _model = _build_provider(args.provider, args.model)
                return provider

            rc = asyncio.run(run_evolution_mission(
                Console(silent=False, meta=True),
                Path(__file__).resolve().parent,
                issue=args.issue,
                provider_factory=_evolve_provider_factory,
                sandbox_factory=_sandbox_manager,
                use_sandbox=not args.no_sandbox,
                gitops=not args.no_gitops,
            ))
        else:
            rc = asyncio.run(_run_verify(
                target=Path(args.target), finding_id=args.finding,
                provider_name=args.provider, model_name=args.model, verbose=args.verbose,
            ))
    except KeyboardInterrupt:
        print("\n  ✗ MISSION ABORTED BY OPERATOR", file=sys.stderr)
        rc = EXIT_MISSION_ERROR
    sys.exit(rc)


if __name__ == "__main__":
    main()
