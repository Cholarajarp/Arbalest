#!/usr/bin/env python3
"""
Arbalest CLI — security-first agentic code analysis and remediation.

Autonomous, real, AI-driven security operations against a local codebase:
  [1/4] 🔍 RECON PHASE        — index sources, map the static attack surface
  [2/4] 🛡 AST SCAN PHASE     — SAST logic-flaw analysis + secret sweep
  [3/4] 🧬 DEPENDENCY CHECK   — SCA against known CVEs
  [4/4] 🧠 THREAT RAG         — correlate findings with the threat-intel corpus
  AGENT PROFILES              — ArchitectAgent writes, PolyglotTranslator forges,
                                RedTeamSwarm breaks (Nebius Sandboxes / local Docker)
  FINAL DEBRIEF               — SARIF report + exit code (0 SECURED, 1 VULNERABLE)

Providers: nebius (Token Factory/Nemotron), openai (native Responses),
anthropic (native Messages), or custom (OpenAI-compatible Chat Completions).

Usage:
  python arbalest_cli.py scan ./my-repo
  python arbalest_cli.py scan ./my-repo --provider nebius -m <model-id>
  python arbalest_cli.py scan ./my-repo -f sarif -o -          # strict SARIF to stdout
  python arbalest_cli.py fix   ./my-repo --finding CWE-89
  python arbalest_cli.py verify ./my-repo --finding CWE-89     # verify only; source remains unchanged
  python arbalest_cli.py verify ./my-repo --finding CWE-89 --apply  # explicit strong-evidence apply
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

from engine import __version__ as _VERSION  # noqa: E402
from engine.services.ai_provider import AIProviderError  # noqa: E402
from engine.services.runtime import (  # noqa: E402
    DEFAULT_MODELS as _DEFAULT_MODELS,
    PROVIDER_KEY_ENV as _PROVIDER_KEY_ENV,
    build_provider,
    build_sandbox_manager,
    load_env_file,
    provider_status_rows,
    resolve_bundle_paths,
    safe_finding_id,
    sandbox_backend,
    sandbox_label,
)
from engine.services.source_graph import build_file_graph, finding_with_evidence  # noqa: E402
from engine.services.source_collector import run_recon  # noqa: E402
from engine.services.git_scope import GitScopeError, resolve_git_diff, scope_recon_to_diff  # noqa: E402
from engine.services.scan_pipeline import SwarmResult, run_agent_swarm  # noqa: E402
from engine.services.scan_workflow import ScanOptions  # noqa: E402
from engine.services.project_config import load_project_config  # noqa: E402
from engine.services.sbom import build_sbom  # noqa: E402
from engine.services.scan_archive import (  # noqa: E402
    ScanArchiveError,
    compare_scan_archives,
    list_scan_archives,
    resolve_archived_finding,
    save_scan_archive,
)
from engine.services.remediation_artifact import (  # noqa: E402
    apply_artifact,
    create_artifact,
    load_artifact,
    save_artifact,
    verify_source_state,
)
from engine.services.sarif_export import findings_to_sarif, sarif_to_pretty_json  # noqa: E402
from engine.services.html_report import findings_to_html  # noqa: E402
from engine.immune.mission import run_immune_mission  # noqa: E402
from engine.hive.mission import run_fleet_mission  # noqa: E402
from engine.ouroboros.mission import run_evolution_mission  # noqa: E402
from engine.agents.architect_agent import (  # noqa: E402
    ArchitectAgent,
    CodeLanguage,
    MutationPlan,
    ThreatFinding,
)
from engine.agents.polyglot_translator import GeneratedCodeBundle, PolyglotTranslator  # noqa: E402
from engine.agents.red_team_swarm import RedTeamSwarm  # noqa: E402
from engine.services.docker_manager import SandboxBackend, SandboxRunSpec, SandboxRuntime  # noqa: E402
from engine.ui.terminal import (  # noqa: E402
    AMBER,
    ELECTRIC_BLUE,
    EMERALD,
    GRAY,
    NEON_ORANGE,
    SEV_ORDER,
    WHITE,
    Console,
    severity_tag,
)

_LOG_FMT = "%(asctime)s | %(levelname)-7s | %(message)s"
_DATE_FMT = "%H:%M:%S"

EXIT_SECURED = 0
EXIT_VULNERABLE = 1
EXIT_MISSION_ERROR = 2


def _load_env_file() -> None:
    """Load `.env` from the script directory or CWD. Existing env vars win."""
    load_env_file((_BACKEND_DIR, Path.cwd()))


def _build_provider(provider_name: str, model_name: str | None):
    """Build the real AI core or raise ``RuntimeError`` with an actionable message."""
    provider, _name, model = build_provider(provider_name, model_name)
    return provider, model

def _probe_sandbox() -> str:
    """Hero-line status for the verification sandbox. Never makes a Nebius API call."""
    try:
        backend = sandbox_backend()
    except RuntimeError as exc:
        return f"MISCONFIGURED ({exc})"
    if backend == "nebius":
        return sandbox_label()
    try:
        import docker  # type: ignore[import-untyped]

        client = docker.from_env(timeout=2)
        version = client.version().get("Version", "unknown")
        client.close()
        return f"LOCAL DOCKER ARMED (engine {version})"
    except Exception:
        return "LOCAL DOCKER STANDBY (engine unreachable)"


class _UnavailableSandbox:
    """Stands in for a sandbox that could not be built, so missions report it cleanly.

    Every mission already wraps ``healthcheck()`` and reports failure with a
    reject exit code; raising from the factory instead would be a traceback.
    """

    def __init__(self, reason: str) -> None:
        self._reason = reason

    async def healthcheck(self) -> None:
        raise RuntimeError(self._reason)

    async def run(self, spec: SandboxRunSpec, *, log_sink=None):
        raise RuntimeError(self._reason)

    async def aclose(self) -> None:
        return None


def _sandbox_manager() -> SandboxBackend:
    """Build the verification sandbox (Nebius Sandboxes or local Docker)."""
    try:
        return build_sandbox_manager()
    except RuntimeError as exc:
        return _UnavailableSandbox(str(exc))


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


_HELLO_PROBE = "import platform, sys\nprint('ARBALEST_SANDBOX_OK', platform.system(), platform.machine(), sys.version.split()[0])\n"
_NET_PROBE = (
    "import socket\n"
    "try:\n"
    "    socket.create_connection(('1.1.1.1', 53), timeout=3).close()\n"
    "    print('ARBALEST_NETWORK_REACHABLE')\n"
    "except OSError as exc:\n"
    "    print('ARBALEST_NETWORK_BLOCKED', type(exc).__name__)\n"
)


async def _run_sandbox_check() -> int:
    """Live self-test of the verification sandbox, including proof that it is offline."""
    ui = Console(silent=False)
    ui.section("SANDBOX CHECK")
    try:
        label = sandbox_label()
    except RuntimeError as exc:
        ui.error(str(exc))
        return EXIT_MISSION_ERROR
    ui.kv("BACKEND", label, ELECTRIC_BLUE)
    sandbox = _sandbox_manager()
    try:
        try:
            with ui.spinner("credentials and permissions"):
                await sandbox.healthcheck()
        except Exception as exc:
            ui.error(f"Sandbox unreachable: {exc}")
            return EXIT_MISSION_ERROR
        ui.success("credentials and permissions accepted")

        async def probe(name: str, source: str):
            with ui.spinner(f"running {name} probe"):
                return await sandbox.run(SandboxRunSpec(
                    runtime=SandboxRuntime.PYTHON, command=("python", "probe.py"),
                    files={"probe.py": source}, name_hint=f"check-{name}",
                ))

        try:
            hello = await probe("hello", _HELLO_PROBE)
            if not hello.succeeded or "ARBALEST_SANDBOX_OK" not in hello.stdout:
                ui.error(f"Hello probe failed: {hello.error or hello.stderr.strip() or hello.status.value}")
                return EXIT_MISSION_ERROR
            ui.success(f"code ran in the sandbox ({hello.stdout.strip()}, {hello.duration_ms} ms)")

            net = await probe("network", _NET_PROBE)
        except Exception as exc:
            ui.error(f"Sandbox probe failed: {exc}")
            return EXIT_MISSION_ERROR
        if "ARBALEST_NETWORK_REACHABLE" in net.stdout:
            ui.error("ISOLATION FAILURE: code inside the sandbox reached the internet. Do not use this backend.")
            return EXIT_VULNERABLE
        if "ARBALEST_NETWORK_BLOCKED" not in net.stdout:
            ui.error(f"Network probe was inconclusive: {net.error or net.stderr.strip() or net.status.value}")
            return EXIT_MISSION_ERROR
        ui.success("network egress blocked (outbound connection failed)")
        ui.note("The sandbox runs code and is offline. Safe to use for verification.")
        return EXIT_SECURED
    finally:
        await sandbox.aclose()


def _run_providers() -> int:
    """Offline table of every provider, its credential source, and readiness."""
    ui = Console(silent=False)
    rows = provider_status_rows()
    ui.table(
        ["ID", "PROVIDER", "PROTOCOL", "CREDENTIAL", "STATUS"],
        [[r["id"], r["name"], r["protocol"], r["credential"], r["status"]] for r in rows],
        max_col=48,
    )
    try:
        sandbox = sandbox_label()
    except RuntimeError as exc:
        sandbox = f"MISCONFIGURED ({exc})"
    ui.note(f"Sandbox: {sandbox}. Any provider verifies in Nebius Sandboxes when NEBIUS_PROJECT_ID is set, otherwise local Docker.")
    ui.note("Select with --provider <id> or ARBALEST_PROVIDER. Add named endpoints in arbalest.providers.json.")
    return EXIT_SECURED


async def _run_models(provider_name: str, name_filter: str | None, model_name: str | None = None) -> int:
    """List network models or the local authenticated CLI's selected model."""
    ui = Console(silent=False)
    try:
        provider, name, _model = build_provider(provider_name, model_name, discover=True)
    except RuntimeError as exc:
        ui.error(str(exc))
        return EXIT_MISSION_ERROR
    try:
        models = await provider.list_models()
    except AIProviderError as exc:
        ui.error(f"Model discovery failed: {exc}")
        return EXIT_MISSION_ERROR
    finally:
        await provider.aclose()
    effective_filter = "nemotron" if name_filter is None and name == "nebius" else (name_filter or "")
    needle = effective_filter.strip().lower()
    shown = [m for m in models if needle in m.id.lower()]
    if not shown:
        ui.error(f"No models matching '{effective_filter}' are available to this key on {name}.")
        ui.note(f"{len(models)} model(s) are available in total. Re-run with --filter '' to list them all.")
        return EXIT_MISSION_ERROR
    is_local_cli = name in {"codex-cli", "claude-cli"}
    if is_local_cli:
        ui.table(["MODEL ID", "DETAIL"], [[m.id, m.display_name] for m in shown], max_col=72)
    else:
        ui.table(["MODEL ID"], [[m.id] for m in shown], max_col=72)
    default = _DEFAULT_MODELS.get(name, "")
    if default and not any(m.id == default for m in models):
        ui.note(f"The built-in default '{default}' is NOT available to this key. Pass -m <id> or set ARBALEST_MODEL.")
    if is_local_cli and any(model.id == "cli-default" for model in shown):
        ui.note("cli-default delegates model selection to the authenticated CLI; omit --model to use it.")
    else:
        ui.note("Use one of these ids with `-m <id>` or ARBALEST_MODEL in .env.")
    return EXIT_SECURED


def _write_patch_bundle(
    ui: Console,
    target: Path,
    bundle: GeneratedCodeBundle,
    original_sources: dict[str, str],
    patch_path: Path,
    *,
    header: str,
) -> None:
    """Write a reviewable diff after validating every generated destination."""
    resolve_bundle_paths(target, [item.path for item in bundle.files])
    diff_blocks: list[str] = []
    for generated in bundle.files:
        original = original_sources.get(generated.path, "")
        diff = _unified_diff(original, generated.content, generated.path)
        diff_blocks.append(diff if diff else f"--- /dev/null\n+++ b/{generated.path} (NEW FILE)\n")
    for generated in bundle.files:
        ui.bullet(f"artifact change: {generated.path} ({len(generated.content)} bytes)", GRAY)
    patch_path.write_text(header + "\n" + "\n".join(diff_blocks), encoding="utf-8")


def _machine_payload(
    swarm: SwarmResult, run_id: str, target: Path,
    provider: str, model: str, elapsed: float,
) -> dict[str, Any]:
    findings = []
    for finding in swarm.findings:
        row = finding.model_dump(mode="json")
        if finding.finding_id in swarm.priorities:
            row["priority"] = swarm.priorities[finding.finding_id]
        if finding.finding_id in swarm.self_check:
            row["self_check"] = swarm.self_check[finding.finding_id]
        if finding.finding_id in swarm.dispositions:
            row["operator_disposition"] = swarm.dispositions[finding.finding_id]
        findings.append(row)
    return {
        "run_id": run_id,
        "target": str(target),
        "provider": provider,
        "model": model,
        "elapsed_s": round(elapsed, 2),
        "total_findings": len(swarm.findings),
        "status": swarm.status,
        "complete": swarm.complete,
        "agent_errors": swarm.agent_errors,
                "budget": swarm.budget,
        "coverage": swarm.recon.summary() if swarm.recon else None,
        "severity_counts": swarm.severity_counts,
        "agents": {k: v.as_dict() for k, v in swarm.stats.items()},
        "findings": findings,
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
    diff_base: str | None = None,
    scan_options: ScanOptions | None = None,
    checkpoint_dir: Path | None = None,
    resume: bool = False,
) -> int:
    """Execute the full curriculum and return the mission exit code."""
    t0 = time.perf_counter()
    run_id = uuid.uuid4().hex[:12]
    machine_mode = output_file is not None and str(output_file) == "-" and output_format in ("json", "sarif")
    if output_file is not None and str(output_file) == "-" and output_format == "html":
        print("MISSION ERROR: -o - streams to stdout for json and sarif only; html requires a file path", file=sys.stderr)
        return EXIT_MISSION_ERROR
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
        ui.line("  Configure a supported provider and retry.", NEON_ORANGE)
        return EXIT_MISSION_ERROR

    ui.hero(_VERSION, provider_name, effective_model, _probe_sandbox(), str(target))

    # ── [1/4] RECON ──────────────────────────────────────────────────────
    ui.phase(1, 4, "RECON PHASE", "🔍")
    try:
        with ui.spinner("RECON — indexing source tree & mapping attack surface"):
            recon = run_recon(target)
            if diff_base:
                recon = scope_recon_to_diff(recon, resolve_git_diff(target, diff_base))
    except GitScopeError as exc:
        await provider.aclose()
        ui.error(f"DIFF SCOPE REJECTED — {exc}")
        return EXIT_MISSION_ERROR
    if not recon.files:
        await provider.aclose()
        ui.error("No source files found — nothing to defend.")
        return EXIT_MISSION_ERROR
    langs = "  ".join(f"{k}:{v}" for k, v in sorted(recon.language_counts.items(), key=lambda x: -x[1]))
    ui.kv("FILES INDEXED", str(recon.total_files), ELECTRIC_BLUE)
    ui.kv("LANGUAGES", langs or "—")
    ui.kv("MANIFESTS", ", ".join(recon.manifests) or "—")
    ui.kv("ENTRYPOINTS", f"{len(recon.entrypoints)} mapped", ELECTRIC_BLUE)
    ui.kv("SINK SIGNATURES", f"{recon.sink_hits} hits", NEON_ORANGE if recon.sink_hits else "—")
    if not recon.collection_complete:
        ui.error(f"SOURCE COVERAGE INCOMPLETE — {recon.skipped_files} file(s) skipped")
        for note in recon.coverage_notes:
            ui.note(note)

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
    try:
        swarm = await run_agent_swarm(
            provider, recon.files, recon, ui=ui, on_phase=on_phase, ledger=ledger,
            options=scan_options, checkpoint_dir=checkpoint_dir, resume=resume,
        )
    except BaseException:
        await provider.aclose()
        raise
    if swarm.injection_hits:
        ledger.record(
            actor="harness.injection_defense",
            action="scan_summary",
            verdict="fenced",
            detail=f"{len(swarm.injection_hits)} injection signature(s) detected; provider payloads were data-fenced",
        )

    try:
        scan_archive = save_scan_archive(
            target, run_id, swarm, provider=provider_name, model=effective_model,
        )
    except (OSError, ScanArchiveError) as exc:
        await provider.aclose()
        ui.error(f"SCAN ARCHIVE FAILED — {exc}")
        return EXIT_MISSION_ERROR

    # ── FINAL DEBRIEF ────────────────────────────────────────────────────
    await provider.aclose()
    counts = swarm.severity_counts
    exit_code = EXIT_MISSION_ERROR if not swarm.complete else _gate_exit_code(counts, fail_on, strict_mode)
    scan_notifications = [*swarm.agent_errors.values(), *recon.coverage_notes]
    elapsed = time.perf_counter() - t0

    if machine_mode:
        payload = _machine_payload(swarm, run_id, target, provider_name, effective_model, elapsed)
        payload["scan_archive"] = {
            "directory": str(scan_archive.directory), "seal_sha256": scan_archive.seal_sha256,
        }
        if output_format == "sarif":
            print(sarif_to_pretty_json(findings_to_sarif(
                swarm.findings, run_id=run_id, target_url=str(target), legacy_sources=recon.files,
                execution_successful=swarm.complete, notifications=scan_notifications,
            )))
        else:
            print(json.dumps(payload, indent=2, default=str))
        return exit_code

    ui.section("SWARM STATUS")
    _agent_status_table(ui, swarm)

    out_path = output_file or Path(f"arbalest-report.{output_format}")
    if output_format == "sarif":
        sarif = findings_to_sarif(
            swarm.findings, run_id=run_id, target_url=str(target), legacy_sources=recon.files,
            execution_successful=swarm.complete, notifications=scan_notifications,
        )
        out_path.write_text(sarif_to_pretty_json(sarif), encoding="utf-8")
    elif output_format == "html":
        out_path.write_text(
            findings_to_html(
                swarm.findings, execution_successful=swarm.complete, notifications=scan_notifications,
            ),
            encoding="utf-8",
        )
    else:
        report_payload = _machine_payload(swarm, run_id, target, provider_name, effective_model, elapsed)
        report_payload["scan_archive"] = {
            "directory": str(scan_archive.directory), "seal_sha256": scan_archive.seal_sha256,
        }
        out_path.write_text(json.dumps(report_payload, indent=2, default=str), encoding="utf-8")

    ui.section("FINAL DEBRIEF")
    ui.kv("RUN ID", run_id, GRAY)
    ui.kv("SEALED SCAN", str(scan_archive.directory), GRAY)
    report_label = {"sarif": "SARIF REPORT", "json": "JSON REPORT", "html": "HTML REPORT"}[output_format]
    ui.verdict(counts, len(swarm.findings), exit_code, str(out_path.resolve()), elapsed, path_label=report_label)
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

    try:
        finding_id = safe_finding_id(finding_id)
    except ValueError as exc:
        ui.error(f"FINDING REJECTED — {exc}")
        return EXIT_MISSION_ERROR
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
        await provider.aclose()
        ui.error("No source files found.")
        return EXIT_MISSION_ERROR

    finding = resolve_archived_finding(target, finding_id)
    if finding is not None:
        ui.kv("FINDING SOURCE", "sealed scan archive", ELECTRIC_BLUE)
        finding.evidence = finding.evidence[:20]
    else:
        finding = finding_with_evidence("CLI", finding_id, recon.files)
        if finding.cwe == "CWE-Unknown":
            ui.note(f"No sealed scan finding for {finding_id}; run `arbalest scan` first for grounded evidence.")
    graph = build_file_graph("cli-fix", recon.files, prioritize=finding.affected_nodes, entrypoints=recon.entrypoints)
    if finding.affected_nodes:
        ui.kv("DETECTED IN", ", ".join(finding.affected_nodes[:4]), ELECTRIC_BLUE)
    else:
        ui.note(f"No deterministic match for {finding_id}; the Architect will plan from the CWE alone.")

    # ── AGENT PROFILE: ARCHITECT-01 — writes the code ────────────────────
    ui.section("AGENT PROFILE ▸ ARCHITECT-01 — WRITES THE CODE")
    architect = ArchitectAgent(provider=provider)
    try:
        with ui.spinner("ARCHITECT-01 — formulating mutation plan"):
            plan: MutationPlan = await architect.create_plan(
                graph_context=graph,
                findings=[finding],
                developer_task=f"Fix the {finding_id} vulnerability in this codebase",
                available_files=recon.files,
                target_language=CodeLanguage.AUTO,
            )
    except Exception as exc:
        await provider.aclose()
        ui.error(f"ARCHITECT-01 failed: {exc}")
        return EXIT_MISSION_ERROR

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
        await provider.aclose()
        ui.error(f"POLYGLOT-02 failed: {exc}")
        return EXIT_MISSION_ERROR

    # Persist the exact generated bytes as an immutable remediation artifact.
    ui.section("PATCH PROPOSAL")
    patch_path = target / f"arbalest-fix-{finding_id}.patch"
    try:
        artifact = create_artifact(finding, plan, bundle, recon.files)
        artifact_path = save_artifact(target, artifact)
        _write_patch_bundle(
            ui, target, bundle, recon.files, patch_path,
            header=(f"# Arbalest Auto-Remediation — {finding_id}\n"
                    f"# plan: {plan.plan_id}  artifact: {artifact.artifact_id}  bundle: {artifact.bundle_sha256}\n"),
        )
    except (OSError, ValueError) as exc:
        await provider.aclose()
        ui.error(f"PATCH WRITE REFUSED: {exc}")
        return EXIT_MISSION_ERROR
    await provider.aclose()
    ui.kv("PATCH FILE", str(patch_path), ELECTRIC_BLUE)
    ui.kv("ARTIFACT ID", artifact.artifact_id, ELECTRIC_BLUE)
    ui.kv("ARTIFACT", str(artifact_path), GRAY)
    ui.note("Nothing changed in the source tree. Review the patch, then verify the immutable artifact.")

    ui.section("FINAL DEBRIEF")
    ui.verdict(
        {}, 0, EXIT_SECURED, str(patch_path), time.perf_counter() - t0,
        headline="PATCH PROPOSED — AWAITING VERIFICATION", headline_color=AMBER, path_label="PATCH FILE",
    )
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
    artifact_reference: str | None = None,
    apply_verified: bool = False,
) -> int:
    t0 = time.perf_counter()
    ui = Console(silent=False)
    logging.basicConfig(level=logging.DEBUG if verbose else logging.CRITICAL,
                        format=_LOG_FMT, datefmt=_DATE_FMT, stream=sys.stderr)

    try:
        finding_id = safe_finding_id(finding_id)
    except ValueError as exc:
        ui.error(f"FINDING REJECTED — {exc}")
        return EXIT_MISSION_ERROR
    if not target.exists() or not target.is_dir():
        ui.error(f"TARGET REJECTED — not a directory: {target}")
        return EXIT_MISSION_ERROR

    ui.hero(_VERSION, provider_name, model_name or "auto", _probe_sandbox(), str(target))

    sandbox = _sandbox_manager()
    try:
        with ui.spinner("SANDBOX — negotiating with the verification sandbox"):
            await sandbox.healthcheck()
        ui.success("Verification sandbox reachable — ranges hot.")
    except Exception as exc:
        # Infrastructure problem, not a verdict on the patch: exit 2, not 1.
        await sandbox.aclose()
        ui.error("The verification sandbox is unreachable.")
        ui.line(f"    {exc}", GRAY)
        ui.note("Run `arbalest sandbox-check` to diagnose, or set ARBALEST_SANDBOX_BACKEND=docker.")
        return EXIT_MISSION_ERROR

    try:
        provider, effective_model = _build_provider(provider_name, model_name)
    except RuntimeError as exc:
        await sandbox.aclose()
        ui.error(str(exc))
        return EXIT_MISSION_ERROR

    try:
        with ui.spinner("ARTIFACT — validating immutable remediation"):
            artifact, artifact_path = load_artifact(target, artifact_reference, finding_id)
            verify_source_state(target, artifact)
    except (OSError, ValueError) as exc:
        await provider.aclose()
        await sandbox.aclose()
        ui.error(f"ARTIFACT REJECTED — {exc}")
        return EXIT_MISSION_ERROR

    finding = artifact.finding
    plan = artifact.plan
    bundle = artifact.bundle
    ui.kv("ARTIFACT ID", artifact.artifact_id, ELECTRIC_BLUE)
    ui.kv("BUNDLE HASH", artifact.bundle_sha256, GRAY)
    ui.kv("ARTIFACT", str(artifact_path), GRAY)

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
        await provider.aclose()
        await sandbox.aclose()
        ui.error(f"REDTEAM-SWARM engagement failed: {exc}")
        return EXIT_MISSION_ERROR

    await provider.aclose()
    await sandbox.aclose()

    # ── MEMBER STORY — the case file ─────────────────────────────────────
    ui.section("MEMBER STORY ▸ ADVERSARIAL CASE FILE")
    held = result.verification_held
    verdict_txt = "PATCH HELD — CODE SURVIVED THE SWARM" if held else "PATCH BREACHED — CODE FAILED VERIFICATION"
    ui.kv("CASE SUBJECT", f"{finding_id} @ {target}", ELECTRIC_BLUE)
    ui.kv("ATTACK OBJECTIVE", result.attack.objective)
    ui.kv("EXPLOIT RESULT", "SUCCEEDED (breach)" if result.analysis.exploit_successful else "REPELLED")
    ui.kv("SANDBOX RUN", f"{result.sandbox.status.value} / exit {result.sandbox.exit_code}",
          EMERALD if result.sandbox.succeeded else NEON_ORANGE)
    if result.sandbox.error:
        ui.kv("SANDBOX ERROR", result.sandbox.error[:300], NEON_ORANGE)
    ui.kv("CONFIDENCE", f"{result.analysis.confidence:.2f}")
    ui.print()
    ui.line(f"  VERDICT: {verdict_txt}", EMERALD if held else NEON_ORANGE, bold=True)
    ui.print()
    ui.bullet(result.analysis.reasoning, GRAY)
    for ev in result.analysis.evidence[:5]:
        ui.bullet(f"evidence: {ev}", GRAY)

    if held:
        patch_path = target / f"arbalest-verified-{finding_id}.patch"
        try:
            original_sources = {
                path: ((target / path).read_text(encoding="utf-8", errors="replace") if (target / path).is_file() else "")
                for path in artifact.source_hashes
            }
            _write_patch_bundle(
                ui, target, bundle, original_sources, patch_path,
                header=(f"# Arbalest Verified Patch — {finding_id}\n# plan: {plan.plan_id}  "
                        f"artifact: {artifact.artifact_id}  red-team: PASSED  tier: {result.verification_tier}\n"),
            )
        except (OSError, ValueError) as exc:
            ui.error(f"VERIFIED PATCH WRITE REFUSED: {exc}")
            return EXIT_MISSION_ERROR

        ui.kv("EVIDENCE TIER", result.verification_tier, ELECTRIC_BLUE)
        if apply_verified:
            if not result.automated_deployment_allowed:
                ui.error(
                    "APPLY BLOCKED — unattended deployment requires adversarial evidence "
                    "with confidence >= 0.70; the verified patch was left for review."
                )
                return EXIT_MISSION_ERROR
            try:
                apply_artifact(target, artifact)
            except (OSError, ValueError) as exc:
                ui.error(f"ATOMIC DEPLOYMENT REFUSED: {exc}")
                return EXIT_MISSION_ERROR
            headline = "EXACT ARTIFACT VERIFIED AND EXPLICITLY APPLIED"
        else:
            ui.note("Verification never writes source by default. Review the patch, then rerun with --apply if appropriate.")
            headline = "EXACT ARTIFACT VERIFIED — SOURCE UNCHANGED"

        ui.section("FINAL DEBRIEF")
        ui.verdict(
            {}, 0, EXIT_SECURED, str(patch_path), time.perf_counter() - t0,
            headline=headline, path_label="PATCH FILE",
        )
        return EXIT_SECURED

    if result.analysis.inconclusive and not result.analysis.exploit_successful:
        ui.error("Verification INCONCLUSIVE: the harness did not finish. Nothing was written to the target.")
    else:
        ui.error("Patch REJECTED by the swarm. Nothing was written to the target.")
    ui.section("FINAL DEBRIEF")
    ui.verdict({"critical": 1}, 1, EXIT_VULNERABLE, None, time.perf_counter() - t0)
    return EXIT_VULNERABLE


def _run_history(target: Path, limit: int) -> int:
    if not target.is_dir():
        print(f"Invalid target directory: {target}", file=sys.stderr)
        return EXIT_MISSION_ERROR
    rows = list_scan_archives(target, limit=limit)
    print(json.dumps(rows, indent=2, default=str))
    return EXIT_SECURED


def _run_compare(target: Path, before: str, after: str) -> int:
    if not target.is_dir():
        print(f"Invalid target directory: {target}", file=sys.stderr)
        return EXIT_MISSION_ERROR
    try:
        comparison = compare_scan_archives(target, before, after)
    except ScanArchiveError as exc:
        print(f"Scan comparison failed: {exc}", file=sys.stderr)
        return EXIT_MISSION_ERROR
    print(json.dumps(comparison, indent=2, default=str))
    return EXIT_SECURED


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    providers = ", ".join(_PROVIDER_KEY_ENV)
    parser = argparse.ArgumentParser(
        prog="arbalest",
        description=(
            "Arbalest — security-first agentic code analysis and remediation. "
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
    scan_p.add_argument("--diff-base", type=str, default=None,
                        help="Scan files changed from a Git revision through the current working tree")
    scan_p.add_argument("--strict", action="store_true",
                        help="Strict enterprise mode — INFO findings also fail the gate")
    scan_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                        default="low",
                        help="Exit 1 when findings at/above this severity exist (default: low → 0 safe, 1 vulnerable)")
    scan_p.add_argument("--hypotheses", dest="review_hypotheses", action="store_true", default=None,
                        help="Agentic discovery: one extra model call derives target-specific review "
                             "priorities from recon and steers the SAST reviewer (unknown vulnerability classes)")
    scan_p.add_argument("--self-check", dest="sast_self_check", action="store_true", default=None,
                        help="Adversarial self-verification: one extra model call confirms or challenges "
                             "each SAST finding against the source; findings are annotated, never deleted")
    _add_provider_args(scan_p)
    scan_p.set_defaults(provider=None)
    scan_p.add_argument("--config", help="Credential-free project JSON (default: TARGET/arbalest.json)")
    scan_p.add_argument("--checkpoint-dir", help="Private durable workflow directory")
    scan_p.add_argument("--resume", action="store_true", help="Resume a matching checkpoint")
    for flag in ("concurrency", "max-model-calls", "max-retries", "per-call-model-calls"):
        scan_p.add_argument(f"--{flag}", type=int, default=None)
    for flag in ("max-seconds", "call-timeout-seconds", "max-cost-usd", "per-call-reserve-usd"):
        scan_p.add_argument(f"--{flag}", type=float, default=None)

    preflight_p = sub.add_parser("preflight", help="Offline configuration and coverage checks (no API spend)")
    preflight_p.add_argument("target")
    preflight_p.add_argument("--config")
    preflight_p.add_argument("--format", choices=["json"], default="json")
    sbom_p = sub.add_parser("sbom", help="Generate an offline CycloneDX dependency inventory")
    sbom_p.add_argument("target")
    sbom_p.add_argument("--output", "-o", default="-")

    disposition_p = sub.add_parser(
        "disposition", help="Record operator feedback for a finding (persists across scans)",
    )
    disposition_p.add_argument("target", help="Repository directory that was scanned")
    disposition_p.add_argument("--finding", "-f", required=True, help="Finding id from a scan report")
    disposition_p.add_argument("--verdict", required=True, choices=["false-positive", "accepted"],
                               help="false-positive ranks the finding down in future scans; accepted acknowledges it")
    disposition_p.add_argument("--note", default="", help="Optional justification (max 500 chars)")

    probe_p = sub.add_parser(
        "probe", help="Live read-only checks against a running service (DAST seed)",
        description=(
            "Scope-gated live probing: missing security headers, verbose errors,\n"
            "version disclosure and open redirects are only observable on a running\n"
            "service. Defensive-only scoping: targets must be explicitly allowlisted\n"
            "with --allow-host or be local when --allow-private is set. Bounded GETs;\n"
            "nothing is mutated; no model required."
        ),
    )
    probe_p.add_argument("url", help="Absolute http(s) URL to probe")
    probe_p.add_argument("--allow-host", action="append", default=[],
                         help="Explicitly allowlisted hostname (repeatable; required for non-local targets)")
    probe_p.add_argument("--allow-private", action="store_true",
                         help="Allow local/private network targets for local testing")
    probe_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="low")

    fix_p = sub.add_parser("fix", help="Autonomously remediate a vulnerability (Architect writes)")
    fix_p.add_argument("target", type=str, help="Repository directory to fix")
    fix_p.add_argument("--finding", "-f", type=str, required=True,
                       help="Vulnerability ID or CWE to remediate (e.g. CWE-89)")
    _add_provider_args(fix_p)

    sub.add_parser(
        "providers",
        help="List every AI provider (API, gateway, local, subscription CLI) and whether it is ready",
    )

    sub.add_parser(
        "sandbox-check",
        help="Prove the verification sandbox works and is offline (run this before a demo)",
        description=(
            "Runs two tiny probes in the configured verification sandbox: a hello probe, and a\n"
            "network probe that must FAIL to connect. Exit 0 = working and offline,\n"
            "1 = sandbox could reach the internet (do not use it), 2 = could not run the check."
        ),
    )

    models_p = sub.add_parser(
        "models",
        help="List models available to the selected provider key",
    )
    models_p.add_argument("--filter", type=str, default=None,
                          help="Optional case-insensitive model-id filter (Nebius defaults to 'nemotron')")
    _add_provider_args(models_p)

    verify_p = sub.add_parser(
        "verify",
        help="Adversarially verify a patch without modifying source (use --apply for an explicit write)",
    )
    verify_p.add_argument("target", type=str, help="Repository directory to verify")
    verify_p.add_argument("--finding", "-f", type=str, required=True,
                          help="Vulnerability ID or CWE to verify against (e.g. CWE-89)")
    verify_p.add_argument("--artifact", type=str, default=None,
                          help="Artifact id or repository-relative artifact path (default: latest exact finding artifact)")
    verify_p.add_argument(
        "--apply", action="store_true",
        help="Explicitly apply the exact artifact after strong adversarial verification (never used for signature-only evidence)",
    )
    _add_provider_args(verify_p)

    immune_p = sub.add_parser(
        "immune",
        help="Immune System mode — blast-radius topology, adversarial war-game, antibody synthesis",
        description=(
            "Immune System mode — the codebase is a living organism; Arbalest is the swarm of antibodies.\n"
            "[1/3] Topological blast-radius mapping proves the attack chain from public API to sink.\n"
            "[2/3] Adversarial war-game: ArchitectAgent vs RedTeamSwarm minimax loop in the verification sandbox.\n"
            "[3/3] Antibody generation: a self-tested Semgrep rule is synthesized from real breaches."
        ),
    )
    immune_p.add_argument("target", type=str, help="Repository directory to defend")
    immune_p.add_argument("--iterations", type=int, default=4,
                          help="Max war-game iterations per finding (default: 4)")
    immune_p.add_argument("--max-findings", type=int, default=3,
                          help="Max sinks to defend in one mission (default: 3)")
    immune_p.add_argument("--no-sandbox", action="store_true",
                          help="Skip sandbox verification (patches will NOT be certified)")
    immune_p.add_argument("--deploy", action="store_true",
                          help="Write verified heals into the working tree (default: stage reviewable patches only)")
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
                          help="Skip sandbox verification (patches will NOT be certified)")
    fleet_p.add_argument("--no-gitops", action="store_true",
                          help="Skip synchronized branch/commit/PR flow (requires --deploy)")
    fleet_p.add_argument("--deploy", action="store_true",
                          help="Write verified heals into working trees and run GitOps "
                               "(default: stage reviewable patches only, nothing is written or pushed)")
    _add_provider_args(fleet_p)

    evolve_p = sub.add_parser(
        "evolve",
        help="Ouroboros Protocol — Arbalest rewrites, mirror-proofs, and commits its own source",
        description=(
            "Ouroboros Protocol — experimental governed self-modification.\n"
            "[1/4] Meta-graph construction: the federation engine maps the organism inward.\n"
            "[2/4] Capability synthesis: the Architect writes the feature into Arbalest itself;\n"
            "      the constitution reviews every byte (protected paths, bounds, loop guard).\n"
            "[3/4] Recursive wargaming: the mutated organism boots inside the verification sandbox and\n"
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

    history_p = sub.add_parser("history", help="List verified local scan archives")
    history_p.add_argument("target", type=str, help="Repository containing .arbalest scan history")
    history_p.add_argument("--limit", type=int, default=20, help="Maximum archives to list (1-100)")

    compare_p = sub.add_parser("compare", help="Compare two sealed scan archives")
    compare_p.add_argument("target", type=str, help="Repository containing the scan archives")
    compare_p.add_argument("--before", required=True, help="Earlier 12-character scan id")
    compare_p.add_argument("--after", required=True, help="Later 12-character scan id")

    return parser


def main() -> None:
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    _load_env_file()
    args = _build_parser().parse_args()
    try:
        if args.command == "preflight":
            config = load_project_config(Path(args.target), Path(args.config) if args.config else None)
            report = config.preflight(Path(args.target))
            print(json.dumps(report, indent=2))
            rc = EXIT_SECURED if report["ready"] else EXIT_MISSION_ERROR
        elif args.command == "sbom":
            from engine.agents.sca_agent import collect_dependencies
            recon = run_recon(Path(args.target))
            report = build_sbom(recon.files)
            report["metadata"]["properties"].append({
                "name": "arbalest:source-collection-complete", "value": str(recon.collection_complete).lower(),
            })
            if not recon.collection_complete:
                report["compositions"][0]["aggregate"] = "incomplete"
            text = json.dumps(report, indent=2)
            if args.output == "-":
                print(text)
            else:
                Path(args.output).write_text(text, encoding="utf-8")
            _, coverage = collect_dependencies(recon.files)
            rc = EXIT_SECURED if coverage.complete and recon.collection_complete else EXIT_MISSION_ERROR
        elif args.command == "disposition":
            from engine.services.dispositions import record_disposition
            target = Path(args.target)
            if not target.is_dir():
                print(f"MISSION ERROR: not a directory: {target}", file=sys.stderr)
                rc = EXIT_MISSION_ERROR
            else:
                try:
                    path = record_disposition(target, args.finding, args.verdict, args.note)
                    print(f"recorded {args.verdict} for {args.finding}")
                    print(f"persisted {path}")
                    print("future scans will annotate and rank down this finding id")
                    rc = EXIT_SECURED
                except (OSError, ValueError) as exc:
                    print(f"MISSION ERROR: {exc}", file=sys.stderr)
                    rc = EXIT_MISSION_ERROR
        elif args.command == "probe":
            from engine.agents.black_box_fuzzer import FuzzingPolicy, ScopeViolation
            from engine.agents.live_probe import run_probe

            async def _probe() -> int:
                ui = Console(silent=False)
                policy = FuzzingPolicy(
                    allowed_hosts=frozenset(host.lower() for host in args.allow_host),
                    allow_private_networks=args.allow_private,
                )
                ui.hero(_VERSION, "—", "deterministic", "LIVE PROBE (scope-gated)", args.url)
                try:
                    result = await run_probe(args.url, policy=policy)
                except ScopeViolation as exc:
                    ui.error(f"SCOPE REJECTED — {exc}")
                    return EXIT_MISSION_ERROR
                except ValueError as exc:
                    ui.error(f"PROBE REJECTED — {exc}")
                    return EXIT_MISSION_ERROR
                ui.kv("REQUESTS SENT", str(result.requests), ELECTRIC_BLUE)
                counts: dict[str, int] = {}
                for finding in result.findings:
                    counts[str(finding.severity).lower()] = counts.get(str(finding.severity).lower(), 0) + 1
                    ui.line(f"  {severity_tag(str(finding.severity))} {finding.cwe} — {finding.summary[7:]}", WHITE)
                    for item in finding.evidence[:3]:
                        ui.line(f"      {item}", GRAY)
                if result.scope_note:
                    ui.note(result.scope_note)
                rc = _gate_exit_code(counts, args.fail_on, False)
                ui.verdict(counts, len(result.findings), rc, None, 0.0,
                           headline="LIVE PROBE COMPLETE", headline_color=ELECTRIC_BLUE)
                return rc

            rc = asyncio.run(_probe())
        elif args.command == "scan":
            from dataclasses import asdict
            config = load_project_config(Path(args.target), Path(args.config) if args.config else None)
            values = asdict(config.scan)
            for name in values:
                override = getattr(args, name, None)
                if override is not None:
                    values[name] = override
            options = ScanOptions.from_mapping(values)
            rc = asyncio.run(_run_scan(
                target=Path(args.target),
                provider_name=args.provider or config.provider or os.environ.get("ARBALEST_PROVIDER", "nebius"),
                model_name=args.model or config.model,
                output_format=args.format,
                output_file=Path(args.output) if args.output else None,
                strict_mode=args.strict,
                verbose=args.verbose,
                fail_on=args.fail_on,
                diff_base=args.diff_base,
                scan_options=options,
                checkpoint_dir=Path(args.checkpoint_dir) if args.checkpoint_dir else None,
                resume=args.resume,
            ))
        elif args.command == "fix":
            rc = asyncio.run(_run_fix(
                target=Path(args.target), finding_id=args.finding,
                provider_name=args.provider, model_name=args.model, verbose=args.verbose,
            ))
        elif args.command == "providers":
            rc = _run_providers()
        elif args.command == "sandbox-check":
            rc = asyncio.run(_run_sandbox_check())
        elif args.command == "models":
            rc = asyncio.run(_run_models(args.provider, args.filter, args.model))
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
                deploy=args.deploy,
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
                deploy=args.deploy,
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
        elif args.command == "history":
            rc = _run_history(Path(args.target), max(1, min(args.limit, 100)))
        elif args.command == "compare":
            rc = _run_compare(Path(args.target), args.before, args.after)
        else:
            rc = asyncio.run(_run_verify(
                target=Path(args.target), finding_id=args.finding,
                provider_name=args.provider, model_name=args.model, verbose=args.verbose,
                artifact_reference=args.artifact,
                apply_verified=args.apply,
            ))
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        print(f"MISSION ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        rc = EXIT_MISSION_ERROR
    except KeyboardInterrupt:
        print("\n  ✗ MISSION ABORTED BY OPERATOR", file=sys.stderr)
        rc = EXIT_MISSION_ERROR
    sys.exit(rc)


if __name__ == "__main__":
    main()
