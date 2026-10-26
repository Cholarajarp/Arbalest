#!/usr/bin/env python3
"""
Arbalest MCP Server — Model Context Protocol interface to the security engine.

Runs on stdio using newline-delimited JSON-RPC 2.0 (the MCP stdio transport).
Content-Length framed requests are also accepted for LSP-style clients.

Tools (all real, all backed by the engine):
  scan_repository    — full curriculum: RECON → AST → DEPENDENCY CHECK → THREAT RAG,
                       writes <target>/arbalest-report.sarif
  scan_code_snippet  — SAST analysis of a single snippet
  fix_vulnerability  — ArchitectAgent + PolyglotTranslator produce an immutable
                       artifact and reviewable diff; no source is deployed from MCP
  verify_fix         — RedTeamSwarm verifies the exact artifact inside the
                       configured sandbox and returns the verdict without deployment
  query_threat_intel — retrieval against workspace-local SQLite threat memory
  list_scan_history  — verify and list sealed scan archives
  compare_scan_runs  — compare new, persistent, and resolved findings

Host-agent (providerless) remediation mode:
  When the MCP host (Claude Code, Codex, Kiro, Cursor, …) does its own reasoning
  on its own subscription, Arbalest supplies grounding, validation, sealing, and
  verification instead of calling an AI provider itself. These three tools take
  no provider/model arguments:
    prepare_remediation_context  — ground the host: bounded, secret-redacted
                                    sources, an architecture graph, a context
                                    digest, and the plan/bundle/attack schemas
    submit_remediation_candidate — validate and seal a host-authored plan and
                                    code bundle into an immutable artifact and a
                                    reviewable patch; nothing is applied
    verify_remediation_candidate — run the sealed artifact in the sandbox and
                                    compute the verdict server-side; nothing is
                                    deployed, and no host-supplied verdict is
                                    ever trusted

MCP client configuration:
  Install the wheel, run `arbalest-mcp`, and follow docs/mcp-clients.md.
  Provider credentials remain in the spawned process environment and are never
  accepted as MCP tool arguments.
"""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import logging
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Protocol

from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Resolve backend imports
# ---------------------------------------------------------------------------
_BACKEND_DIR = Path(__file__).resolve().parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from engine import __version__ as SERVER_VERSION  # noqa: E402
from engine.services.runtime import (  # noqa: E402
    PROVIDER_KEY_ENV as _PROVIDER_KEY_ENV,
    build_provider,
    build_sandbox_manager,
    load_env_file,
    resolve_bundle_paths,
    resolve_target,
    safe_finding_id,
)
from engine.services.source_collector import collect_sources, run_recon  # noqa: E402
from engine.services.git_scope import GitScopeError, resolve_git_diff, scope_recon_to_diff  # noqa: E402
from engine.services.scan_pipeline import run_agent_swarm  # noqa: E402
from engine.services.scan_archive import (  # noqa: E402
    ScanArchiveError,
    compare_scan_archives,
    list_scan_archives,
    resolve_archived_finding,
    save_scan_archive,
)
from engine.services.remediation_artifact import (  # noqa: E402
    create_artifact,
    create_validated_artifact,
    load_artifact,
    save_artifact,
    verify_source_state,
)
from engine.services.sarif_export import findings_to_sarif, sarif_to_pretty_json  # noqa: E402
from engine.agents.architect_agent import (  # noqa: E402
    ArchitectAgent,
    CodeLanguage,
    MutationPlan,
)
from engine.agents.polyglot_translator import GeneratedCodeBundle, PolyglotTranslator  # noqa: E402
from engine.agents.red_team_swarm import (  # noqa: E402
    AttackScript,
    RedTeamSwarm,
    execute_deterministic_verification,
)
from engine.agents.sast_agent import SastAgent  # noqa: E402
from engine.agents.secret_scanner import redact_secrets  # noqa: E402
from engine.services.docker_manager import SandboxBackend  # noqa: E402
from engine.services.source_graph import build_file_graph, finding_with_evidence  # noqa: E402
from engine.services.vector_memory import vector_memory  # noqa: E402

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s | %(levelname)-7s | %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("arbalest-mcp")

JSONRPC_VERSION = "2.0"
SERVER_NAME = "arbalest"
_SUPPORTED_PROTOCOL_VERSIONS = {"2024-10-07", "2024-11-05", "2025-03-26", "2025-06-18"}

def _build_provider(provider_name: str | None = None, model: str | None = None):
    """Build the real AI core from the environment."""
    provider, name, effective_model = build_provider(provider_name, model)
    return provider, name, effective_model


def _sandbox_manager() -> SandboxBackend:
    return build_sandbox_manager()


def _target_dir(args: dict[str, Any]) -> Path:
    """Resolve and validate the MCP target path (honours ARBALEST_MCP_ALLOWED_ROOTS)."""
    raw = args.get("target_path")
    if not isinstance(raw, str) or not raw.strip():
        raise RuntimeError("target_path is required")
    try:
        target = resolve_target(raw)
    except PermissionError as exc:
        raise RuntimeError(str(exc)) from exc
    if not target.exists() or not target.is_dir():
        raise RuntimeError(f"Invalid target directory: {raw}")
    return target


def _finding_arg(args: dict[str, Any]) -> str:
    try:
        return safe_finding_id(str(args.get("finding", "")))
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc

# ---------------------------------------------------------------------------
# Tool implementations — all real engine paths
# ---------------------------------------------------------------------------
async def _tool_scan_repository(args: dict[str, Any]) -> list[dict[str, str]]:
    target = _target_dir(args)
    provider, prov, model = _build_provider(args.get("provider"), args.get("model"))
    try:
        recon = run_recon(target)
        diff_base = args.get("diff_base")
        if diff_base is not None:
            if not isinstance(diff_base, str) or not diff_base:
                raise RuntimeError("diff_base must be a Git revision string")
            try:
                recon = scope_recon_to_diff(recon, resolve_git_diff(target, diff_base))
            except GitScopeError as exc:
                raise RuntimeError(str(exc)) from exc
        if not recon.files:
            raise RuntimeError(f"No source files found in {target}")
        run_id = uuid.uuid4().hex[:12]
        swarm = await run_agent_swarm(provider, recon.files, recon)
    finally:
        await provider.aclose()

    try:
        archive = save_scan_archive(target, run_id, swarm, provider=prov, model=model or "")
    except (OSError, ScanArchiveError) as exc:
        raise RuntimeError(f"scan archive could not be sealed: {exc}") from exc

    notifications = [*swarm.agent_errors.values(), *recon.coverage_notes]
    sarif_path = target / "arbalest-report.sarif"
    sarif_path.write_text(
        sarif_to_pretty_json(findings_to_sarif(
            swarm.findings, run_id=run_id, target_url=str(target), legacy_sources=recon.files,
            execution_successful=swarm.complete, notifications=notifications,
        )),
        encoding="utf-8",
    )
    if not swarm.complete:
        detail = "; ".join(notifications) or "scan coverage was incomplete"
        raise RuntimeError(f"INCOMPLETE SCAN — no clean verdict was issued: {detail}")

    lines = [
        f"## 🛡 Arbalest Scan — {target}",
        f"**Run:** {run_id}  |  **Core:** {prov}/{model}",
        f"**Recon:** {recon.total_files} files, {len(recon.entrypoints)} entrypoints, {recon.sink_hits} sink signatures",
        f"**Total findings:** {len(swarm.findings)}", "",
    ]
    for name, stat in swarm.stats.items():
        icon = "✅" if stat.status == "ok" else "⏭️"
        detail = f" — {stat.detail}" if stat.detail else ""
        lines.append(f"- {icon} **{name}**: {stat.status}, {stat.count} finding(s){detail}")
    lines.append("")
    for finding in swarm.findings[:20]:
        location = finding.affected_nodes[0] if finding.affected_nodes else "—"
        lines.append(f"- **[{str(finding.severity).upper()}]** {finding.summary} ({finding.cwe}) @ {location}")
    if len(swarm.findings) > 20:
        lines.append(f"- … +{len(swarm.findings) - 20} more")
    lines += ["", f"**SARIF report:** `{sarif_path}`", f"**Sealed scan archive:** `{archive.directory}`"]
    return [{"type": "text", "text": "\n".join(lines)}]


async def _tool_scan_code_snippet(args: dict[str, Any]) -> list[dict[str, str]]:
    code = args.get("code")
    filename = args.get("filename", "snippet.py")
    if not isinstance(code, str) or not code or len(code) > 200_000:
        raise RuntimeError("code must be a non-empty string of at most 200,000 characters")
    if not isinstance(filename, str) or not filename or len(filename) > 240 or ".." in Path(filename).parts:
        raise RuntimeError("filename must be a safe relative name")
    provider, _prov, _model = _build_provider(args.get("provider"), args.get("model"))
    agent = SastAgent(provider)
    try:
        findings = await agent.analyze({filename: code})
    finally:
        await provider.aclose()
    if not agent.coverage.complete:
        return [{
            "type": "text",
            "text": f"⚠️ SAST INCOMPLETE — {agent.coverage.detail}. No clean verdict was issued.",
        }]
    if not findings:
        return [{"type": "text", "text": "✅ No vulnerabilities found in the provided snippet within recorded SAST coverage."}]
    lines = ["## 🔍 SAST Findings", ""]
    for finding in findings:
        lines += [
            f"- **[{str(finding.severity).upper()}]** {finding.summary} ({finding.cwe})",
            *(f"  - evidence: {evidence}" for evidence in finding.evidence[:3]),
        ]
    return [{"type": "text", "text": "\n".join(lines)}]


async def _plan_and_bundle(
    target: Path, finding_id: str, provider_name: str | None, model: str | None,
):
    """Create one immutable remediation candidate and close its provider."""
    provider, _prov, _model = _build_provider(provider_name, model)
    try:
        sources = collect_sources(target)
        if not sources:
            raise RuntimeError(f"No source files found in {target}")
        finding = resolve_archived_finding(target, finding_id)
        if finding is None:
            finding = finding_with_evidence("MCP", finding_id, sources)
        graph = build_file_graph("mcp-fix", sources, prioritize=finding.affected_nodes)
        plan = await ArchitectAgent(provider=provider).create_plan(
            graph_context=graph,
            findings=[finding],
            developer_task=f"Fix the {finding_id} vulnerability in this codebase",
            available_files=sources,
            target_language=CodeLanguage.AUTO,
        )
        bundle = await PolyglotTranslator(provider=provider).translate(
            legacy_sources=sources, mutation_plan=plan,
        )
        return finding, plan, bundle, sources
    finally:
        await provider.aclose()


def _bundle_diff(bundle, sources: dict[str, str]) -> str:
    blocks: list[str] = []
    for generated in bundle.files:
        original = sources.get(generated.path, "")
        diff = "".join(difflib.unified_diff(
            original.splitlines(keepends=True),
            generated.content.splitlines(keepends=True),
            fromfile=f"a/{generated.path}",
            tofile=f"b/{generated.path} (SECURED)",
        ))
        blocks.append(diff or f"--- /dev/null\n+++ b/{generated.path} (NEW FILE)\n")
    return "\n".join(blocks)


async def _tool_fix_vulnerability(args: dict[str, Any]) -> list[dict[str, str]]:
    target = _target_dir(args)
    finding_id = _finding_arg(args)
    finding, plan, bundle, sources = await _plan_and_bundle(
        target, finding_id, args.get("provider"), args.get("model")
    )
    diff = _bundle_diff(bundle, sources)
    resolve_bundle_paths(target, [item.path for item in bundle.files])
    artifact = create_artifact(finding, plan, bundle, sources)
    artifact_path = save_artifact(target, artifact)
    patch_path = target / f"arbalest-fix-{finding_id}.patch"
    patch_path.write_text(
        f"# Arbalest Auto-Remediation — {finding_id}\n# plan: {plan.plan_id}  artifact: {artifact.artifact_id}\n\n{diff}",
        encoding="utf-8",
    )
    text = (
        f"## 🔧 Remediation plan {plan.plan_id} for {finding_id}\n"
        + "\n".join(f"- {step.action.value} → {step.target_file}: {step.rationale}" for step in plan.mutations)
        + f"\n\n**Artifact:** `{artifact.artifact_id}` at `{artifact_path}`\n"
        + f"**Reviewable patch:** `{patch_path}` (not applied)\n\n```diff\n{diff}\n```"
    )
    return [{"type": "text", "text": text}]


async def _tool_verify_fix(args: dict[str, Any]) -> list[dict[str, str]]:
    target = _target_dir(args)
    finding_id = _finding_arg(args)
    reference = args.get("artifact")
    if reference is not None and not isinstance(reference, str):
        raise RuntimeError("artifact must be an artifact id or repository-relative path")
    artifact, artifact_path = load_artifact(target, reference, finding_id)
    verify_source_state(target, artifact)

    sandbox = _sandbox_manager()
    provider = None
    try:
        await sandbox.healthcheck()
        provider, _prov, _model = _build_provider(args.get("provider"), args.get("model"))
        swarm = RedTeamSwarm(sandbox=sandbox, provider=provider)
        result = await swarm.execute(
            generated_code=artifact.bundle,
            mutation_plan=artifact.plan,
            findings=[artifact.finding],
        )
    except Exception as exc:
        raise RuntimeError(f"verification could not complete: {exc}") from exc
    finally:
        if provider is not None:
            await provider.aclose()
        await sandbox.aclose()

    if result.automated_deployment_allowed:
        verdict = "✅ EXACT ARTIFACT HELD — strong evidence; eligible for an explicit reviewed CLI apply"
    elif result.verification_held:
        verdict = (
            f"⚠️ ARTIFACT HELD AT {result.verification_tier.upper()} TIER — "
            "insufficient evidence for source deployment"
        )
    elif result.analysis.inconclusive and not result.analysis.exploit_successful:
        verdict = "⚠️ INCONCLUSIVE — nothing is proven; do not deploy"
    else:
        verdict = "❌ ARTIFACT BREACHED — do not deploy"
    text = (
        f"## ⚔ RedTeamSwarm Case File — {finding_id}\n"
        f"- **Artifact:** {artifact.artifact_id} (`{artifact_path}`)\n"
        f"- **Bundle SHA-256:** {artifact.bundle_sha256}\n"
        f"- **Objective:** {result.attack.objective}\n"
        f"- **Exploit:** {'SUCCEEDED (breach)' if result.analysis.exploit_successful else 'REPELLED'}\n"
        f"- **Sandbox:** {result.sandbox.status.value} / exit {result.sandbox.exit_code}\n"
        f"- **Confidence:** {result.analysis.confidence:.2f}\n"
        f"- **Verification tier:** {result.verification_tier}\n"
        f"- **Verdict:** {verdict}\n"
        f"- **Analysis:** {result.analysis.reasoning}"
    )
    return [{"type": "text", "text": text}]


async def _tool_query_threat_intel(args: dict[str, Any]) -> list[dict[str, str]]:
    """Retrieve bounded records from workspace-local threat memory."""
    query = args.get("query")
    if not isinstance(query, str) or not query.strip() or len(query) > 2_000:
        raise RuntimeError("query must be a non-empty string of at most 2,000 characters")
    try:
        count = int(args.get("k", 5))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("k must be an integer") from exc
    if not 1 <= count <= 20:
        raise RuntimeError("k must be between 1 and 20")
    hits = await vector_memory.query_similar(query, n_results=count)
    if not hits:
        return [{"type": "text", "text": f"No intel records found for: {query}"}]
    lines = [f"## 🧠 Threat Intel — '{query}'", ""]
    for hit in hits:
        meta = hit.get("metadata", {}) or {}
        lines.append(f"- **{meta.get('finding_id', 'record')}** — {hit.get('document', '')[:220]}")
    return [{"type": "text", "text": "\n".join(lines)}]


async def _tool_list_scan_history(args: dict[str, Any]) -> list[dict[str, str]]:
    target = _target_dir(args)
    try:
        limit = int(args.get("limit", 20))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("limit must be an integer") from exc
    history = list_scan_archives(target, limit=limit)
    return [{"type": "text", "text": json.dumps(history, indent=2, default=str)}]


async def _tool_compare_scan_runs(args: dict[str, Any]) -> list[dict[str, str]]:
    target = _target_dir(args)
    before = str(args.get("before_scan_id", ""))
    after = str(args.get("after_scan_id", ""))
    try:
        comparison = compare_scan_archives(target, before, after)
    except ScanArchiveError as exc:
        raise RuntimeError(str(exc)) from exc
    return [{"type": "text", "text": json.dumps(comparison, indent=2, default=str)}]


# ---------------------------------------------------------------------------
# Host-agent (providerless) remediation tools
#
# The MCP host does the reasoning on its own subscription; Arbalest grounds the
# host, validates and seals what it produces, and verifies it in the sandbox.
# None of these tools build an AI provider or accept a provider/model argument.
# ---------------------------------------------------------------------------
_MAX_CONTEXT_FILES = 32
_MAX_CONTEXT_BYTES = 256 * 1024


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _context_digest(finding, graph, sources: dict[str, str]) -> str:
    """Bind the finding, graph node ids, and every source hash into one digest.

    submit_remediation_candidate recomputes this from the live repository and
    refuses a candidate whose digest no longer matches, so a host agent cannot
    submit a plan authored against a repository state that has since changed.
    """
    payload = {
        "finding": finding.model_dump(mode="json"),
        "graph_nodes": [node.id for node in graph.nodes],
        "sources": {path: _sha256_text(content) for path, content in sorted(sources.items())},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _ground_finding(target: Path, finding_id: str):
    """Collect sources and build the grounded finding + architecture graph."""
    sources = collect_sources(target)
    if not sources:
        raise RuntimeError(f"No source files found in {target}")
    finding = resolve_archived_finding(target, finding_id)
    if finding is None:
        finding = finding_with_evidence("MCP", finding_id, sources)
    graph = build_file_graph("mcp-host", sources, prioritize=finding.affected_nodes)
    return sources, finding, graph


def _bounded_sources(finding, sources: dict[str, str]) -> tuple[list[dict[str, Any]], int, int]:
    """Prioritize affected files, then the rest sorted; bound files and bytes.

    A source containing a recognized secret is returned redacted and flagged;
    the raw secret value never leaves the server.
    """
    affected = [path for path in finding.affected_nodes if path in sources]
    ordered: list[str] = []
    seen: set[str] = set()
    for path in [*affected, *sorted(sources)]:
        if path in sources and path not in seen:
            seen.add(path)
            ordered.append(path)
    included: list[dict[str, Any]] = []
    total = 0
    omitted_files = 0
    omitted_bytes = 0
    for path in ordered:
        content = sources[path]
        redacted = redact_secrets(content)
        contains_secret = redacted != content
        size = len(redacted.encode("utf-8"))
        if len(included) >= _MAX_CONTEXT_FILES or total + size > _MAX_CONTEXT_BYTES:
            omitted_files += 1
            omitted_bytes += size
            continue
        total += size
        included.append({
            "path": path,
            "sha256": _sha256_text(content),
            "content": redacted,
            "contains_secret": contains_secret,
        })
    return included, omitted_files, omitted_bytes


_HOST_AGENT_INSTRUCTIONS = (
    "You are the reasoning host for Arbalest's providerless remediation. Using only the finding, "
    "the architecture_graph, and the bounded sources below, author a MutationPlan that conforms to "
    "plan_schema and a GeneratedCodeBundle that conforms to bundle_schema. Every plan mutation must "
    "target a graph node id and an available source file; the bundle may only change files the plan "
    "targets or add genuinely new files. Then call submit_remediation_candidate with the same "
    "target_path and finding, the exact context_digest from this response, and your plan and bundle "
    "objects. Arbalest validates, seals, and verifies them; it never trusts a verdict you supply. "
    "Sources flagged contains_secret have had secret values redacted — never try to reconstruct them."
)


async def _tool_prepare_remediation_context(args: dict[str, Any]) -> list[dict[str, str]]:
    target = _target_dir(args)
    finding_id = _finding_arg(args)
    sources, finding, graph = _ground_finding(target, finding_id)
    included, omitted_files, omitted_bytes = _bounded_sources(finding, sources)
    context = {
        "finding": finding.model_dump(mode="json"),
        "architecture_graph": graph.model_dump(mode="json"),
        "sources": included,
        "omitted": {"files": omitted_files, "bytes": omitted_bytes},
        "context_digest": _context_digest(finding, graph, sources),
        "plan_schema": MutationPlan.model_json_schema(),
        "bundle_schema": GeneratedCodeBundle.model_json_schema(),
        "attack_schema": AttackScript.model_json_schema(),
        "instructions": _HOST_AGENT_INSTRUCTIONS,
    }
    return [{"type": "text", "text": json.dumps(context, indent=2, default=str)}]


async def _tool_submit_remediation_candidate(args: dict[str, Any]) -> list[dict[str, str]]:
    target = _target_dir(args)
    finding_id = _finding_arg(args)
    digest = args.get("context_digest")
    if not isinstance(digest, str) or not digest:
        raise RuntimeError("context_digest is required; call prepare_remediation_context first")
    plan_obj = args.get("plan")
    bundle_obj = args.get("bundle")
    if not isinstance(plan_obj, dict) or not isinstance(bundle_obj, dict):
        raise RuntimeError("plan and bundle must each be a JSON object")

    sources, finding, graph = _ground_finding(target, finding_id)
    if _context_digest(finding, graph, sources) != digest:
        raise RuntimeError(
            "stale context_digest: the repository changed since prepare_remediation_context; re-run it"
        )
    try:
        plan = MutationPlan.model_validate(plan_obj)
        bundle = GeneratedCodeBundle.model_validate(bundle_obj)
    except ValidationError as exc:
        raise RuntimeError(f"plan or bundle failed schema validation: {_compact_error(exc)}") from exc

    artifact = create_validated_artifact(target, finding, plan, bundle, sources, graph)
    artifact_path = save_artifact(target, artifact)
    diff = _bundle_diff(bundle, sources)
    patch_path = target / f"arbalest-fix-{finding_id}.patch"
    patch_path.write_text(
        f"# Arbalest Host-Agent Remediation — {finding_id}\n"
        f"# plan: {plan.plan_id}  artifact: {artifact.artifact_id}\n\n{diff}",
        encoding="utf-8",
    )
    text = (
        f"## 🧾 Sealed host-agent remediation for {finding_id}\n"
        f"- **Artifact:** `{artifact.artifact_id}` at `{artifact_path}`\n"
        f"- **Bundle SHA-256:** {artifact.bundle_sha256}\n"
        f"- **Reviewable patch:** `{patch_path}` (not applied)\n\n"
        f"```diff\n{diff}\n```"
    )
    return [{"type": "text", "text": text}]


async def _tool_verify_remediation_candidate(args: dict[str, Any]) -> list[dict[str, str]]:
    target = _target_dir(args)
    finding_id = _finding_arg(args)
    reference = args.get("artifact")
    if reference is not None and not isinstance(reference, str):
        raise RuntimeError("artifact must be an artifact id or repository-relative path")
    artifact, artifact_path = load_artifact(target, reference, finding_id)
    verify_source_state(target, artifact)

    attack_arg = args.get("attack")
    attack: AttackScript | None = None
    if attack_arg is not None:
        if not isinstance(attack_arg, dict):
            raise RuntimeError("attack must be a JSON object matching attack_schema")
        try:
            attack = AttackScript.model_validate(attack_arg)
        except ValidationError as exc:
            raise RuntimeError(f"attack failed schema validation: {_compact_error(exc)}") from exc

    sandbox = _sandbox_manager()
    try:
        await sandbox.healthcheck()
        result = await execute_deterministic_verification(
            sandbox, artifact.bundle, [artifact.finding], attack=attack,
        )
    except Exception as exc:
        raise RuntimeError(f"verification could not complete: {exc}") from exc
    finally:
        await sandbox.aclose()

    source_write_eligible = result.automated_deployment_allowed
    if source_write_eligible:
        verdict = "✅ EXACT ARTIFACT HELD — strong evidence; eligible for an explicit reviewed CLI apply"
    elif result.verification_held:
        verdict = (
            f"⚠️ ARTIFACT HELD AT {result.verification_tier.upper()} TIER — "
            "insufficient evidence for source deployment"
        )
    elif result.analysis.inconclusive and not result.analysis.exploit_successful:
        verdict = "⚠️ INCONCLUSIVE — nothing is proven; do not deploy"
    else:
        verdict = "❌ ARTIFACT BREACHED — do not deploy"
    text = (
        f"## ⚔ Host-agent verification — {finding_id}\n"
        f"- **Artifact:** {artifact.artifact_id} (`{artifact_path}`)\n"
        f"- **Bundle SHA-256:** {artifact.bundle_sha256}\n"
        f"- **Objective:** {result.attack.objective}\n"
        f"- **Exploit:** {'SUCCEEDED (breach)' if result.analysis.exploit_successful else 'REPELLED'}\n"
        f"- **Sandbox:** {result.sandbox.status.value} / exit {result.sandbox.exit_code}\n"
        f"- **Confidence:** {result.analysis.confidence:.2f}\n"
        f"- **Verification tier:** {result.verification_tier}\n"
        f"- **Verdict:** {verdict}\n"
        f"- **source_write_eligible:** {str(source_write_eligible).lower()}\n"
        f"- **Analysis:** {result.analysis.reasoning}"
    )
    return [{"type": "text", "text": text}]


def _compact_error(error: Exception) -> str:
    return str(error).replace("\n", " ")[:600] or error.__class__.__name__


# ---------------------------------------------------------------------------
# MCP protocol surface
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _Tool:
    """One registered MCP tool: its JSON schema definition and its handler.

    ``_TOOL_DEFS`` (advertised to clients) and the dispatch table both derive
    from this single registry, so a tool can never be advertised without a
    handler or dispatched without a schema.
    """

    handler: Callable[[dict[str, Any]], Awaitable[list[dict[str, str]]]]
    definition: dict[str, Any]


_TOOLS: list[_Tool] = [
    _Tool(_tool_scan_repository, {
        "name": "scan_repository",
        "description": (
            "Run a full Arbalest security scan on a local repository. Executes the "
            "curriculum: RECON, AST scan (SAST + secrets), dependency check (SCA), and "
            "Threat Intel RAG. Writes <target>/arbalest-report.sarif and returns a "
            "severity-tagged summary."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Absolute path to the repository directory."},
                "provider": {"type": "string", "enum": sorted(_PROVIDER_KEY_ENV),
                             "description": "AI provider (default: ARBALEST_PROVIDER or nebius)."},
                "model": {"type": "string", "description": "Model override."},
                "diff_base": {"type": "string", "description": "Optional Git base revision for a changed-files scan."},
            },
            "required": ["target_path"],
        },
    }),
    _Tool(_tool_scan_code_snippet, {
        "name": "scan_code_snippet",
        "description": "Analyze a single code snippet for logic vulnerabilities using SAST.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "The source code to analyze."},
                "filename": {"type": "string", "description": "Virtual filename (e.g. app.py).", "maxLength": 240},
                "provider": {"type": "string", "enum": sorted(_PROVIDER_KEY_ENV)},
                "model": {"type": "string", "description": "Model override.", "maxLength": 256},
            },
            "required": ["code", "filename"],
        },
    }),
    _Tool(_tool_fix_vulnerability, {
        "name": "fix_vulnerability",
        "description": (
            "Autonomously generate a secure patch for a vulnerability: ArchitectAgent plans, "
            "PolyglotTranslator forges code. Returns a real unified diff and writes the patch "
            "file next to the target; nothing is applied silently."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Absolute path to the repository directory."},
                "finding": {"type": "string", "description": "Vulnerability ID or CWE (e.g. CWE-89)."},
                "provider": {"type": "string", "enum": sorted(_PROVIDER_KEY_ENV)},
                "model": {"type": "string", "description": "Model override.", "maxLength": 256},
            },
            "required": ["target_path", "finding"],
        },
    }),
    _Tool(_tool_verify_fix, {
        "name": "verify_fix",
        "description": (
            "Adversarially verify an existing immutable remediation artifact "
            "inside the configured Nebius or Docker sandbox. The MCP tool never deploys source changes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Absolute path to the repository directory."},
                "finding": {"type": "string", "description": "Vulnerability ID or CWE to verify against."},
                "artifact": {"type": "string", "description": "Artifact id or repository-relative artifact path."},
                "provider": {"type": "string", "enum": sorted(_PROVIDER_KEY_ENV)},
                "model": {"type": "string", "description": "Model override.", "maxLength": 256},
            },
            "required": ["target_path", "finding"],
        },
    }),
    _Tool(_tool_query_threat_intel, {
        "name": "query_threat_intel",
        "description": "Retrieve similar past findings from workspace-local SQLite threat memory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Natural-language intel query.", "minLength": 1, "maxLength": 2000},
                "k": {"type": "integer", "description": "Maximum number of records (default 5).", "minimum": 1, "maximum": 20},
            },
            "required": ["query"],
        },
    }),
    _Tool(_tool_list_scan_history, {
        "name": "list_scan_history",
        "description": "List verified local scan archives for an authorized repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            },
            "required": ["target_path"],
        },
    }),
    _Tool(_tool_compare_scan_runs, {
        "name": "compare_scan_runs",
        "description": "Compare two sealed scan archives into new, persistent, and resolved findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "before_scan_id": {"type": "string", "pattern": "^[a-f0-9]{12}$"},
                "after_scan_id": {"type": "string", "pattern": "^[a-f0-9]{12}$"},
            },
            "required": ["target_path", "before_scan_id", "after_scan_id"],
        },
    }),
    _Tool(_tool_prepare_remediation_context, {
        "name": "prepare_remediation_context",
        "description": (
            "Host-agent mode: ground your own reasoning. Returns the grounded finding, a bounded "
            "architecture graph, secret-redacted sources, a context_digest, and the plan/bundle/attack "
            "JSON schemas. No AI provider is called; you (the MCP host) author the plan and bundle. "
            "Follow up with submit_remediation_candidate."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Absolute path to the repository directory."},
                "finding": {"type": "string", "description": "Vulnerability ID or CWE (e.g. CWE-89)."},
            },
            "required": ["target_path", "finding"],
        },
    }),
    _Tool(_tool_submit_remediation_candidate, {
        "name": "submit_remediation_candidate",
        "description": (
            "Host-agent mode: validate and seal a host-authored MutationPlan and GeneratedCodeBundle "
            "into an immutable artifact and a reviewable patch. The context_digest from "
            "prepare_remediation_context must still match the repository. Nothing is applied. No AI "
            "provider is called."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Absolute path to the repository directory."},
                "finding": {"type": "string", "description": "Vulnerability ID or CWE being remediated."},
                "context_digest": {"type": "string", "description": "The digest returned by prepare_remediation_context."},
                "plan": {"type": "object", "description": "A MutationPlan object matching plan_schema."},
                "bundle": {"type": "object", "description": "A GeneratedCodeBundle object matching bundle_schema."},
            },
            "required": ["target_path", "finding", "context_digest", "plan", "bundle"],
        },
    }),
    _Tool(_tool_verify_remediation_candidate, {
        "name": "verify_remediation_candidate",
        "description": (
            "Host-agent mode: run a sealed artifact inside the configured sandbox and compute the "
            "verdict server-side. Optionally accepts a host-authored AttackScript harness; the "
            "analysis is always computed by Arbalest and a host-supplied verdict is never trusted. "
            "Nothing is deployed. No AI provider is called."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Absolute path to the repository directory."},
                "finding": {"type": "string", "description": "Vulnerability ID or CWE to verify against."},
                "artifact": {"type": "string", "description": "Artifact id or repository-relative artifact path."},
                "attack": {"type": "object", "description": "Optional AttackScript harness matching attack_schema."},
            },
            "required": ["target_path", "finding"],
        },
    }),
]

_TOOL_DEFS: list[dict[str, Any]] = [tool.definition for tool in _TOOLS]
_TOOL_HANDLERS: dict[str, Callable[[dict[str, Any]], Awaitable[list[dict[str, str]]]]] = {
    tool.definition["name"]: tool.handler for tool in _TOOLS
}


def _handle_initialize(params: dict[str, Any]) -> dict[str, Any]:
    requested = str(params.get("protocolVersion", "") or "")
    negotiated = requested if requested in _SUPPORTED_PROTOCOL_VERSIONS else "2024-11-05"
    return {
        "protocolVersion": negotiated,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        "instructions": (
            "Arbalest analyzes authorized source repositories and produces security findings. "
            "Use scan tools before remediation. fix_vulnerability creates an immutable artifact but does not deploy it; "
            "verify_fix verifies that exact artifact without deployment. "
            "In host-agent mode you do the reasoning on your own subscription: call prepare_remediation_context "
            "to get grounded, secret-redacted context plus a context_digest and the plan/bundle/attack schemas, "
            "author the plan and bundle yourself, then submit_remediation_candidate to validate and seal them, and "
            "verify_remediation_candidate to run the sealed artifact in the sandbox. Arbalest computes every verdict "
            "server-side and never applies or deploys source changes. Keep ARBALEST_MCP_ALLOWED_ROOTS configured."
        ),
    }


async def _handle_tool_call(name: str, arguments: dict[str, Any]) -> list[dict[str, str]]:
    handler = _TOOL_HANDLERS.get(name)
    if handler is None:
        raise RuntimeError(f"Unknown tool: {name}")
    return await handler(arguments)


async def _process_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Process one bounded JSON-RPC request; notifications never receive responses."""
    if not isinstance(msg, dict):
        return {"jsonrpc": JSONRPC_VERSION, "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    msg_id = msg.get("id")
    is_notification = "id" not in msg
    if msg.get("jsonrpc") != JSONRPC_VERSION or not isinstance(msg.get("method"), str):
        return None if is_notification else {
            "jsonrpc": JSONRPC_VERSION, "id": msg_id, "error": {"code": -32600, "message": "Invalid Request"}
        }
    method = msg["method"]
    params = msg.get("params", {})
    if not isinstance(params, dict):
        return None if is_notification else {
            "jsonrpc": JSONRPC_VERSION, "id": msg_id, "error": {"code": -32602, "message": "Invalid params"}
        }

    if method == "initialize":
        response = {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": _handle_initialize(params)}
    elif method == "notifications/initialized":
        return None
    elif method == "tools/list":
        response = {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": {"tools": _TOOL_DEFS}}
    elif method == "tools/call":
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            response = {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "error": {"code": -32602, "message": "Invalid tool arguments"}}
        else:
            try:
                content = await _handle_tool_call(str(params.get("name", "")), arguments)
                response = {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": {"content": content, "isError": False}}
            except Exception as exc:
                logger.exception("tool call failed: %s", params.get("name"))
                response = {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": {
                    "content": [{"type": "text", "text": f"Error: {str(exc)[:1000]}"}], "isError": True}}
    elif method == "ping":
        response = {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": {}}
    else:
        response = {"jsonrpc": JSONRPC_VERSION, "id": msg_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"}}
    return None if is_notification else response


class _AsyncByteReader(Protocol):
    async def readline(self, limit: int | None = None) -> bytes: ...
    async def readexactly(self, n: int) -> bytes: ...


# Line read outcomes. The content and framing bytes are bounded so a hostile or
# buggy client cannot force the server to buffer an unbounded message.
_LINE_OK = "ok"
_LINE_EOF = "eof"
_LINE_OVERSIZED = "oversized"

# Returned by the Content-Length path: skip this frame and keep reading, or stop
# the reader entirely (unrecoverable desync / EOF).
_FRAMED_SKIP = object()
_FRAMED_STOP = object()


class _OversizedLine(Exception):
    """A line exceeded the stream's own internal buffer limit."""


class MessageReader:
    """Bounded newline-delimited JSON-RPC reader with Content-Length fallback.

    Hardened so no single message, header block, or framed body can make the
    server buffer an unbounded amount of memory, while remaining byte-compatible
    with both the production blocking-stdin adapter and ``asyncio.StreamReader``
    used by the tests.
    """

    MAX_MESSAGE_BYTES = 8 * 1024 * 1024
    _MAX_HEADER_LINES = 32
    _MAX_HEADER_LINE_BYTES = 1024
    # Hard ceiling on how much we are willing to read-and-discard to resync
    # after an oversized frame; beyond this we stop rather than spin.
    _MAX_DISCARD_BYTES = 64 * 1024 * 1024

    def __init__(self, reader: _AsyncByteReader) -> None:
        self._reader = reader

    async def read_message(self) -> dict[str, Any] | None:
        while True:
            line, status = await self._read_line(self.MAX_MESSAGE_BYTES)
            if status == _LINE_EOF:
                return None
            if status == _LINE_OVERSIZED:
                logger.warning("discarding oversized stdio message")
                continue
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            if text.lower().startswith("content-length:"):
                framed = await self._read_framed(text)
                if framed is _FRAMED_STOP:
                    return None
                if framed is _FRAMED_SKIP:
                    continue
                return framed  # type: ignore[return-value]
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                logger.warning("discarding non-JSON stdio line")
                continue

    async def _raw_readline(self, limit: int) -> bytes:
        """Read one line bounded to ``limit`` bytes from either reader type."""
        try:
            return await self._reader.readline(limit)
        except TypeError:
            # asyncio.StreamReader.readline() accepts no size argument; it is
            # bounded by the stream's own buffer limit instead.
            try:
                return await self._reader.readline()
            except (ValueError, asyncio.LimitOverrunError) as exc:
                raise _OversizedLine() from exc

    async def _read_line(self, limit: int) -> tuple[bytes, str]:
        """Return (line, status). The line is dropped for non-OK statuses."""
        try:
            data = await self._raw_readline(limit)
        except _OversizedLine:
            return b"", _LINE_OVERSIZED
        if not data:
            return b"", _LINE_EOF
        if len(data) > limit:
            # A blocking adapter returns ``limit + 1`` bytes without a trailing
            # newline for an over-long line; resync by draining to the next one.
            if not data.endswith(b"\n") and not await self._drain_to_newline():
                return b"", _LINE_EOF
            return b"", _LINE_OVERSIZED
        return data, _LINE_OK

    async def _drain_to_newline(self) -> bool:
        """Discard bytes up to the next newline so framing stays in sync."""
        discarded = 0
        while discarded <= self._MAX_DISCARD_BYTES:
            try:
                chunk = await self._raw_readline(self._MAX_HEADER_LINE_BYTES)
            except _OversizedLine:
                return False
            if not chunk:
                return False
            discarded += len(chunk)
            if chunk.endswith(b"\n"):
                return True
        return False

    async def _read_framed(self, header_text: str) -> object | dict[str, Any] | None:
        """Parse a Content-Length frame; return a dict, _FRAMED_SKIP, or _FRAMED_STOP."""
        try:
            length = int(header_text.split(":", 1)[1].strip())
        except ValueError:
            return _FRAMED_SKIP
        if length < 0:
            return _FRAMED_SKIP
        for _ in range(self._MAX_HEADER_LINES):  # consume headers up to the blank line
            header, status = await self._read_line(self._MAX_HEADER_LINE_BYTES)
            if status == _LINE_EOF:
                return _FRAMED_STOP
            if status == _LINE_OVERSIZED:
                continue
            if not header.strip():
                break
        else:
            return _FRAMED_SKIP  # header block never terminated within bounds
        if length > self.MAX_MESSAGE_BYTES:
            # Oversized but declared: discard the body only if it is within the
            # hard cap; otherwise we cannot safely resync, so stop.
            if length > self._MAX_DISCARD_BYTES:
                return _FRAMED_STOP
            return _FRAMED_SKIP if await self._discard_exactly(length) else _FRAMED_STOP
        try:
            body = await self._reader.readexactly(length)
        except asyncio.IncompleteReadError:
            return _FRAMED_STOP
        try:
            return json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return _FRAMED_SKIP

    async def _discard_exactly(self, count: int) -> bool:
        """Read and throw away exactly ``count`` bytes in bounded chunks."""
        remaining = count
        chunk_size = 64 * 1024
        try:
            while remaining > 0:
                data = await self._reader.readexactly(min(remaining, chunk_size))
                remaining -= len(data)
        except asyncio.IncompleteReadError:
            return False
        return True


class _StdioAdapter:
    """File-object adapter so MessageReader works on blocking stdin buffers.

    Reads run in a worker thread, which keeps the event loop responsive and
    sidesteps the Windows ``connect_read_pipe`` limitations entirely.
    """

    def __init__(self, buffer) -> None:
        self._buffer = buffer

    async def readline(self, limit: int | None = None) -> bytes:
        if limit is None:
            return await asyncio.to_thread(self._buffer.readline)
        # Read at most ``limit + 1`` bytes so the caller can detect an over-long
        # line (it comes back without a trailing newline).
        return await asyncio.to_thread(self._buffer.readline, limit + 1)

    async def readexactly(self, n: int) -> bytes:
        data = await asyncio.to_thread(self._buffer.read, n)
        if len(data) < n:
            raise asyncio.IncompleteReadError(data, n)
        return data


def _load_env_file() -> None:
    """Load `.env` from the server directory or CWD. Existing env vars win."""
    load_env_file((_BACKEND_DIR, Path.cwd()))


async def main() -> None:
    logger.info("Arbalest MCP server online on stdio — %d tools armed", len(_TOOL_DEFS))
    out = sys.stdout.buffer
    message_reader = MessageReader(_StdioAdapter(sys.stdin.buffer))
    while True:
        msg = await message_reader.read_message()
        if msg is None:
            break
        response = await _process_message(msg)
        if response is not None:
            out.write((json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8"))
            out.flush()


def run() -> None:
    """Installed console entry point for MCP stdio clients."""
    _load_env_file()
    asyncio.run(main())


if __name__ == "__main__":
    run()
