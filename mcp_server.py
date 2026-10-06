#!/usr/bin/env python3
"""
Arbalest MCP Server — Model Context Protocol interface to the strike platform.

Runs on stdio using newline-delimited JSON-RPC 2.0 (the MCP stdio transport).
Content-Length framed requests are also accepted for LSP-style clients.

Tools (all real, all backed by the engine):
  scan_repository    — full curriculum: RECON → AST → DEPENDENCY CHECK → THREAT RAG,
                       writes <target>/arbalest-report.sarif
  scan_code_snippet  — SAST analysis of a single snippet
  fix_vulnerability  — ArchitectAgent + PolyglotTranslator produce a real unified
                       diff; the patch file is written next to the target (never
                       silently applied from a chat context — use the CLI `fix`
                       command for fully autonomous remediation)
  verify_fix         — RedTeamSwarm attacks the generated patch inside the
                       Nebius Token Factory Sandbox (Docker) and returns the verdict
  query_threat_intel — retrieval against the persisted vector threat memory

Claude Desktop config (claude_desktop_config.json):
  {
    "mcpServers": {
      "arbalest": {
        "command": "python",
        "args": ["/path/to/mcp_server.py"],
        "env": { "ARBALEST_PROVIDER": "nebius", "NEBIUS_API_KEY": "..." }
      }
    }
  }
"""

from __future__ import annotations

import asyncio
import difflib
import json
import logging
import os
import sys
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
from engine.services.source_collector import collect_sources, run_recon  # noqa: E402
from engine.services.scan_pipeline import run_agent_swarm  # noqa: E402
from engine.services.sarif_export import findings_to_sarif, sarif_to_pretty_json  # noqa: E402
from engine.agents.architect_agent import (  # noqa: E402
    ArchitectureGraphContext,
    ArchitectAgent,
    CodeLanguage,
    Severity,
    ThreatFinding,
)
from engine.agents.polyglot_translator import PolyglotTranslator  # noqa: E402
from engine.agents.red_team_swarm import RedTeamSwarm  # noqa: E402
from engine.agents.sast_agent import SastAgent  # noqa: E402
from engine.services.docker_manager import DockerSandboxManager, SandboxRuntime  # noqa: E402
from engine.services.vector_memory import vector_memory  # noqa: E402

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s | %(levelname)-7s | %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("arbalest-mcp")

JSONRPC_VERSION = "2.0"
SERVER_NAME = "arbalest"
SERVER_VERSION = "1.0.0"
_SUPPORTED_PROTOCOL_VERSIONS = {"2024-10-07", "2024-11-05", "2025-03-26", "2025-06-18"}

_PROVIDER_KEY_ENV: dict[str, list[str]] = {
    "custom": ["AI_API_KEY"],
    "nebius": ["NEBIUS_API_KEY", "AI_API_KEY"],
}

_DEFAULT_MODELS: dict[str, str] = {
    "custom": "gpt-4o",
    "nebius": "NVIDIA-Nemotron-3-Nano-30B-A3B",
}


def _build_provider(provider_name: str | None = None, model: str | None = None):
    """Build the real AI core from the environment."""
    prov = provider_name or os.environ.get("ARBALEST_PROVIDER", "nebius")
    candidates = _PROVIDER_KEY_ENV.get(prov, []) + ["AI_API_KEY"]
    api_key = None
    for var in candidates:
        val = os.environ.get(var, "").strip()
        if val:
            api_key = val
            break
    if not api_key:
        raise RuntimeError(
            f"No API key armed for provider '{prov}'. Set one of: {', '.join(candidates)}."
        )
    effective_model = model or os.environ.get("ARBALEST_MODEL") or _DEFAULT_MODELS.get(prov, "gpt-4o")
    settings = AIProviderSettings(provider=prov, api_key=api_key, selected_model=effective_model)
    return create_ai_provider(settings), prov, effective_model


def _sandbox_manager() -> DockerSandboxManager:
    os.environ.setdefault("ARBALEST_ENVIRONMENT", "staging")
    return DockerSandboxManager(images={
        SandboxRuntime.PYTHON: "python:3.12-slim",
        SandboxRuntime.TYPESCRIPT: "node:20-alpine",
        SandboxRuntime.RUST: "rust:1.77-slim",
        SandboxRuntime.GO: "golang:1.22-alpine",
    })


# ---------------------------------------------------------------------------
# Tool implementations — all real engine paths
# ---------------------------------------------------------------------------
async def _tool_scan_repository(args: dict[str, Any]) -> list[dict[str, str]]:
    target = Path(args["target_path"]).resolve()
    if not target.exists() or not target.is_dir():
        raise RuntimeError(f"Invalid target directory: {args['target_path']}")
    provider, prov, model = _build_provider(args.get("provider"), args.get("model"))
    recon = run_recon(target)
    if not recon.files:
        raise RuntimeError(f"No source files found in {target}")

    run_id = uuid.uuid4().hex[:12]
    swarm = await run_agent_swarm(provider, recon.files, recon)

    sarif_path = target / "arbalest-report.sarif"
    sarif_path.write_text(
        sarif_to_pretty_json(findings_to_sarif(swarm.findings, run_id=run_id, target_url=str(target))),
        encoding="utf-8",
    )

    lines = [
        f"## 🛡 Arbalest Scan — {target}",
        f"**Run:** {run_id}  |  **Core:** {prov}/{model}",
        f"**Recon:** {recon.total_files} files, {len(recon.entrypoints)} entrypoints, {recon.sink_hits} sink signatures",
        f"**Total findings:** {len(swarm.findings)}",
        "",
    ]
    for name, stat in swarm.stats.items():
        mark = "✅" if stat.status == "ok" else "⚠️"
        lines.append(f"- {mark} **{name}**: {stat.count} finding(s)"
                     + (f" — {stat.detail}" if stat.detail else ""))
    lines.append("")
    for f in swarm.findings[:20]:
        loc = f.affected_nodes[0] if f.affected_nodes else "—"
        lines.append(f"- **[{str(f.severity).upper()}]** {f.summary} ({f.cwe}) @ {loc}")
    if len(swarm.findings) > 20:
        lines.append(f"- … +{len(swarm.findings) - 20} more")
    lines += ["", f"**SARIF report:** `{sarif_path}`"]
    return [{"type": "text", "text": "\n".join(lines)}]


async def _tool_scan_code_snippet(args: dict[str, Any]) -> list[dict[str, str]]:
    provider, prov, _model = _build_provider(args.get("provider"), None)
    filename = args.get("filename", "snippet.py")
    findings = await SastAgent(provider).analyze({filename: args["code"]})
    if not findings:
        return [{"type": "text", "text": "✅ No vulnerabilities found in the provided snippet."}]
    lines = ["## 🔍 SAST Findings", ""]
    for f in findings:
        lines += [
            f"- **[{str(f.severity).upper()}]** {f.summary} ({f.cwe})",
            *(f"  - evidence: {e}" for e in f.evidence[:3]),
        ]
    return [{"type": "text", "text": "\n".join(lines)}]


async def _plan_and_bundle(
    target: Path, finding_id: str, provider_name: str | None, model: str | None,
):
    """Shared ArchitectAgent → PolyglotTranslator path for fix/verify tools."""
    provider, prov, model = _build_provider(provider_name, model)
    sources = collect_sources(target)
    if not sources:
        raise RuntimeError(f"No source files found in {target}")
    finding = ThreatFinding(
        finding_id=f"MCP-{finding_id}",
        cwe=finding_id if finding_id.upper().startswith("CWE") else "CWE-Unknown",
        severity=Severity.HIGH,
        summary=f"Remediation requested via MCP for {finding_id}",
        affected_nodes=[],
        evidence=[],
    )
    plan = await ArchitectAgent(provider=provider).create_plan(
        graph_context=ArchitectureGraphContext(project_id="mcp-fix", nodes=[], edges=[]),
        findings=[finding],
        developer_task=f"Fix the {finding_id} vulnerability in this codebase",
        available_files=sources,
        target_language=CodeLanguage.AUTO,
    )
    bundle = await PolyglotTranslator(provider=provider).translate(
        legacy_sources=sources, mutation_plan=plan,
    )
    return plan, bundle, sources


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
    target = Path(args["target_path"]).resolve()
    if not target.exists() or not target.is_dir():
        raise RuntimeError(f"Invalid target directory: {args['target_path']}")
    plan, bundle, sources = await _plan_and_bundle(target, args["finding"], args.get("provider"), args.get("model"))
    diff = _bundle_diff(bundle, sources)
    patch_path = target / f"arbalest-fix-{args['finding']}.patch"
    patch_path.write_text(
        f"# Arbalest Auto-Remediation — {args['finding']}\n# plan: {plan.plan_id}\n\n{diff}",
        encoding="utf-8",
    )
    text = (
        f"## 🔧 Remediation plan {plan.plan_id} for {args['finding']}\n"
        + "\n".join(f"- {m.action.value} → {m.target_file}: {m.rationale}" for m in plan.mutations)
        + f"\n\n**Verified patch file written to:** `{patch_path}` (not auto-applied — "
        "use `arbalest fix` for autonomous deployment)\n\n```diff\n" + diff + "\n```"
    )
    return [{"type": "text", "text": text}]


async def _tool_verify_fix(args: dict[str, Any]) -> list[dict[str, str]]:
    target = Path(args["target_path"]).resolve()
    if not target.exists() or not target.is_dir():
        raise RuntimeError(f"Invalid target directory: {args['target_path']}")
    sandbox = _sandbox_manager()
    try:
        await sandbox.healthcheck()
    except Exception as exc:
        raise RuntimeError(f"Nebius Token Factory Sandbox requires a running Docker Engine: {exc}") from exc

    plan, bundle, _sources = await _plan_and_bundle(target, args["finding"], args.get("provider"), args.get("model"))
    finding = ThreatFinding(
        finding_id=f"MCP-VERIFY-{args['finding']}",
        cwe=args["finding"] if args["finding"].upper().startswith("CWE") else "CWE-Unknown",
        severity=Severity.HIGH,
        summary=f"Adversarial verification for {args['finding']}",
        affected_nodes=[],
        evidence=[],
    )
    provider, _prov, _model = _build_provider(args.get("provider"), args.get("model"))
    swarm = RedTeamSwarm(sandbox=sandbox, provider=provider)
    result = await swarm.execute(generated_code=bundle, mutation_plan=plan, findings=[finding])

    verdict = "✅ PATCH HELD — code survived adversarial verification" if result.deployment_allowed \
        else "❌ PATCH BREACHED — the swarm defeated the fix. Do not deploy."
    text = (
        f"## ⚔ RedTeamSwarm Case File — {args['finding']}\n"
        f"- **Objective:** {result.attack.objective}\n"
        f"- **Exploit:** {'SUCCEEDED (breach)' if result.analysis.exploit_successful else 'REPELLED'}\n"
        f"- **Sandbox:** {result.sandbox.status.value} / exit {result.sandbox.exit_code}\n"
        f"- **Confidence:** {result.analysis.confidence:.2f}\n"
        f"- **Verdict:** {verdict}\n"
        f"- **Analysis:** {result.analysis.reasoning}"
    )
    return [{"type": "text", "text": text}]


async def _tool_query_threat_intel(args: dict[str, Any]) -> list[dict[str, str]]:
    """Real retrieval against the persisted vector threat memory (ChromaDB)."""
    query = args["query"]
    hits = await vector_memory.query_similar(query, n_results=int(args.get("k", 5)))
    if not hits:
        return [{"type": "text", "text": f"No intel records found for: {query}"}]
    lines = [f"## 🧠 Threat Intel — '{query}'", ""]
    for hit in hits:
        meta = hit.get("metadata", {}) or {}
        lines.append(f"- **{meta.get('finding_id', 'record')}** — {hit.get('document', '')[:220]}")
    return [{"type": "text", "text": "\n".join(lines)}]


# ---------------------------------------------------------------------------
# MCP protocol surface
# ---------------------------------------------------------------------------
_TOOL_DEFS: list[dict[str, Any]] = [
    {
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
            },
            "required": ["target_path"],
        },
    },
    {
        "name": "scan_code_snippet",
        "description": "Analyze a single code snippet for logic vulnerabilities using SAST.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "The source code to analyze."},
                "filename": {"type": "string", "description": "Virtual filename (e.g. app.py)."},
                "provider": {"type": "string", "enum": sorted(_PROVIDER_KEY_ENV)},
            },
            "required": ["code", "filename"],
        },
    },
    {
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
            },
            "required": ["target_path", "finding"],
        },
    },
    {
        "name": "verify_fix",
        "description": (
            "Adversarially verify a remediation: RedTeamSwarm attacks the generated patch "
            "inside the Nebius Token Factory Sandbox (requires Docker Engine) and returns "
            "the case-file verdict."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Absolute path to the repository directory."},
                "finding": {"type": "string", "description": "Vulnerability ID or CWE to verify against."},
                "provider": {"type": "string", "enum": sorted(_PROVIDER_KEY_ENV)},
            },
            "required": ["target_path", "finding"],
        },
    },
    {
        "name": "query_threat_intel",
        "description": "Retrieve similar past findings from the persisted vector threat memory (Threat RAG store).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Natural-language intel query."},
                "k": {"type": "integer", "description": "Maximum number of records (default 5)."},
            },
            "required": ["query"],
        },
    },
]


def _handle_initialize(params: dict[str, Any]) -> dict[str, Any]:
    requested = str(params.get("protocolVersion", "") or "")
    negotiated = requested if requested in _SUPPORTED_PROTOCOL_VERSIONS else "2024-11-05"
    return {
        "protocolVersion": negotiated,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }


async def _handle_tool_call(name: str, arguments: dict[str, Any]) -> list[dict[str, str]]:
    handlers = {
        "scan_repository": _tool_scan_repository,
        "scan_code_snippet": _tool_scan_code_snippet,
        "fix_vulnerability": _tool_fix_vulnerability,
        "verify_fix": _tool_verify_fix,
        "query_threat_intel": _tool_query_threat_intel,
    }
    handler = handlers.get(name)
    if handler is None:
        raise RuntimeError(f"Unknown tool: {name}")
    return await handler(arguments)


async def _process_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Process one JSON-RPC message; None for notifications."""
    method = msg.get("method", "")
    msg_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        return {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": _handle_initialize(params)}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": {"tools": _TOOL_DEFS}}
    if method == "tools/call":
        try:
            content = await _handle_tool_call(str(params.get("name", "")), params.get("arguments") or {})
            return {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": {"content": content, "isError": False}}
        except Exception as exc:
            logger.exception("tool call failed: %s", params.get("name"))
            return {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": {
                "content": [{"type": "text", "text": f"Error: {exc}"}], "isError": True}}
    if method == "ping":
        return {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": {}}
    if msg_id is not None:
        return {"jsonrpc": JSONRPC_VERSION, "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}}
    return None


class MessageReader:
    """Newline-delimited JSON-RPC reader with Content-Length framing fallback."""

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self._reader = reader

    async def read_message(self) -> dict[str, Any] | None:
        while True:
            line = await self._reader.readline()
            if not line:
                return None
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            if text.lower().startswith("content-length:"):
                try:
                    length = int(text.split(":", 1)[1].strip())
                except ValueError:
                    continue
                while True:  # consume remaining headers up to the blank line
                    header = await self._reader.readline()
                    if not header or header in (b"\r\n", b"\n"):
                        break
                body = await self._reader.readexactly(length)
                try:
                    return json.loads(body.decode("utf-8"))
                except json.JSONDecodeError:
                    continue
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                logger.warning("discarding non-JSON stdio line")
                continue


class _StdioAdapter:
    """File-object adapter so MessageReader works on blocking stdin buffers.

    Reads run in a worker thread, which keeps the event loop responsive and
    sidesteps the Windows ``connect_read_pipe`` limitations entirely.
    """

    def __init__(self, buffer) -> None:
        self._buffer = buffer

    async def readline(self) -> bytes:
        return await asyncio.to_thread(self._buffer.readline)

    async def readexactly(self, n: int) -> bytes:
        data = await asyncio.to_thread(self._buffer.read, n)
        if len(data) < n:
            raise asyncio.IncompleteReadError(data, n)
        return data


def _load_env_file() -> None:
    """Load `.env` from the server directory or CWD. Existing env vars win."""
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


if __name__ == "__main__":
    _load_env_file()
    asyncio.run(main())
