"""MCP server — real stdio protocol behavior (framing + JSON-RPC surface)."""

from __future__ import annotations

import asyncio
import json

import pytest

import mcp_server
from mcp_server import MessageReader, _process_message

pytestmark = pytest.mark.asyncio


async def test_tool_schemas_reference_real_providers():
    for tool in mcp_server._TOOL_DEFS:
        for prop in tool["inputSchema"].get("properties", {}).values():
            if prop.get("enum"):
                assert "nebius" in prop["enum"]


def feed_reader(payload: bytes) -> MessageReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return MessageReader(reader)


async def test_reader_newline_delimited_json():
    msg = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    reader = feed_reader(json.dumps(msg).encode() + b"\n")
    assert await reader.read_message() == msg


async def test_reader_skips_garbage_lines():
    reader = feed_reader(b"garbage\n{\"jsonrpc\": \"2.0\", \"id\": 2, \"method\": \"ping\"}\n")
    assert (await reader.read_message())["id"] == 2


async def test_reader_content_length_framing_fallback():
    body = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"}).encode()
    framed = b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    reader = feed_reader(framed)
    assert (await reader.read_message())["id"] == 3


async def test_reader_eof_returns_none():
    reader = feed_reader(b"")
    assert await reader.read_message() is None


async def test_initialize_negotiates_protocol():
    response = await _process_message({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18"},
    })
    assert response["result"]["protocolVersion"] == "2025-06-18"
    assert response["result"]["serverInfo"]["name"] == "arbalest"


async def test_initialize_falls_back_for_unknown_version():
    response = await _process_message({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "1999-01-01"},
    })
    assert response["result"]["protocolVersion"] == "2024-11-05"


_PROVIDERLESS_TOOLS = {
    "prepare_remediation_context",
    "submit_remediation_candidate",
    "verify_remediation_candidate",
}


async def test_tools_list_exposes_supported_tools():
    response = await _process_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = response["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {
        "scan_repository", "scan_code_snippet",
        "fix_vulnerability", "verify_fix", "query_threat_intel",
        "list_scan_history", "compare_scan_runs",
        "prepare_remediation_context", "submit_remediation_candidate",
        "verify_remediation_candidate",
    }
    assert len(tools) == 10
    for tool in tools:
        assert "inputSchema" in tool and tool["inputSchema"]["type"] == "object"


async def test_providerless_tools_have_no_provider_or_model():
    """Host-agent tools must never advertise a provider/model argument."""
    response = await _process_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    for tool in response["result"]["tools"]:
        if tool["name"] not in _PROVIDERLESS_TOOLS:
            continue
        properties = tool["inputSchema"].get("properties", {})
        assert "provider" not in properties
        assert "model" not in properties


async def test_ping_returns_empty_result():
    response = await _process_message({"jsonrpc": "2.0", "id": 3, "method": "ping"})
    assert response["result"] == {}


async def test_unknown_method_is_error_32601():
    response = await _process_message({"jsonrpc": "2.0", "id": 4, "method": "bogus/method"})
    assert response["error"]["code"] == -32601


async def test_notification_gets_no_response():
    assert await _process_message({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


async def test_tool_call_unarmed_provider_reports_is_error():
    """Real failure path: no API key armed → isError result, not a crash."""
    response = await _process_message({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "scan_repository", "arguments": {"target_path": "Z:/nope"}},
    })
    assert response["result"]["isError"] is True
    assert "Error" in response["result"]["content"][0]["text"]


async def _call(name: str, arguments: dict):
    return await _process_message({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })


@pytest.mark.parametrize("tool", ["fix_vulnerability", "verify_fix"])
async def test_traversal_finding_id_is_rejected_before_any_work(tool, tmp_path, monkeypatch):
    """A model-supplied finding id must never become a path outside the target."""
    monkeypatch.setenv("NEBIUS_API_KEY", "real-looking-key-123456")
    response = await _call(tool, {"target_path": str(tmp_path), "finding": "../../evil"})
    assert response["result"]["isError"] is True
    assert "Finding id" in response["result"]["content"][0]["text"]
    assert not list(tmp_path.parent.glob("arbalest-*evil*"))


async def test_target_outside_allowed_roots_is_refused(tmp_path, monkeypatch):
    allowed = tmp_path / "workspace"
    allowed.mkdir()
    outside = tmp_path / "secrets"
    outside.mkdir()
    monkeypatch.setenv("ARBALEST_MCP_ALLOWED_ROOTS", str(allowed))
    monkeypatch.setenv("NEBIUS_API_KEY", "real-looking-key-123456")
    response = await _call("scan_repository", {"target_path": str(outside)})
    assert response["result"]["isError"] is True
    assert "ARBALEST_MCP_ALLOWED_ROOTS" in response["result"]["content"][0]["text"]


async def test_missing_target_path_is_a_clean_error():
    response = await _call("scan_repository", {})
    assert response["result"]["isError"] is True
    assert "target_path is required" in response["result"]["content"][0]["text"]


# ── Host-agent (providerless) remediation ────────────────────────────────────

_SQLI_SOURCE = (
    "import sqlite3\n\n\n"
    "def get_user(conn, uid):\n"
    "    query = \"SELECT * FROM users WHERE id = '\" + uid + \"'\"\n"
    "    return conn.execute(query).fetchone()\n"
)


def _candidate_plan() -> dict:
    return {
        "plan_id": "plan-cwe89",
        "target_language": "python",
        "mutations": [
            {
                "target_file": "app.py",
                "target_node": "app.py",
                "action": "parameterize_query",
                "rationale": "Use bound parameters so user input cannot alter the SQL statement.",
                "expected_side_effects": [],
                "acceptance_criteria": ["The query uses a bound parameter for the user id"],
            }
        ],
        "security_invariants": ["No untrusted input is concatenated into SQL text"],
        "test_strategy": ["Call get_user with a malicious id and assert no injection"],
    }


def _candidate_bundle() -> dict:
    return {
        "language": "python",
        "entrypoint": "app.py",
        "files": [
            {
                "path": "app.py",
                "content": (
                    "import sqlite3\n\n\n"
                    "def get_user(conn, uid):\n"
                    "    return conn.execute("
                    "\"SELECT * FROM users WHERE id = ?\", (uid,)).fetchone()\n"
                ),
            }
        ],
        "build_instructions": ["none"],
        "test_instructions": ["none"],
    }


async def test_prepare_remediation_context_grounds_and_returns_schemas(tmp_path):
    (tmp_path / "app.py").write_text(_SQLI_SOURCE, encoding="utf-8")
    response = await _call("prepare_remediation_context", {"target_path": str(tmp_path), "finding": "CWE-89"})
    assert response["result"]["isError"] is False
    context = json.loads(response["result"]["content"][0]["text"])
    assert len(context["context_digest"]) == 64
    assert "properties" in context["plan_schema"]
    assert "properties" in context["bundle_schema"]
    assert "properties" in context["attack_schema"]
    assert any(src["path"] == "app.py" for src in context["sources"])


async def test_submit_with_stale_digest_is_rejected(tmp_path):
    (tmp_path / "app.py").write_text(_SQLI_SOURCE, encoding="utf-8")
    response = await _call("submit_remediation_candidate", {
        "target_path": str(tmp_path), "finding": "CWE-89",
        "context_digest": "0" * 64, "plan": _candidate_plan(), "bundle": _candidate_bundle(),
    })
    assert response["result"]["isError"] is True
    assert "stale context_digest" in response["result"]["content"][0]["text"]


async def test_submit_valid_candidate_seals_artifact_without_touching_source(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(_SQLI_SOURCE, encoding="utf-8")
    prepared = await _call("prepare_remediation_context", {"target_path": str(tmp_path), "finding": "CWE-89"})
    digest = json.loads(prepared["result"]["content"][0]["text"])["context_digest"]

    response = await _call("submit_remediation_candidate", {
        "target_path": str(tmp_path), "finding": "CWE-89",
        "context_digest": digest, "plan": _candidate_plan(), "bundle": _candidate_bundle(),
    })
    assert response["result"]["isError"] is False, response["result"]["content"][0]["text"]
    remediations = list((tmp_path / ".arbalest" / "remediations").glob("*.json"))
    assert len(remediations) == 1
    # The candidate is sealed, never applied: the source file is untouched.
    assert source.read_text(encoding="utf-8") == _SQLI_SOURCE


async def test_reader_skips_oversized_newline_message_then_reads_next():
    big = b"x" * (MessageReader.MAX_MESSAGE_BYTES + 16)
    valid = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode()
    reader = asyncio.StreamReader(limit=MessageReader.MAX_MESSAGE_BYTES * 2)
    reader.feed_data(big + b"\n" + valid + b"\n")
    reader.feed_eof()
    message_reader = MessageReader(reader)
    message = await message_reader.read_message()
    assert message["id"] == 7
