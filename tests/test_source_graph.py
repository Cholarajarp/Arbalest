"""The planner needs a real graph: an empty one makes every plan invalid.

Regression for a live failure: `arbalest fix` died with
"Plan references an unknown graph node: executors.py" because the CLI, the MCP
server and two missions handed the Architect an empty architecture graph.
"""

from __future__ import annotations

import json

import pytest

from engine.agents.architect_agent import (
    ArchitectAgent,
    ArchitectureAgentError,
    ArchitectureGraphContext,
    CodeLanguage,
)
from engine.services.ai_provider import StructuredOutputRequest
from engine.services.source_graph import MAX_NODES, build_file_graph, finding_with_evidence

SOURCES = {
    "executors.py": "import os\n\n\ndef run_shell(cmd):\n    return os.system(cmd)\n",
    "handlers.py": "from executors import run_shell\n\n\ndef run_scan(repo):\n    return run_shell('git clone ' + repo)\n",
    "safe.py": "import hashlib\n\n\ndef digest(v):\n    return hashlib.sha256(v.encode()).hexdigest()\n",
}


def test_graph_has_one_node_per_file_with_the_path_as_id():
    graph = build_file_graph("t", SOURCES, entrypoints=["handlers.py"])
    assert {node.id for node in graph.nodes} == set(SOURCES)
    by_id = {node.id: node for node in graph.nodes}
    assert by_id["handlers.py"].properties["entrypoint"] is True
    assert by_id["executors.py"].properties["entrypoint"] is False
    assert by_id["executors.py"].properties["language"] == "py"


def test_windows_paths_are_normalized_to_posix_ids():
    graph = build_file_graph("t", {"src\\app.py": "x = 1\n"})
    assert [node.id for node in graph.nodes] == ["src/app.py"]


def test_prioritized_files_survive_the_node_budget():
    many = {f"pkg/f{i:04d}.py": "x = 1\n" for i in range(MAX_NODES + 50)}
    target = "pkg/f0649.py"  # sorts last, so it would be cut without prioritization
    graph = build_file_graph("t", many, prioritize=[target])
    assert len(graph.nodes) == MAX_NODES
    assert graph.nodes[0].id == target


def test_unknown_prioritized_paths_are_ignored():
    graph = build_file_graph("t", SOURCES, prioritize=["does/not/exist.py"])
    assert {node.id for node in graph.nodes} == set(SOURCES)


def test_finding_is_grounded_in_the_detector_for_a_real_cwe():
    finding = finding_with_evidence("CLI", "CWE-78", SOURCES)
    assert finding.cwe == "CWE-78"
    assert finding.affected_nodes == ["executors.py"]
    assert any("os.system" in line for line in finding.evidence)
    assert finding.finding_id == "CLI-CWE-78"


def test_finding_without_a_match_still_works_and_claims_no_location():
    finding = finding_with_evidence("CLI", "CWE-89", SOURCES)
    assert finding.cwe == "CWE-89"
    assert finding.affected_nodes == [] and finding.evidence == []


def test_non_cwe_id_is_labelled_unknown_not_guessed():
    finding = finding_with_evidence("MCP", "SENT-PY-008", SOURCES)
    assert finding.cwe == "CWE-Unknown" and finding.affected_nodes == []


class _ScriptedProvider:
    """Returns a plan targeting `node`; records the graph the planner was shown."""

    def __init__(self, node: str, file: str = "executors.py") -> None:
        self.node, self.file = node, file
        self.seen_graph_ids: list[str] = []

    async def generate_structured(self, request: StructuredOutputRequest) -> str:
        payload = json.loads(request.input_text) if request.input_text.startswith("{") else {}
        if "architecture_graph" in payload:
            self.seen_graph_ids = [n["id"] for n in payload["architecture_graph"]["nodes"]]
        return json.dumps({
            "plan_id": "p1",
            "target_language": "python",
            "mutations": [{
                "target_file": self.file,
                "target_node": self.node,
                "action": "rewrite_function",
                "rationale": "replace os.system with subprocess argv list",
                "expected_side_effects": ["none"],
                "acceptance_criteria": ["no shell string execution"],
            }],
            "security_invariants": ["no shell=True"],
            "test_strategy": ["inject ; id"],
        })

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_planner_accepts_a_plan_against_the_real_graph():
    graph = build_file_graph("t", SOURCES)
    finding = finding_with_evidence("CLI", "CWE-78", SOURCES)
    provider = _ScriptedProvider(node="executors.py")
    plan = await ArchitectAgent(provider=provider).create_plan(
        graph_context=graph, findings=[finding], developer_task="Fix CWE-78",
        available_files=SOURCES, target_language=CodeLanguage.AUTO,
    )
    assert plan.mutations[0].target_node == "executors.py"
    assert "executors.py" in provider.seen_graph_ids, "the model must actually be shown the file nodes"


@pytest.mark.asyncio
async def test_the_old_empty_graph_could_never_produce_a_valid_plan():
    """Documents the bug: with no nodes, even a correct plan is rejected."""
    empty = ArchitectureGraphContext(project_id="t", nodes=[], edges=[])
    finding = finding_with_evidence("CLI", "CWE-78", SOURCES)
    with pytest.raises(ArchitectureAgentError, match="unknown graph node"):
        await ArchitectAgent(provider=_ScriptedProvider(node="executors.py")).create_plan(
            graph_context=empty, findings=[finding], developer_task="Fix CWE-78",
            available_files=SOURCES, target_language=CodeLanguage.AUTO,
        )


def test_no_call_site_passes_an_empty_graph_to_the_architect():
    """Guard: every planner call site must build a real graph."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    offenders = []
    for rel in ("arbalest_cli.py", "mcp_server.py", "engine/immune/wargame.py", "engine/ouroboros/mission.py"):
        text = (root / rel).read_text(encoding="utf-8")
        if "nodes=[], edges=[]" in text:
            offenders.append(rel)
    assert offenders == []
