"""Ouroboros governance — the constitution is mechanical, not advisory."""

from __future__ import annotations

from pathlib import Path


from engine.agents.architect_agent import CodeLanguage, MutationPlan, MutationStep, MutationAction
from engine.agents.polyglot_translator import GeneratedCodeBundle, GeneratedFile
from engine.ouroboros.metacognitive import MetacognitiveAgent

REPO_ROOT = Path(__file__).resolve().parent.parent


def _agent(tmp_path: Path) -> MetacognitiveAgent:
    return MetacognitiveAgent(self_root=tmp_path)


def _bundle(files: dict[str, str]) -> GeneratedCodeBundle:
    return GeneratedCodeBundle(
        language=CodeLanguage.PYTHON,
        entrypoint=next(iter(files)),
        files=[GeneratedFile(path=p, content=c) for p, c in files.items()],
        build_instructions=["python -m compileall ."],
        test_instructions=["python mirror_harness.py"],
    )


def _plan(targets: list[str]) -> MutationPlan:
    return MutationPlan(
        plan_id="plan-evo",
        target_language=CodeLanguage.PYTHON,
        mutations=[
            MutationStep(
                target_file=t, target_node=f"n:{t}", action=MutationAction.REWRITE_FUNCTION,
                rationale="capability", expected_side_effects=[], acceptance_criteria=["works"],
            )
            for t in targets
        ],
        security_invariants=["no new dangerous constructs"], test_strategy=["mirror sandbox"],
    )


CLEAN_MUTATION = {
    "engine/immune/detection.py": (
        '"""Deterministic detection tripwire."""\n\n\ndef ouroboros_sentinel():\n    return 42\n'
    )
}


def test_meta_graph_maps_request_to_real_modules():
    agent = MetacognitiveAgent(self_root=REPO_ROOT)
    sources = agent.self_sources()
    assert "arbalest_cli.py" in sources and "engine/immune/topology.py" in sources

    targets = agent.map_meta_graph(sources, "Add Java AST parsing support to the topology parser")
    matched_files = [t.file for t in targets]
    assert "engine/immune/topology.py" in matched_files, (
        "the topology parser must remain a candidate as other AST modules are added"
    )
    assert [t.score for t in targets] == sorted((t.score for t in targets), reverse=True)
    assert all(t.score > 0 for t in targets)


def test_import_closure_includes_package_inits_and_external_deps():
    agent = MetacognitiveAgent(self_root=REPO_ROOT)
    sources = agent.self_sources()
    closure, external = agent.import_closure(["engine/immune/topology.py"], sources)
    assert "engine/immune/topology.py" in closure
    assert "engine/__init__.py" in closure and "engine/immune/__init__.py" in closure
    assert "engine/agents/architect_agent.py" in closure
    assert {"pydantic", "openai"} <= set(external), external


def test_constitution_vetoes_governor_self_mutation(tmp_path: Path):
    agent = _agent(tmp_path)
    decision = agent.review_mutation(
        _bundle({"engine/ouroboros/metacognitive.py": "x = 1\n"}),
        _plan(["engine/ouroboros/metacognitive.py"]),
        {},
    )
    assert decision.approved is False
    assert any("protected" in v for v in decision.vetoes)


def test_constitution_vetoes_dangerous_constructs(tmp_path: Path):
    agent = _agent(tmp_path)
    decision = agent.review_mutation(
        _bundle({"engine/immune/detection.py": "import os\n\n\ndef run(cmd):\n    return os.system(cmd)\n"}),
        _plan(["engine/immune/detection.py"]),
        {},
    )
    assert decision.approved is False
    assert any("SENT-PY-008" in v for v in decision.vetoes)


def test_constitution_enforces_diff_bounds(tmp_path: Path):
    agent = _agent(tmp_path)
    files = {f"engine/immune/mod{i}.py": "# " + "x" * 400 + f"\n# gen {i}\n" for i in range(9)}
    decision = agent.review_mutation(_bundle(files), _plan(list(files)), {})
    assert decision.approved is False
    assert any("bound" in v for v in decision.vetoes)


def test_loop_guard_refuses_identical_mutation(tmp_path: Path):
    agent = _agent(tmp_path)
    first = agent.review_mutation(_bundle(CLEAN_MUTATION), _plan(list(CLEAN_MUTATION)), {})
    assert first.approved is True
    agent.record_commit(first.mutation_hash, "gen-1", list(CLEAN_MUTATION))
    second = agent.review_mutation(_bundle(CLEAN_MUTATION), _plan(list(CLEAN_MUTATION)), {})
    assert second.approved is False
    assert any("loop guard" in v for v in second.vetoes)


def test_clean_mutation_is_approved(tmp_path: Path):
    agent = _agent(tmp_path)
    decision = agent.review_mutation(_bundle(dict(CLEAN_MUTATION)), _plan(list(CLEAN_MUTATION)), {})
    assert decision.approved is True
    assert decision.vetoes == []


def test_capability_test_hygiene():
    agent = _agent(tmp_path=Path("."))
    assert agent.review_capability_test("from engine.immune.detection import sweep_file\nassert sweep_file\n") == []
    vetoes = agent.review_capability_test("import subprocess\nsubprocess.run(['ls'])\n")
    assert vetoes and "prohibited primitive" in vetoes[0]
