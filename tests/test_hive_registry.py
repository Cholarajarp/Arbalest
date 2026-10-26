"""HiveRegistry + FleetPatternExchange — global immune memory with P2P semantics."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.hive.exchange import FleetPatternExchange
from engine.hive.registry import HiveRegistry
from engine.immune.antibody import AntibodyLab, AntibodySpec, load_antibodies
from engine.immune.detection import DetectionFinding

VULNERABLE = "def run_shell(cmd):\n    return os.system(cmd)\n"
PATCHED = "def run_shell(cmd):\n    return subprocess.run(cmd, shell=False)\n"


def _finding() -> DetectionFinding:
    return DetectionFinding(
        rule_id="SENT-PY-008", name="Shell command via os.system", cwe="CWE-78",
        severity="high", file="executors.py", line=2, col=12,
        evidence="return os.system(cmd)", hint="Use subprocess with argv list",
    )


def _spec() -> AntibodySpec:
    return AntibodySpec(
        rule_name="os-system-sink", cwe="CWE-78", severity="ERROR",
        pattern_regex=r"os\.system\s*\(",
        message="os.system executes shell strings.",
    )


def test_broadcast_antibody_and_fleet_reload(tmp_path: Path):
    hive = HiveRegistry(tmp_path)
    lab = AntibodyLab(provider=None, root=tmp_path / "origin-repo")
    antibody = lab.build_and_test(_spec(), finding=_finding(),
                                  vulnerable_code=VULNERABLE, patched_code=PATCHED)
    lab.registry.save(antibody)

    record = hive.broadcast_antibody(antibody, origin_repo="origin-repo")
    assert record["origin_repo"] == "origin-repo"
    assert (hive.antibody_dir / f"{antibody.rule_id}.yml").is_file()

    # Every fleet member re-arms from the hive store — the learning loop is global.
    loaded = load_antibodies(tmp_path, directory=hive.antibody_dir)
    assert len(loaded) == 1
    assert loaded[0].rule_id == antibody.rule_id


@pytest.mark.asyncio
async def test_pattern_publish_and_p2p_ack(tmp_path: Path):
    hive = HiveRegistry(tmp_path)
    exchange = FleetPatternExchange(hive)
    receipt = await exchange.publish(
        threat_name="Pickle Session Deserialization",
        cwe_category="CWE-502",
        cypher_pattern="MATCH (f:Function) WHERE f.signature CONTAINS 'pickle.loads' RETURN f",
        origin_repo="authlib",
        source_finding="SENT-PY-004 @ authlib/tokens.py:7",
    )
    assert receipt.pattern_id.startswith("pattern-")
    patterns = hive.list_patterns()
    assert len(patterns) == 1

    # billing-api has not acknowledged → pattern outstanding for it
    outstanding = exchange.outstanding("billing-api")
    assert len(outstanding) == 1
    assert exchange.acknowledge("billing-api", receipt.pattern_id) is True
    assert exchange.outstanding("billing-api") == []
    assert exchange.acknowledge("billing-api", receipt.pattern_id) is False  # idempotent


@pytest.mark.asyncio
async def test_publish_fanout_reports_graph_errors(tmp_path: Path):
    """A graph that cannot accept the pattern is reported, never fatal."""
    from engine.hive.registry import HiveRegistry as R  # noqa: F401 — already imported

    exchange = FleetPatternExchange(HiveRegistry(tmp_path))

    class _OfflineGraph:
        async def add_vulnerability_pattern(self, **kwargs):
            raise ConnectionError("neo4j offline")

    receipt = await exchange.publish(
        threat_name="t", cwe_category="CWE-89", cypher_pattern="MATCH (n) RETURN n",
        origin_repo="repo-a", source_finding="x",
        graph_managers=[("primary", _OfflineGraph())],
    )
    assert receipt.graphs_updated == []
    assert receipt.graph_errors and "neo4j offline" in receipt.graph_errors[0]
