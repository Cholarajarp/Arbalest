"""Hive Mind — federated topology: real cross-repo import resolution and tracing."""

from __future__ import annotations

from pathlib import Path

from engine.hive.federation import FleetTopology
from engine.hive.fleet_commander import FleetCommanderAgent
from engine.immune.detection import sweep_sources
from engine.services.source_collector import collect_sources

FLEET_DIR = Path(__file__).resolve().parent.parent / "examples" / "hive_fleet"


def _topology() -> tuple[FleetTopology, dict[str, list]]:
    repos = {
        name: collect_sources(path)
        for name, path in sorted((p.name, p) for p in FLEET_DIR.iterdir() if p.is_dir())
    }
    topology = FleetTopology(repos)
    findings = {
        repo: sweep_sources(sources) for repo, sources in repos.items()
    }
    return topology, findings


def test_fleet_discovery_and_graph():
    topology, findings = _topology()
    assert set(topology.repos) == {"authlib", "billing-api", "search-api"}
    total_nodes = len(topology._funcs)
    assert total_nodes >= 4                       # load_session, sign_token, session_endpoint, index_query
    # Cross-repo CALLS edge: billing-api session_endpoint → authlib load_session
    cross = [(s, d) for s, d in topology.cross_edges if s.startswith("billing-api:") and d.startswith("authlib:")]
    assert cross, "billing-api must be linked to authlib by real import resolution"


def test_cross_repo_blast_radius_proven():
    topology, findings = _topology()
    pickle_finding = next(
        f for f in findings["authlib"] if f.rule_id == "SENT-PY-004"
    )
    radius = topology.trace("authlib", pickle_finding)
    assert radius.proven is True
    assert radius.affected_repos == ["authlib", "billing-api"]
    assert any("billing-api" in entry for entry in radius.entrypoints), (
        "the public route reaching the authlib sink lives in billing-api"
    )
    chain = radius.chains[0]
    assert chain[0]["repo"] == "billing-api"      # chain starts at the downstream route
    assert chain[-1]["repo"] == "authlib"         # and terminates at the sink
    assert "PROVEN" in radius.verdict and "spanning 2 repositories" in radius.verdict


def test_isolated_sink_in_clean_repo():
    topology, findings = _topology()
    assert findings["search-api"] == []


def test_fleet_commander_dispatch_plan():
    topology, findings = _topology()
    pickle_finding = next(f for f in findings["authlib"] if f.rule_id == "SENT-PY-004")
    radius = topology.trace("authlib", pickle_finding)
    commander = FleetCommanderAgent()
    plan = commander.plan_response(topology, "authlib", pickle_finding, radius, findings)

    assert plan.affected_repos == ["authlib", "billing-api"]
    origin_order = next(o for o in plan.orders if o.kind == "origin")
    assert origin_order.repo == "authlib"
    # billing-api has no sink of its own for CWE-502 → integration audit, not a wargame
    audits = [o for o in plan.orders if o.kind == "integration_audit"]
    assert any(o.repo == "billing-api" for o in audits)


def test_fleet_commander_dispatches_downstream_wargame_for_own_sink():
    topology, findings = _topology()
    pickle_finding = next(f for f in findings["authlib"] if f.rule_id == "SENT-PY-004")
    radius = topology.trace("authlib", pickle_finding)
    # Simulate billing-api having its own CWE-502 sink (real downstream condition)
    findings_by_repo = dict(findings)
    from engine.immune.detection import DetectionFinding

    findings_by_repo["billing-api"] = [
        DetectionFinding(
            rule_id="SENT-PY-004", name="Unsafe deserialization (pickle)", cwe="CWE-502",
            severity="critical", file="cache.py", line=3, col=12, evidence="pickle.loads(raw)",
        )
    ]
    commander = FleetCommanderAgent()
    plan = commander.plan_response(topology, "authlib", pickle_finding, radius, findings_by_repo)
    downstream = [o for o in plan.orders if o.kind == "downstream"]
    assert [o.repo for o in downstream] == ["billing-api"]
    assert downstream[0].finding.file == "cache.py"
