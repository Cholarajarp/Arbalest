"""Topological blast-radius mapping — real AST call graphs, real attack chains."""

from __future__ import annotations

from engine.immune.detection import sweep_sources
from engine.immune.topology import TopologyMapper

ROUTES = '''from flask import Flask, request
from handlers import run_scan

app = Flask(__name__)


@app.route("/scan")
def scan_endpoint():
    repo = request.args.get("repo", ".")
    return run_scan(repo)
'''

HANDLERS = '''from executors import run_shell


def run_scan(repo):
    command = "git clone " + repo
    return run_shell(command)
'''

EXECUTORS = '''import os


def run_shell(cmd):
    return os.system(cmd)


def orphan_sink(cmd):
    return os.system(cmd)
'''

JS = '''const express = require("express");
const app = express();

function getUsers(req, res) {
  return eval(req.query.x);
}

app.get("/users", getUsers);
'''


def _mapper() -> TopologyMapper:
    return TopologyMapper({
        "routes.py": ROUTES, "handlers.py": HANDLERS,
        "executors.py": EXECUTORS, "web.js": JS,
    })


def test_graph_nodes_and_call_edges():
    mapper = _mapper()
    names = {f.name for f in mapper._funcs.values()}
    assert {"scan_endpoint", "run_scan", "run_shell", "orphan_sink", "getUsers"} <= names
    assert ("handlers.py::run_scan", "executors.py::run_shell") in mapper._edges
    assert ("routes.py::scan_endpoint", "handlers.py::run_scan") in mapper._edges


def test_cross_file_route_edge_via_import():
    mapper = _mapper()
    route = next(f for f in mapper._funcs.values() if f.is_route and f.route_path == "/scan")
    assert route.name == "scan_endpoint"
    # scan_endpoint calls run_scan (imported from handlers) — the import edge exists
    assert mapper._forward.get(route.node_id), "route must have an outgoing CALLS edge"


def test_blast_radius_proves_exploitability():
    mapper = _mapper()
    findings = sweep_sources({"executors.py": EXECUTORS})
    os_finding = next(f for f in findings if f.rule_id == "SENT-PY-008" and f.line == 5)
    radius = mapper.trace(os_finding)
    assert radius.proven is True
    assert radius.entrypoints and "/scan" in radius.entrypoints[0]
    chain = radius.chains[0]
    assert [hop["name"] for hop in chain] == ["scan_endpoint()", "run_scan(repo)", "run_shell(cmd)"]
    assert chain[-1]["file"] == "executors.py"
    assert "PROVEN" in radius.verdict


def test_orphan_sink_is_isolated():
    mapper = _mapper()
    findings = sweep_sources({"executors.py": EXECUTORS})
    orphan = next(f for f in findings if f.rule_id == "SENT-PY-008" and f.line == 9)
    radius = mapper.trace(orphan)
    assert radius.proven is False
    assert "ISOLATED" in radius.verdict


def test_js_route_chain():
    mapper = _mapper()
    findings = sweep_sources({"web.js": JS})
    eval_finding = next(f for f in findings if f.rule_id == "SENT-JS-001")
    radius = mapper.trace(eval_finding)
    assert radius.proven is True
    assert "/users" in radius.entrypoints[0]


def test_downstream_blast_radius():
    from engine.immune.detection import DetectionFinding

    mapper = _mapper()
    # Sink at the route handler itself: downstream = run_scan + run_shell
    route_finding = DetectionFinding(
        rule_id="SENT-PY-013", name="AWS access key literal", cwe="CWE-798",
        severity="critical", file="routes.py", line=9, col=12,
        evidence="return run_scan(repo)",
    )
    radius = mapper.trace(route_finding)
    assert set(radius.downstream) == {"handlers.py::run_scan", "executors.py::run_shell"}


def test_node_budget_enforced():
    many = "\n\n".join(f"def fn_{i}(x):\n    return fn_{i + 1}(x)" for i in range(700))
    mapper = TopologyMapper({"big.py": many})
    assert len(mapper._funcs) <= 600
    assert mapper.truncated_nodes > 0
