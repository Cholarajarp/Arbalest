"""JavaScript subset taint analysis: direct flows, templates, calls, DOM sinks."""

from __future__ import annotations

from engine.services.taint_analysis import analyze_taint
from engine.services.taint_js import analyze_js_taint


def test_direct_source_to_eval():
    result = analyze_js_taint({"app.js": "const q = req.query.cmd;\neval(q);\n"})
    assert [f.cwe for f in result.findings] == ["CWE-95"]


def test_template_literal_into_exec():
    result = analyze_js_taint({
        "run.js": 'const dir = req.query.dir;\nexec(`du -sh ${dir}`, cb);\n',
    })
    assert [f.cwe for f in result.findings] == ["CWE-78"]


def test_tainted_argument_flows_through_user_function():
    result = analyze_js_taint({
        "via.js": "function run(p) { eval(p); }\nconst x = request.body.expr;\nrun(x);\n",
    })
    assert [f.cwe for f in result.findings] == ["CWE-95"]
    # Once at the tainted call site, once in the request-handler breadth pass.
    assert result.interpretations == 2


def test_inner_html_sink():
    result = analyze_js_taint({"dom.js": "const note = req.params.note;\nel.innerHTML = note;\n"})
    assert [f.cwe for f in result.findings] == ["CWE-79"]


def test_clean_code_is_silent():
    result = analyze_js_taint({
        "ok.js": (
            "const q = req.query.q;\n"
            "const safe = encodeURIComponent(q);\n"
            "res.send(safe);\n"
            "const flag = req.query.a == req.query.b;\n"
            "console.log(flag);\n"
        ),
    })
    assert result.findings == []


def test_every_analyzed_file_records_subset_note():
    result = analyze_js_taint({"a.js": "x = 1;\n", "b.ts": "y = 2;\n"})
    assert result.analyzed_paths == ["a.js", "b.ts"]
    assert {note["reason"] for note in result.notes} == {"js_subset"}


def test_dispatcher_merges_python_and_javascript():
    result = analyze_taint({
        "app.py": "import os\nos.system(input())\n",
        "app.js": "const q = req.query.cmd;\neval(q);\n",
        "notes.md": "text",
    })
    assert {f.cwe for f in result.findings} == {"CWE-78", "CWE-95"}
    assert result.coverage.analyzed_paths == ["app.js", "app.py"]
    assert result.coverage.unsupported_files == ["notes.md"]
    assert result.coverage.complete
    assert "javascript" in result.coverage.as_dict()["supported_languages"]


def test_dispatched_js_findings_carry_file_locations():
    result = analyze_taint({"svc.ts": "const t = ctx.query.t;\neval(t);\n"})
    finding = result.findings[0]
    assert finding.affected_nodes == ["svc.ts"]
    assert finding.finding_id.startswith("TAINT-JS-")
