"""Behavior, boundedness and reproducibility tests for the optional Python analyzer."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from engine.agents.architect_agent import ThreatFinding
from engine.services.taint_analysis import TaintLimits, analyze_taint

FIXTURES = json.loads(
    (Path(__file__).resolve().parents[1] / "benchmarks/taint/fixtures/cases.json").read_text(encoding="utf-8")
)


def sinks(result):
    found = set()
    for finding in result.findings:
        assert isinstance(finding, ThreatFinding)
        match = re.match(r"^(.*):(\d+) sink ", finding.evidence[-1])
        assert match, finding.evidence
        found.add((match[1], int(match[2]), finding.cwe))
    return found


@pytest.mark.parametrize("case", FIXTURES, ids=lambda case: case["name"])
def test_cross_file_corpus(case):
    result = analyze_taint(case["sources"])
    assert sinks(result) == {tuple(item) for item in case["expected"]}
    assert result.coverage.complete, result.coverage.as_dict()
    if case["expected"]:
        assert all(len(f.affected_nodes) >= 2 for f in result.findings)
        assert all(f.evidence[0].split(" ", 1)[1].startswith("source ") for f in result.findings)


def test_determinism_and_windows_paths():
    sources = {
        "pkg\\sink.py": "import os\ndef run(value):\n    os.system(value)\n",
        "pkg\\web.py": "from .sink import run\nfrom flask import request\nrun(request.args['cmd'])\n",
    }
    first = analyze_taint(sources)
    second = analyze_taint(dict(reversed(list(sources.items()))))
    assert first == second
    assert first.findings[0].affected_nodes == ["pkg/sink.py", "pkg/web.py"]
    assert any("call pkg.sink.run parameter value" in step for step in first.findings[0].evidence)
    assert all("\\" not in step for step in first.findings[0].evidence)


def test_javascript_is_analyzed_by_the_subset_analyzer():
    result = analyze_taint({"index.js": "eval(request.query.cmd)", "readme.md": "text"})
    data = result.coverage.as_dict()
    assert len(result.findings) == 1 and result.findings[0].cwe == "CWE-95"
    assert data["complete"] is True
    assert data["supported_files"] == data["analyzed_files"] == 1
    assert data["unsupported_file_count"] == 1
    assert data["unsupported_files"] == ["readme.md"]
    assert any(note["reason"] == "js_subset" for note in result.coverage.approximation_notes)


def test_mixed_languages_and_empty_input():
    result = analyze_taint({"app.py": "eval(input())", "app.ts": "const v = req.query.v;\neval(v);\n"})
    assert result.coverage.complete
    assert result.coverage.as_dict()["applicable"]
    assert {finding.cwe for finding in result.findings} == {"CWE-95"}
    assert len(result.findings) == 2
    assert analyze_taint({}).coverage.complete


def test_parse_error_does_not_hide_other_findings():
    result = analyze_taint({"bad.py": "def x(", "good.py": "eval(input())"})
    assert not result.coverage.complete
    assert result.coverage.skipped_paths == ["bad.py"]
    assert result.coverage.issues[0]["reason"] == "parse_error"
    assert len(result.findings) == 1


@pytest.mark.parametrize(
    ("limits", "sources", "reason"),
    [
        (TaintLimits(max_files=1), {"a.py": "pass", "b.py": "pass"}, "file_limit"),
        (TaintLimits(max_file_bytes=1), {"a.py": "eval(input())"}, "file_size_limit"),
        (TaintLimits(max_ast_nodes=1), {"a.py": "eval(input())"}, "ast_node_limit"),
        (TaintLimits(max_functions=1), {"a.py": "def a(): pass\ndef b(): pass"}, "function_limit"),
        (TaintLimits(max_steps=1), {"a.py": "eval(input())"}, "step_limit"),
        (TaintLimits(max_iterations=1), {"a.py": "eval(input())"}, "iteration_limit"),
        (TaintLimits(max_flows=1), {"a.py": "x = input()\ny = input()\neval(x + y)"}, "flow_limit"),
        (TaintLimits(max_trace_steps=1), {"a.py": "x = input()\neval(x)"}, "trace_limit"),
        (TaintLimits(max_findings=1), {"a.py": "eval(input())\nexec(input())"}, "finding_limit"),
    ],
)
def test_limits_are_explicit_incomplete(limits, sources, reason):
    result = analyze_taint(sources, limits=limits)
    assert not result.coverage.complete
    assert reason in {issue["reason"] for issue in result.coverage.issues}
    assert result.coverage.as_dict()["limits"] == limits.__dict__


def test_invalid_limits():
    with pytest.raises(ValueError):
        TaintLimits(max_steps=0)
    with pytest.raises(ValueError):
        TaintLimits(max_trace_steps=51)


def test_fixed_point_is_necessary_for_long_call_chain():
    sources = {
        "a.py": "def relay(v):\n    return v\n",
        "b.py": "from a import relay\ndef relay2(v):\n    return relay(v)\n",
        "c.py": "from b import relay2\ndef relay3(v):\n    return relay2(v)\n",
        "web.py": "from c import relay3\neval(relay3(input()))\n",
    }
    result = analyze_taint(sources)
    assert result.coverage.complete
    assert result.coverage.iterations >= 4
    assert len(result.findings) == 1
    assert result.findings[0].affected_nodes == ["a.py", "b.py", "c.py", "web.py"]
    bounded = analyze_taint(sources, limits=TaintLimits(max_iterations=2))
    assert not bounded.coverage.complete


def test_branch_union_and_overwrite():
    sources = {
        "app.py": """from flask import request
value = 'safe'
if True:
    value = request.args['cmd']
else:
    value = 'other'
eval(value)
value = 'fixed'
eval(value)
"""
    }
    assert sinks(analyze_taint(sources)) == {("app.py", 7, "CWE-95")}


def test_independent_call_sites_do_not_contaminate_constant_calls():
    sources = {
        "helpers.py": "def identity(v):\n    return v\n",
        "app.py": "from helpers import identity\nx = identity(input())\neval(identity('1'))\neval(x)\n",
    }
    assert sinks(analyze_taint(sources)) == {("app.py", 4, "CWE-95")}


def test_sanitizers_are_sink_specific_and_paths_stay_controlled():
    sources = {
        "app.py": """import shlex
import os
x = input()
quoted = shlex.quote(x)
os.system('echo ' + quoted)
eval(quoted)
open(quoted)
open(str(int(x)))
"""
    }
    assert sinks(analyze_taint(sources)) == {
        ("app.py", 6, "CWE-95"),
        ("app.py", 7, "CWE-22"),
        ("app.py", 8, "CWE-22"),
    }


def test_partial_sanitization_retains_unsanitized_flow():
    result = analyze_taint({"app.py": "import os, shlex\nx = input()\nos.system(shlex.quote(x) + x)"})
    assert len(result.findings) == 1


def test_unknown_transform_preserves_taint_and_reports_gap():
    result = analyze_taint({"app.py": "eval(custom_escape(input()))"})
    assert len(result.findings) == 1
    assert any(issue["reason"] == "unresolved_call" for issue in result.coverage.approximation_notes)


def test_shadowed_builtin_is_not_a_sanitizer():
    result = analyze_taint({"app.py": "def run(int):\n    eval(int(input()))\n"})
    assert len(result.findings) == 1
    assert result.coverage.complete


def test_request_alias_and_annotated_request():
    result = analyze_taint(
        {
            "app.py": """def endpoint(req: Request):
    alias = req
    eval(alias.query_params['code'])
"""
        }
    )
    assert result.coverage.complete
    assert len(result.findings) == 1


def test_local_import_alias():
    result = analyze_taint(
        {
            "helper.py": "def run(code):\n    exec(code)\n",
            "app.py": "def endpoint():\n    from helper import run as execute\n    from flask import request as req\n    execute(req.args['code'])\n",
        }
    )
    assert result.coverage.complete
    assert sinks(result) == {("helper.py", 2, "CWE-95")}


def test_module_globals_across_files():
    result = analyze_taint({"settings.py": "value = input()\n", "app.py": "from settings import value\neval(value)"})
    assert len(result.findings) == 1
    assert result.coverage.complete


def test_keyword_and_default_arguments():
    result = analyze_taint(
        {
            "helper.py": "def run(code=input()):\n    eval(code)\n",
            "main.py": "from helper import run\nrun()\n",
        }
    )
    assert result.coverage.complete
    assert sinks(result) == {("helper.py", 2, "CWE-95")}


@pytest.mark.parametrize(
    "source, reason",
    [
        ("from unknown import *", "star_import"),
        ("class Handler:\n    pass", "unsupported_construct"),
        ("def outer():\n    def inner(): pass", "nested_function"),
        ("assert eval(input())", "unsupported_statement"),
    ],
)
def test_skipped_semantics_fail_coverage(source, reason):
    result = analyze_taint({"app.py": source})
    assert not result.coverage.complete
    assert reason in {issue["reason"] for issue in result.coverage.failures}


@pytest.mark.parametrize(
    "source, reason",
    [
        ("for x in []:\n    pass", "loop_approximation"),
        ("values = []\nvalues[0] = input()\neval(values[0])", "heap_write"),
        ("__import__('dynamic')", "unresolved_call"),
    ],
)
def test_conservative_approximations_are_notes_not_failures(source, reason):
    result = analyze_taint({"app.py": source})
    assert result.coverage.complete
    assert reason in {issue["reason"] for issue in result.coverage.approximation_notes}


def test_unknown_shell_flag_is_potential_shell_execution():
    result = analyze_taint({"app.py": "import subprocess\nsubprocess.run(input(), shell=flag)"})
    assert sinks(result) == {("app.py", 2, "CWE-78")}


def test_comprehension_and_fstring_propagation():
    result = analyze_taint({"app.py": "x = [f'{part}' for part in [input()]]\neval(''.join(x))"})
    assert result.coverage.complete
    assert len(result.findings) == 1


@pytest.mark.parametrize(
    "expression",
    [
        "'echo \\\"' + quoted + '\\\"'",
        "quoted[1:-1]",
        'quoted.strip("\'")',
        "quoted.replace(\"'\", '')",
        "f'echo \\\"{quoted}\\\"'",
        "'echo \\\"{}\\\"'.format(quoted)",
        "format(quoted, '.3')",
        "'echo {:.3}'.format(quoted)",
        "f'{quoted:.3}'",
        "quoted.encode().decode('unicode_escape')",
        "''.join(sorted(quoted))",
    ],
)
def test_shell_quote_is_not_safe_in_arbitrary_context(expression):
    source = "import os, shlex\nquoted = shlex.quote(input())\nos.system(" + expression + ")"
    result = analyze_taint({"app.py": source})
    assert len(result.findings) == 1
    assert result.coverage.complete


def test_unsafe_shell_context_in_callee_summary():
    result = analyze_taint(
        {
            "helper.py": "def wrap(value):\n    return '\\\"' + value + '\\\"'\n",
            "app.py": "import os, shlex\nfrom helper import wrap\nos.system(wrap(shlex.quote(input())))\n",
        }
    )
    assert result.coverage.complete
    assert sinks(result) == {("app.py", 3, "CWE-78")}


def test_unknown_transform_can_invalidate_sanitization():
    result = analyze_taint({"app.py": "eval(unknown(int(input())))"})
    assert len(result.findings) == 1
    assert result.coverage.approximation_notes


def test_pathlib_open_and_stdin():
    result = analyze_taint({"app.py": "from pathlib import Path\nimport sys\nPath(sys.stdin.read()).open()"})
    assert result.coverage.complete
    assert sinks(result) == {("app.py", 3, "CWE-22")}


@pytest.mark.parametrize(
    "source",
    [
        "from os import environ as env\neval(env['EXPR'])",
        "from sys import stdin as stream\neval(stream.read())",
        "from sys import argv as args\neval(args[1])",
    ],
)
def test_direct_import_source_aliases(source):
    result = analyze_taint({"app.py": source})
    assert result.coverage.complete
    assert len(result.findings) == 1


def test_conditional_function_definition_is_a_reported_gap():
    result = analyze_taint({"app.py": "if flag:\n    def run():\n        eval(input())"})
    assert not result.coverage.complete
    assert any(issue["reason"] == "nested_function" for issue in result.coverage.issues)


def test_unknown_function_named_sanitize_is_not_magically_trusted():
    result = analyze_taint(
        {
            "helper.py": "def sanitize(value):\n    return value\n",
            "app.py": "from helper import sanitize\neval(sanitize(input()))",
        }
    )
    assert result.coverage.complete
    assert len(result.findings) == 1


def test_parameterization_does_not_protect_a_tainted_query():
    result = analyze_taint({"app.py": "def run(cursor):\n    cursor.execute(input(), ('bound',))"})
    assert result.coverage.complete
    assert sinks(result) == {("app.py", 2, "CWE-89")}


def test_duplicate_normalized_paths_are_explicit():
    result = analyze_taint({"pkg/app.py": "pass", "pkg\\app.py": "eval(input())"})
    assert not result.coverage.complete
    assert result.coverage.issues[0]["reason"] == "duplicate_path"
