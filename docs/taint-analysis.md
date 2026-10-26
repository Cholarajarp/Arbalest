# Bounded Python cross-file taint analysis

`engine/services/taint_analysis.py` provides a deterministic, local AST may-flow
analysis. It is an initial, deliberately limited analyzer, not a mature security
engine or a proof that code is safe. It neither imports nor executes supplied code,
reads dependencies from disk, calls an AI provider, nor uses the network. The
pipeline and CLI are not modified by this implementation.

## API

```python
from engine.services.taint_analysis import TaintLimits, analyze_taint

result = analyze_taint({
    "pkg/commands.py": "import os\ndef run(cmd):\n    os.system(cmd)\n",
    "pkg/web.py": (
        "from flask import request\nfrom .commands import run\n"
        "def endpoint():\n    run(request.args['cmd'])\n"
    ),
})
for finding in result.findings:
    print(finding.cwe, finding.affected_nodes, finding.evidence)
print(result.coverage.as_dict())

# Optional deterministic resource budgets; defaults are usually sufficient for fixtures.
limited = analyze_taint({"example.py": "eval(input())"}, limits=TaintLimits(max_steps=100))
```

Input is a `Mapping[str, str]` of repository-relative paths to source text. Windows
separators are normalized to `/`. Paths must describe the actual Python import
root: use `pkg/web.py`, not `src/pkg/web.py`, if the application imports `pkg` from
its `src` directory. There is no automatic `sys.path`, workspace-root, namespace
package, or dependency discovery. Module naming uses paths, not filesystem imports.

`TaintResult.findings` is a list of existing `ThreatFinding` objects. Findings have
stable `TAINT-PY-…` identifiers, a CWE, potential-flow descriptions, severity
`high`, involved file paths in `affected_nodes`, and a source-to-sink trace in
`evidence` (`path:line label`). There is one finding per sink location/name/CWE,
with one deterministic representative source trace, not every possible path.
Locations are line-level; identical sources on the same line can coalesce.
Severity is a default triage label, not an exploitability assessment.

## Dataflow model

* Python is parsed with `ast.parse` on the running interpreter. Syntax newer than
  that interpreter produces an explicit parse gap.
* All supplied module bodies and module-level sync/async functions are analyzed.
  Functions use symbolic parameter origins; an ordinary parameter is **not** itself
  an untrusted source. Source reads inside functions are considered potentially
  executable even without a known caller. No entrypoint reachability is inferred.
* Imports, aliases, local imports, relative imports (including parent packages),
  package re-exports, and simple function/request aliases resolve against the
  supplied modules. Missing external function bodies are not guessed.
* Return values and sink effects form function summaries. Deterministic fixed-point
  rounds propagate summaries and module globals across files, including recursion.
  Summaries are instantiated with each call's positional/keyword/default arguments;
  unrelated constant calls do not become tainted because another call was tainted.
* Local assignments are flow-sensitive. Branches union may-values. Strings,
  f-strings, ordinary containers, indexing, simple comprehensions, and awaited
  values propagate taint. Containers are field/key-insensitive; indexing can revoke
  sanitization. Index taint alone does not taint a constant lookup result.
* Loop bodies are approximated with one pass joined with loop entry. This is a
  conservative over-approximation, not a claim of a loop fixed point.
* Unknown calls propagate input/receiver taint, revoke sanitizer guarantees, and
  produce an `unresolved_call` approximation note: they could hide sources, sinks,
  mutations or other behavior. Small modeled sets of builtins/string/path helpers
  propagate taint without assuming they validate input.
* Conservative over-approximations (`unresolved_call`, `loop_approximation`,
  `heap_write`, `conditional_alias`, `expanded_arguments`, `variadic_arguments`,
  `unmodeled_decorator`, `js_subset`) widen or merge abstract state without dropping any
  observed flow. They are recorded in `coverage.approximation_notes` and do not
  fail coverage. Issues that skip semantics or files (parse errors, limits,
  unsupported statements/expressions/constructs) can silently erase taint, stay
  coverage failures, and keep the mission fail-closed.
* JavaScript and TypeScript files run a bounded subset analyzer
  (`engine/services/taint_js.py`): request-object sources (`req`/`request`/
  `event`/`ctx` with query/body/params/headers), assignment/template-literal
  propagation, module-level function calls and request-handler bodies, and
  eval/Function (CWE-95), child_process exec-family (CWE-78) and innerHTML
  (CWE-79) sinks. Go files run the analogous subset
  (`engine/services/taint_go.py`): net/http request sources
  (`r.FormValue`, `r.URL.Query()`, `r.URL.Path`), `:=`/concat/`fmt.Sprintf`
  propagation, handler breadth-pass interpretation, and exec.Command
  (CWE-78, shell-aware: argv-style calls with untrusted arguments are not
  flagged) plus Query/Exec with a tainted query string (CWE-89; parameterized
  queries are not flagged). Every analyzed JS/Go file records a
  `js_subset`/`go_subset` approximation note: constructs outside the subset
  can hide flows.

### Sources

Recognized untrusted origins include:

* Flask-style `request`/`flask.request` attributes and imported aliases: `args`,
  `form`, `values`, `json`, `data`, `headers`, cookies, uploaded files, URL/path and
  query-string values, plus `get_json()` and `get_data()`.
* Django-style `request.GET`, `POST`, `COOKIES`, `META` and `body`.
* Starlette/FastAPI-style `request.query_params`, `path_params`, `json()` and
  `body()`; aiohttp-style `query` and `match_info`.
* Conventionally named `request` parameters, simple aliases, and parameters with
  direct `Request`/`HttpRequest` annotations (not general type inference).
* `input()`, `sys.argv`, `sys.stdin`, `os.environ`, `os.getenv()` and environment
  `.get()` reads, including import aliases.

Environment values are treated as untrusted conservatively; deployments may
trust some of them. Route parameters injected directly as arbitrary function
arguments, `Query`/`Body` dependency injection, arbitrary request variable names
without recognized annotations, socket reads, database results, and custom input
wrappers without supplied bodies are not automatically sources.

### Sinks and sanitizer boundaries

| Family | Recognized sink examples | Treatment |
| --- | --- | --- |
| SQL / CWE-89 | `.execute`, `.executemany`, `.executescript`, `.raw` | Only query/SQL argument is a sink, not bound parameters. Dynamic query strings remain findings even when parameters are also supplied. Method names are conservative heuristics, not inferred database types. |
| Shell / CWE-78 | `os.system`, `os.popen`, `subprocess.getoutput`/`getstatusoutput`; `subprocess.run`/`call`/`check_call`/`check_output`/`Popen` with potentially true `shell=` | Explicit `shell=False` and omitted `shell` are not shell sinks for subprocess APIs. Unknown explicit shell flags are treated as potentially true. |
| Python code / CWE-95 | `eval`, `exec`, `compile` | First/source argument is a sink. This does not cover every executable-code API. |
| Paths / CWE-22 | `open`, `io.open`, `os.open`, remove/unlink/rmdir/listdir/scandir, `shutil.rmtree`, Path-style open/read/write/unlink/iterdir methods | Reports potentially uncontrolled paths, not proven traversal or an authorization bypass. |

Sanitizer modeling is contextual, not a universal “clean” flag:

* `shlex.quote()` blocks only **shell** flows. It does not validate SQL, Python
  expressions or paths. Simple `"echo " + quote(value)` composition is modeled.
  Literal quote/backslash scaffolding, multiple dynamic fragments, dynamic format
  templates/separators and quote-destroying operations conservatively revoke shell
  protection. This is not a shell grammar analysis; prefer argv APIs without a
  shell. Some safe complex shell constructions will be reported.
* Successful `int()`/`float()` conversion blocks injection through that value into
  the SQL/shell/eval families. It does **not** remove user control over a file path.
* Unknown transformations, slicing/indexing, format specifications/conversions,
  encodings and destructive string transforms such as `replace`, `strip` and
  `split` revoke sanitizer guarantees. Most modeled builtins/path helpers also
  conservatively revoke them; ordinary single-argument `str()` preserves them.
* `os.path.normpath`, `abspath`, `realpath`, `Path.resolve`, string escaping,
  encoding, lowercasing and arbitrary functions named `sanitize` are **not**
  recognized as universal validation. In particular, path normalization alone
  does not establish containment under an allowed directory.
* Parameterized SQL is handled by separating the query from parameter values,
  not by globally sanitizing the parameter values. A constant SQL query with
  tainted bound parameters does not produce a query-injection finding.

## Coverage contract

Always inspect `result.coverage.as_dict()` alongside findings. It is JSON-ready
and includes:

* `input_files`, normalized `supported_files`, `analyzed_files`, `analyzed_paths`,
  `skipped_paths`, `unsupported_files` and `unsupported_file_count`;
* `supported_languages`, `supported_scopes`, `completion_scope`, `applicable`,
  `complete`, `status`, `converged`, function/round/step counts;
* all configured `limits` and deterministic `issues`, each with `reason`, `path`,
  `line` and `detail`. Whole-analysis issues can have an empty path and line zero.

**`complete` means the supported Python model reached a fixed point with no
reported bound or semantic gap. It does not mean all Python semantics or all
vulnerability families were analyzed. No findings never means safe.** A result
can contain findings while incomplete. Preserve both findings and coverage.
`analyzed_files` means parsed/indexed files, not a promise that every construct
inside a file was modeled. `converged` can be true despite semantic issues.

Only `.py` files are supported. Non-Python files are counted and listed, but are
not failed Python analyses. With only JavaScript (or no files), coverage is
`applicable=false`, `status="not_applicable"`, and `complete=true` unless an input
normalization issue occurred. A mixed project can complete Python analysis while
listing its JavaScript files as unsupported. Consumers must not interpret that as
JavaScript coverage or make an optional Python analyzer fail every non-Python
project. For Python with a bound/error/gap, `status="incomplete"` and
`complete=false`, even if findings is empty.

Default budgets:

| Budget | Default |
| --- | ---: |
| Python files attempted (sorted by normalized path) | 256 |
| UTF-8 bytes per Python file | 512,000 |
| Total accepted AST nodes | 100,000 |
| Module-level functions | 2,000 |
| Fixed-point rounds | 32 |
| Evaluation steps | 500,000 |
| Origin/sanitizer alternatives per abstract value | 128 |
| Steps per representative trace | 32 |
| Findings | 1,000 |

All limits must be positive integers. `max_trace_steps` cannot exceed the
`ThreatFinding` evidence limit of 50. Limits cap their respective stages, not
wall-clock time or interpreter memory: parsing a size-bounded file happens before
its node count is checked. Caller-supplied source mappings are already in memory.
Hitting any budget records an explicit reason such as `file_limit`,
`file_size_limit`, `ast_node_limit`, `function_limit`, `iteration_limit`,
`step_limit`, `flow_limit`, `trace_limit` or `finding_limit`. Very short traces may
lose intermediate/source steps; trace truncation is always reported. At least
the sink remains in a returned trace. Findings collected in completed rounds are
retained if later rounds stop; interrupted work need not yield all findings.

Other reported gaps include syntax errors, duplicate normalized paths, ambiguous
module names, unresolved relative imports, star imports, arbitrary decorators,
unknown calls, classes, lambdas, nested functions, generators/yields, global or
nonlocal writes, heap writes, variadic/expanded calls and unmodeled statements.
Analysis continues where possible. Issues describe observed gaps, not a complete
inventory of every unmodeled Python behavior.

## Known limitations

This analysis is neither sound nor complete for Python. In particular, it does
not model general object dispatch, inheritance, closures, callbacks, higher-order
functions, reflection, monkey-patching, runtime import paths, module initialization
order, metaprogramming, dependency source code not supplied by the caller, or
heap/alias side effects. Classes are reported as unsupported and their methods
are not summarized. Decorated route bodies are inspected without emulating the
framework. It does not prove branch feasibility, exception behavior, validation
predicates, allowlists, path containment, OS-specific shell quoting, or authorization.
`subprocess` argument injection and explicit interpreters such as `['sh', '-c', x]`
without `shell=True` are outside the shell model. There are no language models for
JavaScript, TypeScript, templates or other non-Python content.

Method-name sink heuristics, ignored branch feasibility, container joins and
untrusted-environment assumptions can produce false positives. Missing sources,
dynamic dispatch, unsupported semantics and bounded traversal can produce false
negatives. Even `complete=true` applies only to this documented model, never to
an entire application or its dependencies.

## Reproducible local benchmark and tests

From the repository root (use `.venv/Scripts/python.exe` on this Windows workspace):

```text
python benchmarks/taint/runner.py
python benchmarks/taint/runner.py --output benchmarks/taint/results.json
python -m pytest tests/test_taint_analysis.py -q
python -m ruff check engine/services/taint_analysis.py tests/test_taint_analysis.py benchmarks/taint/runner.py
python -m mypy engine/services/taint_analysis.py
```

`benchmarks/taint/fixtures/cases.json` contains labeled positive **and** negative
cross-file programs as inert source text. The runner never executes them. It
matches exact `(sink path, sink line, CWE)` tuples, reports TP/FP/FN, measured
precision `TP/(TP+FP)`, recall `TP/(TP+FN)`, fixture/file counts, negative-case counts,
completion, per-case predictions/issues and elapsed analysis seconds. Undefined
ratios are `null`. A mismatch or incomplete fixture returns a nonzero exit code.
Timing is measured locally and is not part of deterministic analyzer output.

Observed local run of the supplied corpus: **18 fixtures, 40 source files,
10 positive fixtures/sinks, 8 negative fixtures; TP=10, FP=0, FN=0; precision=1.0,
recall=1.0; all 18 completed**. Run the command to obtain fresh measurements. These
are small synthetic regression fixtures written with this implementation, not an
independent evaluation, production performance guarantee, broad coverage score,
or comparison with any external tool. No external superiority is claimed.
