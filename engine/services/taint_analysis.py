"""Bounded, deterministic Python AST taint analysis; no code is imported or executed.

This is a small may-flow analysis, not a proof of safety. See docs/taint-analysis.md
for the supported scope, modeling assumptions and deliberately explicit coverage gaps.
"""

from __future__ import annotations

import ast
import hashlib
import posixpath
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from engine.agents.architect_agent import Severity, ThreatFinding

_KINDS = frozenset({"sql", "shell", "eval", "path"})
_CWES = {"sql": "CWE-89", "shell": "CWE-78", "eval": "CWE-95", "path": "CWE-22"}
_REQUEST_FIELDS = frozenset(
    {
        "args",
        "form",
        "values",
        "json",
        "data",
        "query_params",
        "path_params",
        "GET",
        "POST",
        "COOKIES",
        "cookies",
        "headers",
        "body",
        "files",
        "META",
        "environ",
        "query",
        "match_info",
        "query_string",
        "path",
        "full_path",
        "url",
    }
)
_SOURCE_ROOTS = frozenset({"request", "flask.request", "django.http.request", "aiohttp.request"})
_PURE = frozenset(
    {
        "str",
        "bytes",
        "list",
        "tuple",
        "dict",
        "set",
        "repr",
        "format",
        "sorted",
        "min",
        "max",
        "len",
        "bool",
        "abs",
        "range",
        "enumerate",
        "zip",
        "print",
        "isinstance",
        "type",
        "os.path.join",
        "os.path.abspath",
        "os.path.normpath",
        "os.path.realpath",
        "pathlib.Path",
        "Path",
    }
)
_SHELL = frozenset({"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"})
_PROCESS = frozenset(
    {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}
)
_PATH = frozenset(
    {"open", "io.open", "os.open", "os.remove", "os.unlink", "os.rmdir", "os.listdir", "os.scandir", "shutil.rmtree"}
)
# Issues that only widen or merge abstract state: every observed flow is kept
# (unknown calls are marked with all unsafe kinds, loops take one joined pass).
# They are approximation notes, not coverage failures. Anything that skips
# semantics (statements, expressions, files) can silently erase taint and
# remains a failure.
_APPROXIMATION_REASONS = frozenset(
    {
        "unresolved_call",
        "loop_approximation",
        "heap_write",
        "conditional_alias",
        "expanded_arguments",
        "variadic_arguments",
        "unmodeled_decorator",
        "js_subset",
        "go_subset",
    }
)


@dataclass(frozen=True)
class TaintLimits:
    max_files: int = 256
    max_file_bytes: int = 512_000
    max_ast_nodes: int = 100_000
    max_functions: int = 2_000
    max_iterations: int = 32
    max_steps: int = 500_000
    max_flows: int = 128
    max_trace_steps: int = 32
    max_findings: int = 1_000

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 1 for value in asdict(self).values()):
            raise ValueError("All taint limits must be positive integers")
        if self.max_trace_steps > 50:
            raise ValueError("max_trace_steps must fit ThreatFinding's 50 evidence entries")


@dataclass
class TaintCoverage:
    """`complete` is completion of supported Python analysis, never a clean bill of health."""

    input_files: int = 0
    supported_files: int = 0
    analyzed_files: int = 0
    unsupported_files: list[str] = field(default_factory=list)
    analyzed_paths: list[str] = field(default_factory=list)
    skipped_paths: list[str] = field(default_factory=list)
    issues: list[dict[str, Any]] = field(default_factory=list)
    iterations: int = 0
    steps: int = 0
    functions: int = 0
    converged: bool = False
    limits: dict[str, int] = field(default_factory=dict)

    @property
    def failures(self) -> list[dict[str, Any]]:
        """Issues where semantics or files were skipped and taint may have been erased."""
        return [issue for issue in self.issues if issue.get("reason") not in _APPROXIMATION_REASONS]

    @property
    def approximation_notes(self) -> list[dict[str, Any]]:
        """Recorded conservative over-approximations; no observed flow was dropped."""
        return [issue for issue in self.issues if issue.get("reason") in _APPROXIMATION_REASONS]

    @property
    def complete(self) -> bool:
        return self.converged and not self.failures

    def as_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "complete": self.complete,
            "applicable": self.supported_files > 0,
            "supported_languages": ["python", "javascript", "go"],
            "supported_scopes": [
                "python_modules", "module_functions", "direct_import_calls",
                "javascript_direct_flows",
                "go_direct_flows",
            ],
            "unsupported_file_count": len(self.unsupported_files),
            "approximation_note_count": len(self.approximation_notes),
            "status": "not_applicable" if not self.supported_files else ("complete" if self.complete else "incomplete"),
            "completion_scope": (
                "supported Python AST may-flow model; not proof of absence of vulnerabilities; "
                "conservative over-approximations are recorded as notes and do not fail coverage"
            ),
        }


@dataclass
class TaintResult:
    findings: list[ThreatFinding]
    coverage: TaintCoverage


@dataclass(frozen=True, order=True)
class _Step:
    path: str
    line: int
    label: str

    def text(self) -> str:
        return f"{self.path}:{self.line} {self.label}"


@dataclass(frozen=True, order=True)
class _Origin:
    kind: str
    owner: str
    name: str
    path: str = ""
    line: int = 0


@dataclass(frozen=True)
class _Flow:
    origin: _Origin
    safe: frozenset[str]
    trace: tuple[_Step, ...]


_Value = tuple[_Flow, ...]


def _dotted(node: ast.AST | None) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        parts.append(node.value)
    return ".".join(reversed(parts))


@dataclass(frozen=True, order=True)
class _Site:
    path: str
    line: int
    kind: str
    name: str


@dataclass
class _Summary:
    returns: _Value = ()
    sinks: dict[_Site, _Value] = field(default_factory=dict)


@dataclass
class _Module:
    path: str
    name: str
    package: str
    tree: ast.Module
    aliases: dict[str, str]
    globals: dict[str, _Value] = field(default_factory=dict)


@dataclass
class _Function:
    name: str
    module: _Module
    node: ast.FunctionDef | ast.AsyncFunctionDef
    params: list[str]


class _BudgetExceeded(Exception):
    pass


class _Analyzer:
    def __init__(self, sources: Mapping[str, str], limits: TaintLimits) -> None:
        self.limits = limits
        self.coverage = TaintCoverage(input_files=len(sources), limits=asdict(limits))
        self.modules: dict[str, _Module] = {}
        self.functions: dict[str, _Function] = {}
        self.summaries: dict[str, _Summary] = {}
        self.module_summaries: dict[str, _Summary] = {}
        self._issues: set[tuple[str, str, int, str]] = set()
        self._load(sources)

    def issue(self, reason: str, path: str = "", line: int = 0, detail: str = "") -> None:
        self._issues.add((reason, path, line, detail))

    def tick(self) -> None:
        self.coverage.steps += 1
        if self.coverage.steps > self.limits.max_steps:
            self.issue("step_limit")
            raise _BudgetExceeded

    def value(self, *values: _Value) -> _Value:
        best: dict[tuple[_Origin, frozenset[str]], _Flow] = {}
        for flows in values:
            for flow in flows:
                key = (flow.origin, flow.safe)
                previous = best.get(key)
                if previous is None or (len(flow.trace), flow.trace) < (len(previous.trace), previous.trace):
                    best[key] = flow
        ordered = sorted(best.values(), key=lambda f: (f.origin, sorted(f.safe), len(f.trace), f.trace))
        if len(ordered) > self.limits.max_flows:
            self.issue("flow_limit")
        return tuple(ordered[: self.limits.max_flows])

    def step(self, value: _Value, step: _Step) -> _Value:
        result = []
        for flow in value:
            trace = flow.trace
            if not trace or trace[-1] != step:
                trace += (step,)
            if len(trace) > self.limits.max_trace_steps:
                self.issue("trace_limit", step.path, step.line)
                # Preserve the source and latest sink/call rather than silently dropping either.
                trace = trace[: max(0, self.limits.max_trace_steps - 1)] + (step,)
            result.append(_Flow(flow.origin, flow.safe, trace))
        return self.value(tuple(result))

    def _aliases(self, module: _Module, statements: list[ast.stmt], aliases: dict[str, str]) -> None:
        for node in statements:
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split(".")[0]] = (
                        item.name if item.asname else item.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom):
                parts = module.package.split(".") if module.package else []
                if node.level:
                    if node.level > len(parts):
                        self.issue("unresolved_relative_import", module.path, node.lineno)
                    base = ".".join(parts[: len(parts) - node.level + 1])
                    base = ".".join(filter(None, (base, node.module)))
                else:
                    base = node.module or ""
                for item in node.names:
                    if item.name == "*":
                        self.issue("star_import", module.path, node.lineno)
                    else:
                        aliases[item.asname or item.name] = ".".join(filter(None, (base, item.name)))

    def resolve(self, name: str) -> str:
        seen = set()
        while name not in seen:
            seen.add(name)
            replacement = name
            # Resolve package re-exports as well as `import pkg.mod as alias`.
            for module_name in sorted(self.modules, key=lambda s: (-len(s), s)):
                if name.startswith(module_name + "."):
                    rest = name[len(module_name) + 1 :]
                    first, _, suffix = rest.partition(".")
                    target = self.modules[module_name].aliases.get(first)
                    if target:
                        replacement = target + ("." + suffix if suffix else "")
                        break
            if replacement == name:
                return name
            name = replacement
        return name

    def _load(self, sources: Mapping[str, str]) -> None:
        normalized: dict[str, str] = {}
        for path, text in sorted(sources.items()):
            name = posixpath.normpath(path.replace("\\", "/"))
            if name in normalized:
                self.issue("duplicate_path", name)
            else:
                normalized[name] = text
        python_paths = [p for p in sorted(normalized) if p.lower().endswith(".py")]
        self.coverage.supported_files = len(python_paths)
        python_path_set = set(python_paths)
        self.coverage.unsupported_files = [p for p in sorted(normalized) if p not in python_path_set]
        total_nodes = 0
        for index, path in enumerate(python_paths):
            text = normalized[path]
            if index >= self.limits.max_files:
                self.issue("file_limit", path)
                self.coverage.skipped_paths.append(path)
                continue
            if len(text.encode("utf-8", errors="replace")) > self.limits.max_file_bytes:
                self.issue("file_size_limit", path)
                self.coverage.skipped_paths.append(path)
                continue
            try:
                tree = ast.parse(text, filename=path)
                count = sum(1 for _ in ast.walk(tree))
            except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
                self.issue("parse_error", path, getattr(exc, "lineno", 0) or 0, getattr(exc, "msg", type(exc).__name__))
                self.coverage.skipped_paths.append(path)
                continue
            if total_nodes + count > self.limits.max_ast_nodes:
                self.issue("ast_node_limit", path)
                self.coverage.skipped_paths.append(path)
                continue
            total_nodes += count
            stem = path[:-3].replace("/", ".")
            name = stem.removesuffix(".__init__") if stem.endswith(".__init__") else stem
            package = name if posixpath.basename(path) == "__init__.py" else name.rpartition(".")[0]
            if name in self.modules:
                self.issue("ambiguous_module", path, detail=name)
                self.coverage.skipped_paths.append(path)
                continue
            module = _Module(path, name, package, tree, {})
            self._aliases(module, tree.body, module.aliases)
            self.modules[name] = module
            self.coverage.analyzed_paths.append(path)
            top_level_nodes = set(tree.body)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node not in top_level_nodes:
                    self.issue("nested_function", path, node.lineno)
                if isinstance(node, (ast.ClassDef, ast.Lambda, ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom)):
                    self.issue("unsupported_construct", path, node.lineno, type(node).__name__)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if len(self.functions) >= self.limits.max_functions:
                        self.issue("function_limit", path, node.lineno)
                        continue
                    args = node.args
                    params = [p.arg for p in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
                    if args.vararg:
                        params.append(args.vararg.arg)
                    if args.kwarg:
                        params.append(args.kwarg.arg)
                    full = f"{name}.{node.name}"
                    self.functions[full] = _Function(full, module, node, params)
                    self.summaries[full] = _Summary()
                    if node.decorator_list:
                        # Route decorators do not change body analysis; arbitrary wrappers may.
                        for decorator in node.decorator_list:
                            raw = _dotted(decorator.func if isinstance(decorator, ast.Call) else decorator)
                            if raw.rsplit(".", 1)[-1] not in {"route", "get", "post", "put", "delete", "patch"}:
                                self.issue("unmodeled_decorator", path, decorator.lineno, raw[:120])
        self.coverage.analyzed_files = len(self.modules)
        self.coverage.functions = len(self.functions)

    def merge_summary(self, old: _Summary, new: _Summary) -> _Summary:
        return _Summary(
            self.value(old.returns, new.returns),
            {
                site: self.value(old.sinks.get(site, ()), new.sinks.get(site, ()))
                for site in sorted(old.sinks.keys() | new.sinks.keys())
            },
        )

    def run(self) -> TaintResult:
        try:
            for iteration in range(self.limits.max_iterations):
                self.coverage.iterations = iteration + 1
                changed = False
                # Jacobi rounds: results never depend on the input mapping's insertion order.
                updates = {}
                globals_updates = {}
                module_updates = {}
                for name, module in sorted(self.modules.items()):
                    context = _Context(self, module)
                    context.block(module.tree.body)
                    globals_updates[name] = context.env
                    module_updates[name] = self.merge_summary(
                        self.module_summaries.get(name, _Summary()), context.summary
                    )
                    if module.globals != context.env or self.module_summaries.get(name) != module_updates[name]:
                        changed = True
                for name, function in sorted(self.functions.items()):
                    context = _Context(self, function.module, function)
                    context.block(function.node.body)
                    updates[name] = self.merge_summary(self.summaries[name], context.summary)
                    changed |= updates[name] != self.summaries[name]
                self.summaries.update(updates)
                self.module_summaries.update(module_updates)
                for name, env in globals_updates.items():
                    self.modules[name].globals = env
                if not changed:
                    self.coverage.converged = True
                    break
            else:
                self.issue("iteration_limit")
        except (_BudgetExceeded, RecursionError) as exc:
            if isinstance(exc, RecursionError):
                self.issue("recursion_limit")
        findings = self.findings()
        self.coverage.issues = [
            {"reason": reason, "path": path, "line": line, "detail": detail}
            for reason, path, line, detail in sorted(self._issues)
        ]
        return TaintResult(findings, self.coverage)

    def findings(self) -> list[ThreatFinding]:
        sites: dict[_Site, _Value] = {}
        for summary in [*self.summaries.values(), *self.module_summaries.values()]:
            for site, flows in summary.sinks.items():
                concrete = tuple(f for f in flows if f.origin.kind != "parameter" and site.kind not in f.safe)
                if concrete:
                    sites[site] = self.value(sites.get(site, ()), concrete)
        if len(sites) > self.limits.max_findings:
            self.issue("finding_limit")
        result = []
        for site in sorted(sites)[: self.limits.max_findings]:
            flow = sites[site][0]
            trace = self.step((flow,), _Step(site.path, site.line, f"sink {site.name} ({site.kind})"))[0].trace
            files = sorted({s.path for s in trace} | {site.path, flow.origin.path})
            digest = hashlib.sha256(f"{site.path}:{site.line}:{site.kind}:{site.name}".encode()).hexdigest()[:20]
            result.append(
                ThreatFinding(
                    finding_id=f"TAINT-PY-{digest}",
                    cwe=_CWES[site.kind],
                    severity=Severity.HIGH,
                    summary=f"Potential {site.kind} injection: untrusted {flow.origin.kind} input reaches {site.name} at {site.path}:{site.line}",
                    affected_nodes=files[:100],
                    evidence=[s.text() for s in trace][:50],
                )
            )
        return result


class _Context:
    def __init__(self, analyzer: _Analyzer, module: _Module, function: _Function | None = None) -> None:
        self.a, self.module, self.function = analyzer, module, function
        self.env = dict(module.globals) if function else {}
        self.aliases = dict(module.aliases)
        self.summary = _Summary()
        self.request_names = {"request"}
        if function:
            for param in function.params:
                origin = _Origin("parameter", function.name, param)
                self.env[param] = (_Flow(origin, frozenset(), ()),)
                self.aliases.pop(param, None)
            for arg in (*function.node.args.posonlyargs, *function.node.args.args, *function.node.args.kwonlyargs):
                annotation = _dotted(arg.annotation)
                if annotation.rsplit(".", 1)[-1] in {"Request", "HttpRequest"}:
                    self.request_names.add(arg.arg)

    def step(self, node: ast.AST, label: str) -> _Step:
        return _Step(self.module.path, getattr(node, "lineno", 1), label)

    def name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            if node.id in self.aliases:
                return self.a.resolve(self.aliases[node.id])
            if node.id in self.env and node.id not in self.request_names:
                return f"<value>.{node.id}"
            local = f"{self.module.name}.{node.id}"
            return local if local in self.a.functions else node.id
        if isinstance(node, ast.Attribute):
            return f"{self.name(node.value)}.{node.attr}"
        return ""

    def source(self, node: ast.AST, kind: str, label: str) -> _Value:
        step = self.step(node, f"source {label}")
        return (_Flow(_Origin(kind, "", label, step.path, step.line), frozenset(), (step,)),)

    def request_source(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Attribute):
            return False
        root = self.name(node.value)
        # A request parameter is recognized by conventional name, not arbitrary `.args` objects.
        return (root in _SOURCE_ROOTS or root in self.request_names) and node.attr in _REQUEST_FIELDS

    def bind(self, target: ast.AST, value: _Value) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = self.a.step(value, self.step(target, f"assign {target.id}"))
            self.aliases.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.bind(item, value)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            self.a.issue("heap_write", self.module.path, target.lineno)
            root = target.value
            if isinstance(root, ast.Name):
                self.env[root.id] = self.a.value(self.env.get(root.id, ()), value)

    def block(self, statements: list[ast.stmt]) -> None:
        for node in statements:
            self.a.tick()
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.a._aliases(self.module, [node], self.aliases)
            elif isinstance(node, ast.Assign):
                value = self.expr(node.value)
                alias = self.name(node.value) if isinstance(node.value, (ast.Name, ast.Attribute)) else ""
                for target in node.targets:
                    self.bind(target, value)
                    if (
                        isinstance(target, ast.Name)
                        and alias
                        and (
                            alias in self.a.functions
                            or alias in _SOURCE_ROOTS
                            or alias in self.request_names
                            or (isinstance(node.value, ast.Name) and node.value.id in self.aliases)
                        )
                    ):
                        self.aliases[target.id] = alias
            elif isinstance(node, ast.AnnAssign):
                self.bind(node.target, self.expr(node.value))
            elif isinstance(node, ast.AugAssign):
                self.bind(node.target, self.a.value(self.expr(node.target), self.expr(node.value)))
            elif isinstance(node, ast.Expr):
                self.expr(node.value)
            elif isinstance(node, ast.Return):
                self.summary.returns = self.a.value(
                    self.summary.returns, self.a.step(self.expr(node.value), self.step(node, "return"))
                )
            elif isinstance(node, ast.If):
                self.expr(node.test)
                self.branches([node.body, node.orelse])
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                self.a.issue("loop_approximation", self.module.path, node.lineno, "one body pass joined with entry")
                if isinstance(node, (ast.For, ast.AsyncFor)):
                    self.bind(node.target, self.expr(node.iter))
                else:
                    self.expr(node.test)
                self.branches([node.body, []])
                self.block(node.orelse)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    value = self.expr(item.context_expr)
                    if item.optional_vars:
                        self.bind(item.optional_vars, value)
                self.block(node.body)
            elif isinstance(node, (ast.Try, ast.TryStar)):
                self.branches([node.body, *(h.body for h in node.handlers)])
                self.block(node.orelse)
                self.block(node.finalbody)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in (*node.args.defaults, *node.args.kw_defaults):
                    self.expr(default)
            elif isinstance(node, (ast.Pass, ast.Break, ast.Continue)):
                pass
            elif isinstance(node, ast.Raise):
                # Exception paths are outside the may-flow model by design;
                # the raised expressions are still evaluated, and skipping
                # the raise itself cannot erase taint on the normal path.
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.expr):
                        self.expr(child)
            else:
                self.a.issue("unsupported_statement", self.module.path, node.lineno, type(node).__name__)
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.expr):
                        self.expr(child)

    def branches(self, blocks: list[list[ast.stmt]]) -> None:
        before, aliases = dict(self.env), dict(self.aliases)
        states, names = [], []
        for block in blocks:
            self.env, self.aliases = dict(before), dict(aliases)
            self.block(block)
            states.append(self.env)
            names.append(self.aliases)
        self.env = {
            name: self.a.value(*(state.get(name, ()) for state in states)) for name in sorted(set().union(*states))
        }
        self.aliases = {name: target for name, target in aliases.items() if all(n.get(name) == target for n in names)}
        if any(n != names[0] for n in names[1:]):
            self.a.issue("conditional_alias", self.module.path)

    def expr(self, node: ast.AST | None) -> _Value:
        if node is None:
            return ()
        self.a.tick()
        if isinstance(node, ast.Constant):
            return ()
        if isinstance(node, ast.Name):
            full = self.name(node)
            if full in {"sys.argv", "os.environ", "sys.stdin"}:
                kind = {"sys.argv": "cli", "os.environ": "environment", "sys.stdin": "stdin"}[full]
                return self.source(node, kind, full)
            if node.id in self.env:
                return self.env[node.id]
            full = self.name(node)
            owner, _, variable = full.rpartition(".")
            return self.a.modules[owner].globals.get(variable, ()) if owner in self.a.modules else ()
        if isinstance(node, ast.Attribute):
            if self.request_source(node):
                return self.source(node, "http", self.name(node))
            full = self.name(node)
            if full in {"sys.argv", "os.environ", "sys.stdin"}:
                kind = {"sys.argv": "cli", "os.environ": "environment", "sys.stdin": "stdin"}[full]
                return self.source(node, kind, full)
            owner, _, variable = full.rpartition(".")
            if owner in self.a.modules and variable in self.a.modules[owner].globals:
                return self.a.modules[owner].globals[variable]
            return self.expr(node.value)
        if isinstance(node, ast.Call):
            return self.call(node)
        if isinstance(node, ast.NamedExpr):
            value = self.expr(node.value)
            self.bind(node.target, value)
            return value
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            before = dict(self.env)
            for generator in node.generators:
                self.bind(generator.target, self.expr(generator.iter))
                for condition in generator.ifs:
                    self.expr(condition)
            value = (
                self.a.value(self.expr(node.key), self.expr(node.value))
                if isinstance(node, ast.DictComp)
                else self.expr(node.elt)
            )
            self.env = before
            return value
        if isinstance(node, ast.Subscript):
            # Index taint alone does not taint a constant lookup result.
            self.expr(node.slice)
            return self.safety(self.expr(node.value), unsafe=_KINDS)
        if isinstance(node, ast.IfExp):
            self.expr(node.test)
            return self.a.value(self.expr(node.body), self.expr(node.orelse))
        if isinstance(node, ast.FormattedValue):
            value = self.a.value(self.expr(node.value), self.expr(node.format_spec))
            if node.conversion != -1 or node.format_spec is not None:
                return self.safety(value, unsafe=_KINDS)
            return value
        if isinstance(node, (ast.Compare, ast.UnaryOp)):
            value = self.a.value(
                *(self.expr(child) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr))
            )
            return value
        if isinstance(
            node,
            (
                ast.BinOp,
                ast.BoolOp,
                ast.JoinedStr,
                ast.FormattedValue,
                ast.List,
                ast.Tuple,
                ast.Set,
                ast.Dict,
                ast.Await,
                ast.Starred,
                ast.Slice,
            ),
        ):
            value = self.a.value(
                *(self.expr(child) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr))
            )
            return self.composition(node, value) if isinstance(node, (ast.BinOp, ast.JoinedStr)) else value
        self.a.issue("unsupported_expression", self.module.path, getattr(node, "lineno", 0), type(node).__name__)
        return ()

    def sink(self, node: ast.Call, kind: str, name: str, value: _Value) -> None:
        site = _Site(self.module.path, node.lineno, kind, name)
        value = tuple(f for f in value if kind not in f.safe)
        if value:
            self.summary.sinks[site] = self.a.value(self.summary.sinks.get(site, ()), value)

    def safety(
        self, value: _Value, *, safe: frozenset[str] = frozenset(), unsafe: frozenset[str] = frozenset()
    ) -> _Value:
        result = []
        for flow in value:
            flags = set(flow.safe)
            for kind in safe:
                flags.discard("!" + kind)
                flags.add(kind)
            for kind in unsafe:
                flags.discard(kind)
                flags.add("!" + kind)
            result.append(_Flow(flow.origin, frozenset(flags), flow.trace))
        return self.a.value(tuple(result))

    def composition(self, node: ast.AST, value: _Value) -> _Value:
        # Shell-word quoting is not valid inside caller-supplied quotes. Unknown
        # untainted fragments are also not assumed to be safe shell scaffolding.
        expressions = [c for c in ast.iter_child_nodes(node) if isinstance(c, ast.expr)]
        risky = (
            any(
                isinstance(c, ast.Constant) and isinstance(c.value, str) and any(ch in c.value for ch in "'\"\\\\")
                for c in expressions
            )
            or sum(not isinstance(c, ast.Constant) for c in expressions) > 1
        )
        if risky:
            return self.safety(value, unsafe=frozenset({"shell"}))
        return value

    def substitute(self, flows: _Value, function: _Function, bound: dict[str, _Value], node: ast.Call) -> _Value:
        result: _Value = ()
        for flow in flows:
            if flow.origin.kind == "parameter" and flow.origin.owner == function.name:
                actual = bound.get(flow.origin.name, ())
                mapped = self.a.step(actual, self.step(node, f"call {function.name} parameter {flow.origin.name}"))
                for step in flow.trace:
                    mapped = self.a.step(mapped, step)
                mapped = self.safety(
                    mapped,
                    safe=flow.safe & _KINDS,
                    unsafe=frozenset(kind for kind in _KINDS if "!" + kind in flow.safe),
                )
            else:
                mapped = self.a.step((flow,), self.step(node, f"call {function.name}"))
            result = self.a.value(result, mapped)
        return result

    def call(self, node: ast.Call) -> _Value:
        name = self.a.resolve(self.name(node.func))
        args = [self.expr(arg) for arg in node.args]
        keywords = {kw.arg: self.expr(kw.value) for kw in node.keywords}
        receiver = self.expr(node.func.value) if isinstance(node.func, ast.Attribute) else ()
        combined = self.a.value(receiver, *args, *keywords.values())
        first = args[0] if args else ()
        leaf = name.rsplit(".", 1)[-1]
        if name in {"input", "builtins.input"}:
            return self.source(node, "stdin", name)
        if name in {"os.getenv", "os.environ.get"}:
            return self.source(node, "environment", name)
        request_root = name.rpartition(".")[0]
        if (request_root in _SOURCE_ROOTS or request_root in self.request_names) and leaf in {
            "get_json",
            "get_data",
            "json",
            "body",
        }:
            return self.source(node, "http", name)
        if name in self.a.functions:
            function = self.a.functions[name]
            bound = dict(zip(function.params, args))
            bound.update({key: value for key, value in keywords.items() if key is not None})
            params = [p.arg for p in (*function.node.args.posonlyargs, *function.node.args.args)]
            for param, default in zip(
                params[len(params) - len(function.node.args.defaults) :], function.node.args.defaults
            ):
                if param not in bound:
                    # Defaults belong to the callee module, not to the caller's name scope.
                    bound[param] = _Context(self.a, function.module).expr(default)
            for kw_param, kw_default in zip(function.node.args.kwonlyargs, function.node.args.kw_defaults):
                if kw_param.arg not in bound and kw_default is not None:
                    bound[kw_param.arg] = _Context(self.a, function.module).expr(kw_default)
            if any(isinstance(arg, ast.Starred) for arg in node.args) or None in keywords:
                self.a.issue("expanded_arguments", self.module.path, node.lineno)
                for param in function.params:
                    bound[param] = self.a.value(bound.get(param, ()), combined)
            if function.node.args.vararg or function.node.args.kwarg:
                self.a.issue("variadic_arguments", self.module.path, node.lineno)
                for variadic in (function.node.args.vararg, function.node.args.kwarg):
                    if variadic:
                        bound[variadic.arg] = combined
            summary = self.a.summaries[name]
            for site, flows in summary.sinks.items():
                self.summary.sinks[site] = self.a.value(
                    self.summary.sinks.get(site, ()),
                    self.substitute(flows, function, bound, node),
                )
            return self.substitute(summary.returns, function, bound, node)
        if name in {"int", "float", "builtins.int", "builtins.float"}:
            return self.safety(combined, safe=_KINDS - {"path"})
        if name == "shlex.quote":
            return self.safety(first, safe=frozenset({"shell"}))
        if name in {"eval", "exec", "builtins.eval", "builtins.exec", "compile", "builtins.compile"}:
            self.sink(node, "eval", name, first or keywords.get("source", ()))
            return combined
        if name in _SHELL:
            self.sink(node, "shell", name, first or keywords.get("command", keywords.get("cmd", ())))
            return combined
        if name in _PROCESS:
            shell_node = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
            if shell_node is not None and not (isinstance(shell_node, ast.Constant) and shell_node.value is False):
                self.sink(node, "shell", name, first or keywords.get("args", ()))
            return combined
        if name in _PATH or (
            leaf in {"open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink", "iterdir"}
        ):
            self.sink(
                node,
                "path",
                name,
                (first or keywords.get("file", keywords.get("path", ()))) if name in _PATH else receiver,
            )
            return combined
        if leaf in {"execute", "executemany", "executescript", "raw"}:
            self.sink(
                node,
                "sql",
                name,
                first
                or keywords.get(
                    "query", keywords.get("sql", keywords.get("operation", keywords.get("sql_script", ())))
                ),
            )
            return combined
        if leaf in {"replace", "strip", "lstrip", "rstrip", "split", "encode", "decode"}:
            return self.safety(combined, unsafe=_KINDS)
        if name in {"str", "bytes"} and (len(args) > 1 or keywords):
            return self.safety(combined, unsafe=_KINDS)
        if leaf in {"format", "join"}:
            if name == "format" and len(args) > 1:
                return self.safety(combined, unsafe=_KINDS)
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Constant):
                template = node.func.value.value
                if leaf == "format" and isinstance(template, str) and any(ch in template for ch in ":!"):
                    return self.safety(combined, unsafe=_KINDS)
            if isinstance(node.func, ast.Attribute) and not isinstance(node.func.value, ast.Constant):
                return self.safety(combined, unsafe=frozenset({"shell"}))
            return self.composition(node.func, combined)
        if name in _PURE - {"str", "pathlib.Path", "Path"}:
            return self.safety(combined, unsafe=_KINDS)
        if name in _PURE or leaf in {
            "get",
            "encode",
            "decode",
            "lower",
            "upper",
            "read",
            "readline",
            "resolve",
            "absolute",
        }:
            return combined
        self.a.issue("unresolved_call", self.module.path, node.lineno, name or "dynamic call")
        # Unknown transforms must not silently erase taint; they can still hide sinks or sources.
        return self.safety(combined, unsafe=_KINDS)


def analyze_taint(sources: Mapping[str, str], *, limits: TaintLimits | None = None) -> TaintResult:
    """Analyze supplied repo-relative source texts without filesystem or network access.

    Python files run the full may-flow model. JavaScript/TypeScript files run
    the bounded JS subset analyzer (``engine.services.taint_js``); every
    analyzed JS file records a ``js_subset`` approximation note because
    constructs outside the subset can hide flows. Other files are counted as
    unsupported, not as failed analysis. Bounds, parse errors and skipped
    semantics make coverage incomplete; conservative over-approximations are
    notes and do not fail coverage. Findings remain useful when coverage is
    incomplete; no findings never means safe.
    """
    js_exts = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
    py_sources: dict[str, str] = {}
    js_sources: dict[str, str] = {}
    go_sources: dict[str, str] = {}
    remainder: dict[str, str] = {}
    for path, content in sources.items():
        suffix = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if f".{suffix}" in js_exts:
            js_sources[path] = content
        elif path.endswith(".go"):
            go_sources[path] = content
        elif path.endswith(".py"):
            py_sources[path] = content
        else:
            remainder[path] = content

    # The Python analyzer sees Python files plus the remainder so unsupported
    # accounting stays truthful; JS/Go files are not "unsupported Python".
    result = _Analyzer({**py_sources, **remainder}, limits or TaintLimits()).run()

    for subset_sources, analyzer in ((js_sources, "js"), (go_sources, "go")):
        if not subset_sources:
            continue
        if analyzer == "js":
            from engine.services.taint_js import analyze_js_taint as analyze_subset
        else:
            from engine.services.taint_go import analyze_go_taint as analyze_subset
        subset = analyze_subset(subset_sources)
        result.findings.extend(subset.findings)
        coverage = result.coverage
        coverage.supported_files += len(subset.analyzed_paths)
        coverage.analyzed_files += len(subset.analyzed_paths)
        coverage.analyzed_paths = sorted([*coverage.analyzed_paths, *subset.analyzed_paths])
        coverage.skipped_paths = sorted([*coverage.skipped_paths, *subset.skipped_paths])
        coverage.issues = sorted(
            [*coverage.issues, *subset.notes],
            key=lambda item: (str(item.get("path", "")), str(item.get("reason", ""))),
        )
        result.coverage = coverage
    return result
