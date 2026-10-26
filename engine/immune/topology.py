"""Topological blast-radius mapping.

Builds a real call/entry-point graph from source (Python via `ast`, JS/TS via
bounded extraction), wraps it in an ArchitectureGraphContext, and traces the
exact attack chain from a public API boundary down to a detected sink —
proving exploitability topologically instead of asserting it.

Honest limits: dynamic dispatch, reflection, and framework-mediated indirection
are invisible to static analysis; unresolved calls simply produce no edge.
"""

from __future__ import annotations

import ast
import re
from collections import deque
from dataclasses import dataclass, field

from engine.agents.architect_agent import ArchitectureEdge, ArchitectureGraphContext, ArchitectureNode
from engine.immune.detection import DetectionFinding

MAX_NODES = 600
MAX_EDGES = 2000
MAX_CHAINS = 3
MAX_CHAIN_HOPS = 8
MAX_DOWNSTREAM = 50

_ROUTE_DECORATOR = re.compile(
    r"(?:app|bp|api|router)\.(?:route|get|post|put|delete|patch)\b|api_view|add_api_route",
)
_ROUTE_PATH = re.compile(r"[\"']([^\"']+)[\"']")

_JS_FUNC = re.compile(r"(?m)^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(\w+)\s*\(")
_JS_ARROW = re.compile(r"(?m)^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>")
_JS_ROUTE = re.compile(r"\b(?:app|router|server)\.(get|post|put|delete|patch|all)\(\s*[\"']([^\"']+)[\"']\s*,\s*(\w+)?")
_JS_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
_JS_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "return", "function", "typeof",
    "await", "async", "new", "delete", "void", "in", "of", "do", "else", "try",
})

_PY_CALL_KEYWORDS = frozenset({"if", "for", "while", "with", "assert"})


@dataclass
class _Func:
    node_id: str
    name: str
    file: str
    line: int
    end_line: int
    signature: str
    is_route: bool = False
    route_path: str = ""
    lang: str = "py"


@dataclass
class BlastRadius:
    """The topological verdict for one detected sink."""

    finding: DetectionFinding
    sink_node: str | None
    proven: bool = False                # a public API boundary reaches the sink
    chains: list[list[dict]] = field(default_factory=list)   # entry → … → sink hops
    entrypoints: list[str] = field(default_factory=list)
    roots: list[str] = field(default_factory=list)           # callers with no caller
    downstream: list[str] = field(default_factory=list)      # callees transitively
    downstream_files: set[str] = field(default_factory=set)
    verdict: str = ""

    def summary(self) -> dict[str, object]:
        return {
            "finding": f"{self.finding.rule_id} @ {self.finding.file}:{self.finding.line}",
            "proven": self.proven,
            "verdict": self.verdict,
            "entrypoints": self.entrypoints,
            "chains": self.chains,
            "downstream_calls": len(self.downstream),
            "downstream_files": sorted(self.downstream_files),
        }


class TopologyMapper:
    """Static architecture graph + blast-radius tracer over one source tree."""

    def __init__(self, sources: dict[str, str]) -> None:
        self._sources = sources
        self._funcs: dict[str, _Func] = {}
        self._by_name: dict[str, list[_Func]] = {}
        self._edges: set[tuple[str, str]] = set()
        self._reverse: dict[str, set[str]] = {}
        self._forward: dict[str, set[str]] = {}
        self.truncated_nodes = 0
        self.truncated_edges = 0
        self.parse_errors: list[str] = []
        self._build()

    # -- graph construction --------------------------------------------------
    def _build(self) -> None:
        for rel, content in sorted(self._sources.items()):
            if rel.endswith(".py"):
                self._scan_python(rel, content)
            elif rel.rsplit(".", 1)[-1].lower() in {"js", "jsx", "ts", "tsx"}:
                self._scan_js(rel, content)
        self._resolve_cross_file_edges()

    def _add_func(self, fn: _Func) -> bool:
        if len(self._funcs) >= MAX_NODES:
            self.truncated_nodes += 1
            return False
        self._funcs[fn.node_id] = fn
        self._by_name.setdefault(fn.name, []).append(fn)
        return True

    def _scan_python(self, rel: str, content: str) -> None:
        try:
            tree = ast.parse(content)
        except SyntaxError as exc:
            self.parse_errors.append(f"{rel}: {exc.msg} (line {exc.lineno})")
            return

        class _DefVisitor(ast.NodeVisitor):
            def __init__(inner, mapper: "TopologyMapper"):
                inner.mapper = mapper
                inner.class_stack: list[str] = []

            def visit_ClassDef(inner, node: ast.ClassDef) -> None:
                inner.class_stack.append(node.name)
                inner.generic_visit(node)
                inner.class_stack.pop()

            def _visit_function(inner, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                qual = "::".join([*inner.class_stack, node.name])
                fn = _Func(
                    node_id=f"{rel}::{qual}", name=node.name, file=rel,
                    line=node.lineno, end_line=getattr(node, "end_lineno", node.lineno),
                    signature=f"{node.name}({', '.join(a.arg for a in node.args.args)})",
                    lang="py",
                )
                if hasattr(ast, "unparse"):
                    for dec in node.decorator_list:
                        dec_src = ast.unparse(dec)
                        if _ROUTE_DECORATOR.search(dec_src):
                            fn.is_route = True
                            pm = _ROUTE_PATH.search(dec_src)
                            fn.route_path = pm.group(1) if pm else ""
                inner.mapper._add_func(fn)
                inner.generic_visit(node)

            visit_FunctionDef = _visit_function
            visit_AsyncFunctionDef = _visit_function

        _DefVisitor(self).visit(tree)
        self._scan_python_calls(rel, content)

    def _scan_python_calls(self, rel: str, content: str) -> None:
        """Link intra-file CALLS edges, scope-correct for nested functions."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return
        file_funcs = [f for f in self._funcs.values() if f.file == rel]
        if not file_funcs:
            return

        class _CallVisitor(ast.NodeVisitor):
            def __init__(inner, mapper: "TopologyMapper"):
                inner.mapper = mapper
                inner.scope: list[_Func] = []

            def _link(self, callee: str) -> None:
                if not self.scope:
                    return
                caller = self.scope[-1]
                targets = [t for t in file_funcs if t.name == callee and t.node_id != caller.node_id]
                for target in targets[:2]:
                    self.mapper._add_edge(caller.node_id, target.node_id)

            def visit_Call(self, node: ast.Call) -> None:
                if isinstance(node.func, ast.Name):
                    self._link(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    self._link(node.func.attr)
                self.generic_visit(node)

            def _scoped(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                spans = [f for f in file_funcs
                         if f.name == node.name and f.line <= node.lineno <= f.end_line]
                fn = min(spans, key=lambda f: f.end_line - f.line, default=None)
                if fn is not None:
                    self.scope.append(fn)
                self.generic_visit(node)
                if fn is not None:
                    self.scope.pop()

            visit_FunctionDef = _scoped
            visit_AsyncFunctionDef = _scoped

        _CallVisitor(self).visit(tree)

    def _scan_js(self, rel: str, content: str) -> None:
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            m = _JS_FUNC.search(line) or _JS_ARROW.search(line)
            if m:
                name = m.group(1)
                self._add_func(_Func(
                    node_id=f"{rel}::{name}", name=name, file=rel, line=idx,
                    end_line=self._js_block_end(lines, idx), signature=f"{name}(…)", lang="js",
                ))
        for idx, line in enumerate(lines, 1):
            rm = _JS_ROUTE.search(line)
            if rm:
                route = _Func(
                    node_id=f"{rel}::route:{rm.group(2)}:{idx}", name=f"{rm.group(1).upper()} {rm.group(2)}",
                    file=rel, line=idx, end_line=idx, signature=f"{rm.group(1).upper()} {rm.group(2)}",
                    is_route=True, route_path=rm.group(2), lang="js",
                )
                self._add_func(route)
                handler = rm.group(3)
                if handler:
                    for target in self._by_name.get(handler, []):
                        self._add_edge(route.node_id, target.node_id)

        known = {f.name for f in self._funcs.values() if f.lang == "js" and not f.is_route}
        for idx, line in enumerate(lines, 1):
            owner = next((f for f in self._funcs.values()
                          if f.file == rel and not f.is_route and f.line <= idx <= f.end_line), None)
            if owner is None:
                continue
            for cm in _JS_CALL.finditer(line):
                callee = cm.group(1)
                if callee in _JS_KEYWORDS or callee == owner.name:
                    continue
                if callee in known:
                    for target in self._by_name.get(callee, []):
                        if target.node_id != owner.node_id:
                            self._add_edge(owner.node_id, target.node_id)
                            break

    @staticmethod
    def _js_block_end(lines: list[str], start: int, *, max_span: int = 80) -> int:
        """Bounded brace-span estimate so multi-line JS functions contain their sinks."""
        depth = 0
        seen_open = False
        for offset, line in enumerate(lines[start - 1:start - 1 + max_span], start):
            for ch in line:
                if ch == "{":
                    depth += 1
                    seen_open = True
                elif ch == "}":
                    depth -= 1
                    if seen_open and depth <= 0:
                        return offset
        return min(start + max_span, len(lines))

    def _add_edge(self, src: str, dst: str) -> None:
        if len(self._edges) >= MAX_EDGES:
            self.truncated_edges += 1
            return
        if (src, dst) in self._edges:
            return
        self._edges.add((src, dst))
        self._forward.setdefault(src, set()).add(dst)
        self._reverse.setdefault(dst, set()).add(src)

    def _resolve_cross_file_edges(self) -> None:
        """Python cross-file CALLS via `from module import name` convention."""
        for rel, content in sorted(self._sources.items()):
            if not rel.endswith(".py"):
                continue
            try:
                tree = ast.parse(content)
            except SyntaxError:
                continue
            file_funcs = [f for f in self._funcs.values() if f.file == rel]
            imported: dict[str, list[_Func]] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    mod_path = node.module.replace(".", "/")
                    for alias in node.names:
                        for candidate in (f"{mod_path}.py", f"{mod_path}/__init__.py"):
                            targets = [f for f in self._funcs.values()
                                       if f.file == candidate and f.name == (alias.asname or alias.name)]
                            if targets:
                                imported[alias.asname or alias.name] = targets
                            break
            if not imported:
                continue
            for caller in file_funcs:
                body = content.splitlines()[caller.line - 1:caller.end_line]
                for line_text in body:
                    for cm in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", line_text):
                        for target in imported.get(cm.group(1), [])[:1]:
                            self._add_edge(caller.node_id, target.node_id)

    # -- context export -------------------------------------------------------
    def build_context(self, project_id: str = "immune") -> ArchitectureGraphContext:
        nodes: list[ArchitectureNode] = []
        for fn in self._funcs.values():
            labels = ["Function"] if not fn.is_route else ["Function", "Route", "Entrypoint"]
            nodes.append(ArchitectureNode(
                id=fn.node_id,
                labels=labels,
                properties={
                    "file": fn.file, "line": fn.line, "end_line": fn.end_line,
                    "signature": fn.signature, **({"route": fn.route_path} if fn.route_path else {}),
                },
            ))
        edges = [ArchitectureEdge(source_id=s, target_id=d, relationship_type="CALLS", properties={})
                 for s, d in sorted(self._edges)]
        return ArchitectureGraphContext(project_id=project_id, nodes=nodes, edges=edges)

    # -- blast-radius tracing ---------------------------------------------------
    def _find_sink(self, finding: DetectionFinding) -> _Func | None:
        candidates = [f for f in self._funcs.values()
                      if f.file == finding.file and f.line <= finding.line <= f.end_line]
        candidates.sort(key=lambda f: (f.end_line - f.line, f.line))  # innermost first
        return candidates[0] if candidates else None

    def trace(self, finding: DetectionFinding) -> BlastRadius:
        radius = BlastRadius(finding=finding, sink_node=None)
        sink = self._find_sink(finding)
        if sink is None:
            radius.verdict = "SINK AT MODULE SCOPE — no enclosing function to trace"
            return radius
        radius.sink_node = sink.node_id

        ancestors, parent = self._reverse_bfs(sink.node_id)
        entries = [self._funcs[a] for a in ancestors if self._funcs[a].is_route]
        roots = [self._funcs[a] for a in ancestors
                 if a not in self._reverse and not self._funcs[a].is_route]

        radius.proven = bool(entries)
        radius.entrypoints = [f"{e.route_path or e.name} ({e.file}:{e.line})" for e in entries]
        radius.roots = [f"{r.signature} ({r.file}:{r.line})" for r in roots[:5]]

        if radius.proven:
            for entry in sorted(entries, key=lambda e: e.node_id)[:MAX_CHAINS]:
                chain = self._shortest_path(entry.node_id, sink.node_id, self._forward)
                if chain and len(chain) <= MAX_CHAIN_HOPS:
                    radius.chains.append([self._hop(self._funcs[n]) for n in chain])

        radius.downstream = self._downstream(sink.node_id)
        radius.downstream_files = {self._funcs[n].file for n in radius.downstream if n in self._funcs}

        if radius.proven:
            radius.verdict = (
                f"EXPLOITABILITY PROVEN — {len(radius.chains)} attack chain(s) from public API boundary"
            )
        elif roots:
            radius.verdict = f"ISOLATED SINK — reachable from {len(roots)} internal root(s), no public route found"
        else:
            radius.verdict = "ISOLATED SINK — no inbound call edge discovered"
        return radius

    def _hop(self, fn: _Func) -> dict[str, object]:
        return {
            "node": fn.node_id, "name": fn.signature, "file": fn.file,
            "line": fn.line, "route": fn.route_path or None,
        }

    def _reverse_bfs(self, start: str) -> tuple[set[str], dict[str, str]]:
        seen, parent, queue = {start}, {start: start}, deque([start])
        while queue:
            current = queue.popleft()
            for prev in self._reverse.get(current, ()):
                if prev not in seen:
                    seen.add(prev)
                    parent[prev] = current
                    queue.append(prev)
        return seen, parent

    def _shortest_path(self, src: str, dst: str, forward: dict[str, set[str]]) -> list[str]:
        parent, queue = {src: src}, deque([src])
        while queue:
            current = queue.popleft()
            if current == dst:
                break
            for nxt in forward.get(current, ()):
                if nxt not in parent:
                    parent[nxt] = current
                    queue.append(nxt)
        if dst not in parent:
            return []
        path, cursor = [dst], dst
        while cursor != src:
            cursor = parent[cursor]
            path.append(cursor)
        return list(reversed(path))

    def _downstream(self, start: str) -> list[str]:
        seen: list[str] = []
        queue = deque([start])
        visited = {start}
        while queue and len(seen) < MAX_DOWNSTREAM:
            current = queue.popleft()
            for nxt in self._forward.get(current, ()):
                if nxt not in visited:
                    visited.add(nxt)
                    seen.append(nxt)
                    queue.append(nxt)
        return seen[:MAX_DOWNSTREAM]
