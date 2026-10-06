"""Federated topology — one organism, many repositories.

Builds a per-repo TopologyMapper for every repository in the fleet, then
stitches them into a single organization-wide graph by resolving real import
relationships across repository boundaries:

* Python ``from authlib.tokens import sign_token`` resolves when ``authlib``
  is a package/module published by another fleet repository.
* JS ``require('<package>/sub')`` / ``import … from '<package>/x'`` resolves
  against each fleet repository's ``package.json`` name.

The result is a unified graph in which a blast-radius trace legitimately
crosses repository borders: a sink in repo-A is provably reachable from a
public route in repo-B. Unresolvable imports produce no edges — precision
over recall, always.
"""

from __future__ import annotations

import ast
import json
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from engine.immune.detection import DetectionFinding
from engine.immune.topology import TopologyMapper

MAX_FLEET_NODES = 4000
MAX_FLEET_EDGES = 12000

_JS_REQUIRE = re.compile(r"""(?:require\(\s*|from\s+)[\"']([^\"' ]+)[\"']""")
_PKG_KEYWORDS = frozenset({"require", "exports", "module"})


@dataclass(frozen=True)
class FleetRepo:
    name: str
    path: Path
    mapper: TopologyMapper


@dataclass
class FleetRadius:
    """Blast radius in the federated graph, tagged per repository."""

    finding: DetectionFinding
    origin_repo: str
    sink_node: str | None = None
    proven: bool = False
    chains: list[list[dict]] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    affected_repos: list[str] = field(default_factory=list)
    downstream: list[str] = field(default_factory=list)
    verdict: str = ""

    def summary(self) -> dict[str, object]:
        return {
            "finding": f"{self.finding.rule_id} @ {self.origin_repo}/{self.finding.file}:{self.finding.line}",
            "proven": self.proven,
            "verdict": self.verdict,
            "entrypoints": self.entrypoints,
            "affected_repos": self.affected_repos,
            "cross_repo": len(self.affected_repos) > 1,
            "chains": self.chains,
        }


class FleetTopology:
    """The organization-wide topological map."""

    def __init__(self, repos: dict[str, dict[str, str]]) -> None:
        self.repos: dict[str, FleetRepo] = {}
        self._funcs: dict[str, dict] = {}      # prefixed node id → hop-like record
        self._forward: dict[str, set[str]] = {}
        self._reverse: dict[str, set[str]] = {}
        self.cross_edges: list[tuple[str, str]] = []
        self.truncated = 0
        self._build(repos)

    # -- construction ---------------------------------------------------------
    def _build(self, repos: dict[str, dict[str, str]]) -> None:
        for name, sources in sorted(repos.items()):
            mapper = TopologyMapper(sources)
            self.repos[name] = FleetRepo(name=name, path=Path(name), mapper=mapper)
            for fn in mapper._funcs.values():
                prefixed = self._prefix(name, fn.node_id)
                self._funcs[prefixed] = {
                    "node": prefixed, "repo": name, "file": fn.file, "line": fn.line,
                    "name": fn.signature, "route": fn.route_path or None,
                    "is_route": fn.is_route, "fn_name": fn.name,
                }
                if len(self._funcs) >= MAX_FLEET_NODES:
                    self.truncated += 1
            for src, dst in mapper._edges:
                self._link(self._prefix(name, src), self._prefix(name, dst))
        self._link_python_packages()
        self._link_js_packages()

    @staticmethod
    def _prefix(repo: str, node_id: str) -> str:
        return f"{repo}:{node_id}"

    def _link(self, src: str, dst: str) -> bool:
        if src == dst or src not in self._funcs or dst not in self._funcs:
            return False
        if dst in self._forward.setdefault(src, set()):
            return False
        if sum(len(v) for v in self._forward.values()) >= MAX_FLEET_EDGES:
            self.truncated += 1
            return False
        self._forward[src].add(dst)
        self._reverse.setdefault(dst, set()).add(src)
        return True

    # -- python cross-repo linkage ---------------------------------------------
    def _python_module_table(self) -> dict[str, list[tuple[str, str]]]:
        """top-level importable name → [(repo, rel_file)] across the fleet."""
        table: dict[str, list[tuple[str, str]]] = {}
        for repo in sorted(self.repos):
            sources = self.repos[repo].mapper._sources
            for rel in sources:
                if rel.endswith(".py") and "/" not in rel:
                    table.setdefault(rel[:-3], []).append((repo, rel))
                if rel.endswith("/__init__.py") and rel.count("/") == 1:
                    table.setdefault(rel.split("/")[0], []).append((repo, rel))
        return table

    def _resolve_py_module(self, parts: list[str]) -> tuple[str, str] | None:
        """Resolve dotted module path to (repo, rel_file) in another repo."""
        table = self._table
        if not parts:
            return None
        for depth in range(len(parts), 0, -1):
            name = "/".join(parts[:depth])
            for repo, base in table.get(name, []):
                rest = parts[depth:]
                if not rest:
                    return repo, base
                candidate = "/".join([name, *rest]) + ".py"
                if candidate in self.repos[repo].mapper._sources:
                    return repo, candidate
                candidate = "/".join([name, *rest]) + "/__init__.py"
                if candidate in self.repos[repo].mapper._sources:
                    return repo, candidate
        return None

    def _link_python_packages(self) -> None:
        self._table = self._python_module_table()
        for repo in sorted(self.repos):
            mapper = self.repos[repo].mapper
            for rel in sorted(mapper._sources):
                if not rel.endswith(".py"):
                    continue
                self._link_python_file(repo, rel)

    def _link_python_file(self, repo: str, rel: str) -> None:
        mapper = self.repos[repo].mapper
        content = mapper._sources[rel]
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return
        file_funcs = [f for f in mapper._funcs.values() if f.file == rel]
        if not file_funcs:
            return
        bindings: dict[str, tuple[str, str, str]] = {}  # local name → (repo, file, fn_name|"")

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                resolved = self._resolve_py_module(node.module.split("."))
                if resolved and resolved[0] != repo:
                    target_repo, target_file = resolved
                    for alias in node.names:
                        fn_name = alias.asname or alias.name
                        bindings[alias.asname or alias.name] = (target_repo, target_file, alias.name)
                        self._try_edge(repo, rel, fn_name, target_repo, target_file, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    resolved = self._resolve_py_module(alias.name.split("."))
                    if resolved and resolved[0] != repo:
                        local = alias.asname or alias.name.split(".")[0]
                        bindings[local] = (resolved[0], resolved[1], "")

        if not bindings:
            return

        class _CallVisitor(ast.NodeVisitor):
            """Resolve call sites through fleet import bindings; owner via line span."""

            def __init__(inner, fleet: FleetTopology, host_repo: str):
                inner.fleet = fleet
                inner.host_repo = host_repo

            def _owner(self, lineno: int) -> dict | None:
                spans = [f for f in file_funcs if f.line <= lineno <= f.end_line]
                return min(spans, key=lambda f: f.end_line - f.line, default=None)

            def _edge_to_fn(self, caller, target_repo: str, target_file: str, fn_name: str) -> None:
                """caller is a topology _Func from the host repo's mapper."""
                self.fleet._try_edge(
                    self.host_repo, caller.file, caller.name,
                    target_repo, target_file, fn_name,
                    caller_prefixed=self.fleet._prefix(self.host_repo, caller.node_id),
                )

            def visit_Call(self, node: ast.Call) -> None:
                owner = self._owner(node.lineno)
                if owner is not None:
                    if isinstance(node.func, ast.Name):
                        binding = bindings.get(node.func.id)
                        if binding and binding[2]:
                            self._edge_to_fn(owner, binding[0], binding[1], binding[2])
                    elif isinstance(node.func, ast.Attribute):
                        base = node.func.value
                        if isinstance(base, ast.Name):
                            binding = bindings.get(base.id)
                            if binding and not binding[2]:
                                self._edge_to_fn(owner, binding[0], binding[1], node.func.attr)
                self.generic_visit(node)

        _CallVisitor(self, repo).visit(tree)

    def _try_edge(
        self, src_repo: str, src_file: str, src_fn: str,
        dst_repo: str, dst_file: str, dst_fn: str,
        caller_prefixed: str | None = None,
    ) -> bool:
        dst_candidates = [
            self._prefix(dst_repo, f.node_id)
            for f in self.repos[dst_repo].mapper._funcs.values()
            if f.file == dst_file and f.name == dst_fn
        ]
        if not dst_candidates:
            return False
        if caller_prefixed is not None:
            src = caller_prefixed
        else:
            srcs = [
                self._prefix(src_repo, f.node_id)
                for f in self.repos[src_repo].mapper._funcs.values()
                if f.file == src_file and f.name == src_fn
            ]
            if not srcs:
                return False
            src = srcs[0]
        linked = self._link(src, dst_candidates[0])
        if linked and not src.startswith(dst_repo + ":"):
            self.cross_edges.append((src, dst_candidates[0]))
        return linked

    # -- js cross-repo linkage ---------------------------------------------------
    def _js_package_names(self) -> dict[str, str]:
        """package.json name → repo, per fleet repository."""
        names: dict[str, str] = {}
        for repo in sorted(self.repos):
            raw = self.repos[repo].mapper._sources.get("package.json")
            if not raw:
                continue
            try:
                name = json.loads(raw).get("name")
            except json.JSONDecodeError:
                continue
            if isinstance(name, str) and name:
                names[name] = repo
        return names

    def _link_js_packages(self) -> None:
        pkg_names = self._js_package_names()
        if not pkg_names:
            return
        for repo in sorted(self.repos):
            mapper = self.repos[repo].mapper
            for rel, content in sorted(mapper._sources.items()):
                if rel.rsplit(".", 1)[-1].lower() not in {"js", "jsx", "ts", "tsx"}:
                    continue
                for line_no, line in enumerate(content.splitlines(), 1):
                    m = _JS_REQUIRE.search(line)
                    if not m:
                        continue
                    spec = m.group(1)
                    if spec.startswith((".", "/")):
                        continue
                    pkg = spec.split("/")[0]
                    if pkg.startswith("@"):
                        parts = spec.split("/")
                        pkg = "/".join(parts[:2]) if len(parts) >= 2 else pkg
                    target_repo = pkg_names.get(pkg)
                    if not target_repo or target_repo == repo:
                        continue
                    sub = spec[len(pkg):].lstrip("/")
                    target_file = self._resolve_js_file(self.repos[target_repo].mapper._sources, sub)
                    if not target_file:
                        continue
                    owner = next(
                        (f for f in mapper._funcs.values()
                         if f.file == rel and not f.is_route and f.line <= line_no <= f.end_line),
                        None,
                    )
                    if owner is None:
                        continue
                    targets = [f for f in self.repos[target_repo].mapper._funcs.values()
                               if f.file == target_file and not f.is_route]
                    if targets:
                        self._try_edge(
                            repo, owner.file, owner.name, target_repo, target_file,
                            targets[0].name, caller_prefixed=self._prefix(repo, owner.node_id),
                        )

    @staticmethod
    def _resolve_js_file(sources: dict[str, str], sub: str) -> str | None:
        if not sub:
            index = "index.js"
            return index if index in sources else None
        base = re.sub(r"\.(js|ts|jsx|tsx)$", "", sub)
        for candidate in (f"{base}.js", f"{base}.ts", f"{base}/index.js", sub):
            if candidate in sources:
                return candidate
        return None

    # -- federated tracing ---------------------------------------------------------
    def _find_sink(self, repo: str, finding: DetectionFinding) -> str | None:
        mapper = self.repos[repo].mapper
        spans = [f for f in mapper._funcs.values()
                 if f.file == finding.file and f.line <= finding.line <= f.end_line]
        if not spans:
            return None
        innermost = min(spans, key=lambda f: f.end_line - f.line)
        return self._prefix(repo, innermost.node_id)

    def trace(self, repo: str, finding: DetectionFinding) -> FleetRadius:
        radius = FleetRadius(finding=finding, origin_repo=repo)
        sink = self._find_sink(repo, finding)
        if sink is None:
            radius.verdict = "SINK AT MODULE SCOPE — no enclosing function to trace"
            return radius
        radius.sink_node = sink

        seen, parent, queue = {sink}, {sink: sink}, deque([sink])
        while queue:
            current = queue.popleft()
            for prev in self._reverse.get(current, ()):
                if prev not in seen:
                    seen.add(prev)
                    parent[prev] = current
                    queue.append(prev)

        entries = [n for n in seen if self._funcs[n]["is_route"]]
        radius.proven = bool(entries)
        radius.entrypoints = [
            f"[{self._funcs[n]['repo']}] {self._funcs[n]['route'] or self._funcs[n]['name']}"
            f" ({self._funcs[n]['file']}:{self._funcs[n]['line']})"
            for n in sorted(entries)
        ]

        if radius.proven:
            for entry in sorted(entries)[:3]:
                path, cursor = [entry], entry
                while cursor != sink:
                    cursor = min(self._forward.get(cursor, ()), key=lambda n: len(self._path_to(n, sink)), default=None)
                    if cursor is None or cursor in path:
                        path = []
                        break
                    path.append(cursor)
                if path and path[-1] == sink and len(path) <= 8:
                    radius.chains.append([dict(self._funcs[n]) for n in path])

        downstream, queue, visited = [], deque([sink]), {sink}
        while queue and len(downstream) < 50:
            current = queue.popleft()
            for nxt in self._forward.get(current, ()):
                if nxt not in visited:
                    visited.add(nxt)
                    downstream.append(nxt)
                    queue.append(nxt)
        radius.downstream = downstream

        touched = {self._funcs[n]["repo"] for n in seen}
        radius.affected_repos = sorted(touched)
        if radius.proven:
            cross = len(radius.affected_repos) > 1
            radius.verdict = (
                f"EXPLOITABILITY PROVEN — {len(radius.chains)} attack chain(s)"
                + (f" spanning {len(radius.affected_repos)} repositories" if cross else
                   " from public API boundary")
            )
        else:
            radius.verdict = "ISOLATED SINK — no public entry reaches it in the federated graph"
        return radius

    def _path_to(self, src: str, dst: str) -> list[str]:
        parent, queue = {src: src}, deque([src])
        while queue:
            current = queue.popleft()
            if current == dst:
                break
            for nxt in self._forward.get(current, ()):
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
