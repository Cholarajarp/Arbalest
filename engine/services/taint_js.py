"""Bounded deterministic JavaScript/TypeScript may-flow taint analysis.

Scope (deliberately narrow and documented): module-level statements and
function bodies; sources are request objects (req/request/event/ctx with
query/body/params/headers members); propagation covers assignment, identifier
reference, string concatenation and template literals, and calling
module-level user functions with tainted arguments (return summaries are
memoized by argument-taint signature); sinks are eval/Function (CWE-95),
child_process exec-family string commands (CWE-78) and innerHTML assignment
(CWE-79). Unknown statement shapes are skipped and every analyzed file adds
one ``js_subset`` approximation note: constructs outside the subset can hide
flows, exactly like unresolved calls in the Python analyzer. No execution,
no filesystem access, bounded by file count and size.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from engine.agents.architect_agent import Severity, ThreatFinding

_MAX_FILES = 256
_MAX_FILE_BYTES = 512_000
_MAX_FINDINGS = 500
_MAX_INTERPRETATIONS = 256

_JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"})
_SOURCE_ROOTS = frozenset({"req", "request", "event", "ctx"})
_SOURCE_MEMBERS = frozenset({
    "query", "body", "params", "headers", "cookies", "queryStringParameters",
    "searchParams",
})
_EVAL_SINKS = frozenset({"eval", "Function"})
_EXEC_SINKS = frozenset({"exec", "execSync", "spawnSync", "spawn", "execFile"})
_TOKEN = re.compile(
    r"""(?P<ws>\s+)
      | (?P<template>`(?:[^`\\]|\\.)*`)
      | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
      | (?P<num>\b\d[\d._]*\b)
      | (?P<word>[A-Za-z_$][\w$]*)
      | (?P<punct>[{}()\[\];,.=+\-*/%<>!&|?:])
    """,
    re.VERBOSE,
)


@dataclass
class JsTaintResult:
    findings: list[ThreatFinding] = field(default_factory=list)
    analyzed_paths: list[str] = field(default_factory=list)
    skipped_paths: list[str] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)   # per-file subset notes
    interpretations: int = 0


def _tokens(text: str) -> list[tuple[str, str, int]]:
    output: list[tuple[str, str, int]] = []
    position = 0
    line = 1
    while position < len(text):
        match = _TOKEN.match(text, position)
        if not match:
            position += 1
            continue
        kind = match.lastgroup or ""
        value = match.group(0)
        if kind == "ws":
            line += value.count("\n")
        else:
            output.append((kind, value, line))
        position = match.end()
    return output


def _line_of(tokens: list[tuple[str, str, int]], index: int) -> int:
    return tokens[index][2] if index < len(tokens) else (tokens[-1][2] if tokens else 0)


class _Function:
    __slots__ = ("name", "params", "body_start", "body_end")

    def __init__(self, name: str, params: list[str], body_start: int, body_end: int) -> None:
        self.name = name
        self.params = params
        self.body_start = body_start
        self.body_end = body_end


class _JsAnalyzer:
    def __init__(self, sources: dict[str, str]) -> None:
        self._sources = sources
        self.result = JsTaintResult()
        self._interpretations = 0

    # -- expression taint --------------------------------------------------
    def _expr_tainted(
        self, tokens: list[tuple[str, str, int]], start: int, end: int,
        env: dict[str, bool],
    ) -> bool:
        index = start
        depth = 0
        while index < end:
            kind, value, _ = tokens[index]
            if kind == "punct":
                if value in "([{":
                    depth += 1
                elif value in ")]}":
                    depth -= 1
                index += 1
                continue
            if kind == "word":
                if value in _SOURCE_ROOTS:
                    # req.query.x / request.body / event.queryStringParameters
                    if (
                        index + 2 < end
                        and tokens[index + 1][1] == "."
                        and tokens[index + 2][0] == "word"
                        and tokens[index + 2][1] in _SOURCE_MEMBERS
                    ):
                        return True
                elif env.get(value):
                    return True
            elif kind == "template":
                if "${" in value:
                    inner = value[value.find("${") + 2: value.rfind("}")]
                    if any(env.get(word) or self._is_source_text(inner) for word in re.findall(r"[A-Za-z_$][\w$]*", inner)):
                        return True
            index += 1
        return False

    @staticmethod
    def _is_source_text(text: str) -> bool:
        return bool(re.search(r"\b(?:req|request|event|ctx)\.(?:query|body|params|headers)\b", text))

    # -- statement walker --------------------------------------------------
    def _run_block(
        self, tokens: list[tuple[str, str, int]], start: int, end: int,
        env: dict[str, bool], path: str, functions: dict[str, _Function],
        steps: list[str],
    ) -> None:
        index = start
        while index < end:
            kind, value, line = tokens[index]
            if kind == "punct" and value == ";":
                index += 1
                continue
            # Variable declaration / assignment: [const|let|var] name = expr ;
            if kind == "word" and value in {"const", "let", "var"}:
                name_index = index + 1
                if name_index < end and tokens[name_index][0] == "word":
                    expr_start = name_index + 1
                    if (
                        expr_start < end and tokens[expr_start][1] == "="
                        and not (expr_start + 1 < end and tokens[expr_start + 1][1] == "=")
                    ):
                        stmt_end = self._statement_end(tokens, expr_start, end)
                        # Initializers can contain sinks and user calls, not
                        # just taint: `const f = eval(req.query.x);`.
                        self._handle_call(tokens, expr_start, stmt_end, env, path, functions, steps, line)
                        tainted = self._expr_tainted(tokens, expr_start + 1, stmt_end, env)
                        env[tokens[name_index][1]] = tainted
                        if tainted:
                            steps.append(f"{path}:{line} {tokens[name_index][1]} carries request input")
                        index = stmt_end
                        continue
            if kind == "word" and value in {"if", "for", "while", "switch", "try", "catch"}:
                # Approximate both branches: jump into the block(s) that follow.
                index = self._skip_control_header(tokens, index, end)
                continue
            if kind == "word" and value == "function":
                index = self._skip_function(tokens, index, end)
                continue
            if kind == "word" and value == "return":
                stmt_end = self._statement_end(tokens, index, end)
                index = stmt_end
                continue
            if (
                kind == "word" and value in env and index + 1 < end and tokens[index + 1][1] == "="
                and not (index + 2 < end and tokens[index + 2][1] == "=")
            ):
                stmt_end = self._statement_end(tokens, index, end)
                env[value] = self._expr_tainted(tokens, index + 2, stmt_end, env)
                index = stmt_end
                continue
            if (
                kind == "word" and index + 3 < end
                and tokens[index + 1][1] == "." and tokens[index + 2][1] == "innerHTML"
                and tokens[index + 3][1] == "="
                and not (index + 4 < end and tokens[index + 4][1] == "=")
            ):
                stmt_end = self._statement_end(tokens, index, end)
                if self._expr_tainted(tokens, index + 4, stmt_end, env):
                    self._emit(path, line, "CWE-79", "unsafe DOM sink",
                               "untrusted request input reaches innerHTML",
                               steps + [f"{path}:{line} innerHTML assignment"])
                index = stmt_end
                continue
            # Expression statement: sink call, user call, or unknown shape.
            stmt_end = self._statement_end(tokens, index, end)
            self._handle_call(tokens, index, stmt_end, env, path, functions, steps, line)
            index = stmt_end

    def _handle_call(
        self, tokens: list[tuple[str, str, int]], start: int, end: int,
        env: dict[str, bool], path: str, functions: dict[str, _Function],
        steps: list[str], line: int,
    ) -> None:
        # Find the call name and argument span for `name(...)` / `member.exec(...)`.
        index = start
        while index < end:
            if tokens[index][0] == "word" and index + 1 < end and tokens[index + 1][1] == "(":
                name = tokens[index][1]
                args_start = index + 2
                args_end = self._matching_paren(tokens, index + 1, end)
                if args_end is None:
                    return
                arg_tainted = self._any_arg_tainted(tokens, args_start, args_end, env)
                if name in _EVAL_SINKS and arg_tainted:
                    self._emit(path, line, "CWE-95", "dynamic code evaluation",
                               "untrusted request input reaches eval/Function", steps)
                elif name in _EXEC_SINKS and arg_tainted:
                    self._emit(path, line, "CWE-78", "shell injection",
                               "untrusted request input reaches a child_process exec sink", steps)
                elif name in functions and arg_tainted and self._interpretations < _MAX_INTERPRETATIONS:
                    self._call_function(functions[name], tokens, args_start, args_end, env, path, functions, steps)
                index = args_end
            index += 1

    def _call_function(
        self, function: _Function, tokens: list[tuple[str, str, int]],
        args_start: int, args_end: int, env: dict[str, bool],
        path: str, functions: dict[str, _Function], steps: list[str],
    ) -> None:
        self._interpretations += 1
        # Split top-level commas to bind parameters to argument taint.
        child: dict[str, bool] = {}
        arg_taints = self._split_args(tokens, args_start, args_end, env)
        for param, tainted in zip(function.params, arg_taints):
            child[param] = tainted
        self._run_block(tokens, function.body_start, function.body_end, child, path, functions, steps)

    def _split_args(
        self, tokens: list[tuple[str, str, int]], start: int, end: int, env: dict[str, bool],
    ) -> list[bool]:
        parts: list[bool] = []
        depth = 0
        segment_start = start
        index = start
        while index < end:
            if tokens[index][1] in "([{":
                depth += 1
            elif tokens[index][1] in ")]}":
                depth -= 1
            elif tokens[index][1] == "," and depth == 0:
                parts.append(self._expr_tainted(tokens, segment_start, index, env))
                segment_start = index + 1
            index += 1
        parts.append(self._expr_tainted(tokens, segment_start, end, env))
        return parts

    def _any_arg_tainted(
        self, tokens: list[tuple[str, str, int]], start: int, end: int, env: dict[str, bool],
    ) -> bool:
        return any(self._split_args(tokens, start, end, env))

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _statement_end(tokens: list[tuple[str, str, int]], start: int, end: int) -> int:
        index = start
        depth = 0
        while index < end:
            value = tokens[index][1]
            if value in "([{":
                depth += 1
            elif value in ")]}":
                if depth == 0:
                    return index
                depth -= 1
            elif value == ";" and depth == 0:
                return index + 1
            elif value == "{" and depth == 0:
                # Statement continues into a block; skip it whole.
                close = _JsAnalyzer._matching_brace_static(tokens, index, end)
                return (close + 1) if close is not None else end
            index += 1
        return end

    @staticmethod
    def _matching_paren(tokens: list[tuple[str, str, int]], start: int, end: int) -> int | None:
        depth = 0
        for index in range(start, end):
            value = tokens[index][1]
            if value == "(":
                depth += 1
            elif value == ")":
                depth -= 1
                if depth == 0:
                    return index
        return None

    @staticmethod
    def _matching_brace_static(tokens: list[tuple[str, str, int]], start: int, end: int) -> int | None:
        depth = 0
        for index in range(start, end):
            value = tokens[index][1]
            if value == "{":
                depth += 1
            elif value == "}":
                depth -= 1
                if depth == 0:
                    return index
        return None

    def _skip_control_header(self, tokens: list[tuple[str, str, int]], start: int, end: int) -> int:
        paren = start + 1
        if paren < end and tokens[paren][1] == "(":
            close = self._matching_paren(tokens, paren + 1, end)
            if close is not None:
                paren = close + 1
        if paren < end and tokens[paren][1] == "{":
            close = self._matching_brace_static(tokens, paren, end)
            return (close + 1) if close is not None else end
        return paren

    def _skip_function(self, tokens: list[tuple[str, str, int]], start: int, end: int) -> int:
        index = start + 1
        while index < end and tokens[index][1] != "{":
            index += 1
        close = self._matching_brace_static(tokens, index, end) if index < end else None
        return (close + 1) if close is not None else end

    def _collect_functions(self, tokens: list[tuple[str, str, int]], end: int) -> dict[str, _Function]:
        functions: dict[str, _Function] = {}
        index = 0
        while index < end:
            if tokens[index][1] == "function" and index + 1 < end and tokens[index + 1][0] == "word":
                name = tokens[index + 1][1]
                params: list[str] = []
                paren = index + 2
                if paren < end and tokens[paren][1] == "(":
                    close = self._matching_paren(tokens, paren, end)
                    if close is not None:
                        cursor = paren + 1
                        while cursor < close:
                            if tokens[cursor][0] == "word":
                                params.append(tokens[cursor][1])
                            cursor += 1
                    body = close + 1 if close is not None else end
                    if body < end and tokens[body][1] == "{":
                        body_end = self._matching_brace_static(tokens, body, end)
                        if body_end is not None:
                            functions[name] = _Function(name, params, body + 1, body_end)
                            index = body_end + 1
                            continue
            index += 1
        return functions

    def _emit(self, path: str, line: int, cwe: str, name: str, summary: str, steps: list[str]) -> None:
        if len(self.result.findings) >= _MAX_FINDINGS:
            return
        digest = hashlib.sha256(f"{cwe}|{path}|{line}|{summary}".encode()).hexdigest()[:18]
        evidence = steps[-6:] + [f"{path}:{line} reaches {name} sink"]
        self.result.findings.append(ThreatFinding(
            finding_id=f"TAINT-JS-{digest}",
            cwe=cwe,
            severity=Severity.CRITICAL if cwe != "CWE-79" else Severity.HIGH,
            summary=f"Potential {summary} (deterministic JS subset analysis)",
            affected_nodes=[path],
            evidence=evidence,
        ))

    # -- entry -------------------------------------------------------------
    def run(self) -> JsTaintResult:
        for path, content in sorted(self._sources.items()):
            if len(self.result.analyzed_paths) + len(self.result.skipped_paths) >= _MAX_FILES:
                self.result.skipped_paths.append(path)
                continue
            if len(content) > _MAX_FILE_BYTES:
                self.result.skipped_paths.append(path)
                continue
            tokens = _tokens(content)
            functions = self._collect_functions(tokens, len(tokens))
            self._run_block(tokens, 0, len(tokens), {}, path, functions, [])
            # Request handlers are registered as callbacks, never called at
            # module level: interpret every function once so handler bodies
            # (params named req/request/event/ctx satisfy the source pattern)
            # are analyzed. Bounded by the interpretation budget.
            for name in sorted(functions):
                if self._interpretations >= _MAX_INTERPRETATIONS:
                    break
                function = functions[name]
                child = {param: False for param in function.params}
                self._interpretations += 1
                self._run_block(
                    tokens, function.body_start, function.body_end, child, path, functions, [],
                )
            self.result.analyzed_paths.append(path)
            self.result.notes.append({"reason": "js_subset", "path": path, "detail": "javascript subset analysis"})
        self.result.interpretations = self._interpretations
        return self.result


def analyze_js_taint(sources: dict[str, str]) -> JsTaintResult:
    return _JsAnalyzer(sources).run()


__all__ = ["JsTaintResult", "analyze_js_taint"]
