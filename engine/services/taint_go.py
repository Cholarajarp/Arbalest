"""Bounded deterministic Go may-flow taint analysis.

Scope (narrow and documented, mirroring ``taint_js``): module-level statements
and function bodies; sources are net/http request patterns — ``r.URL.Query()``,
``r.FormValue(...)``, ``r.PostFormValue(...)``, ``r.URL.Path`` for receivers
named r/req/request; propagation covers ``:=`` and ``=`` assignments, string
concatenation and ``fmt.Sprintf`` with tainted arguments; functions are
interpreted at tainted call sites and once each in a handler breadth pass;
sinks are ``exec.Command``/``exec.CommandContext`` (CWE-78) and
``Query``/``QueryRow``/``Exec`` receiving tainted strings (CWE-89). Unknown
statement shapes are skipped and every analyzed file records one ``go_subset``
approximation note. No execution, no filesystem access.
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

_SOURCE_RECEIVERS = frozenset({"r", "req", "request"})
_SPRINTF = frozenset({"Sprintf"})
_EXEC_SINKS = frozenset({"Command", "CommandContext"})
_QUERY_SINKS = frozenset({"Query", "QueryRow", "Exec"})
_TOKEN = re.compile(
    r"""(?P<ws>[ \t\r]+)
      | (?P<nl>\n)
      | (?P<raw>`(?:[^`\\]|\\.)*`)
      | (?P<string>"(?:[^"\\]|\\.)*")
      | (?P<num>\b\d[\d._]*\b)
      | (?P<word>[A-Za-z_][\w]*)
      | (?P<punct>[{}()\[\];,.:=+\-*/%<>!&|])
    """,
    re.VERBOSE,
)


@dataclass
class GoTaintResult:
    findings: list[ThreatFinding] = field(default_factory=list)
    analyzed_paths: list[str] = field(default_factory=list)
    skipped_paths: list[str] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)
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
        if kind == "nl":
            output.append(("nl", "\n", line))
            line += 1
        elif kind != "ws":
            output.append((kind, value, line))
        position = match.end()
    return output


class _Function:
    __slots__ = ("name", "params", "body_start", "body_end")

    def __init__(self, name: str, params: list[str], body_start: int, body_end: int) -> None:
        self.name = name
        self.params = params
        self.body_start = body_start
        self.body_end = body_end


class _GoAnalyzer:
    def __init__(self, sources: dict[str, str]) -> None:
        self._sources = sources
        self.result = GoTaintResult()
        self._interpretations = 0

    # -- expression taint --------------------------------------------------
    def _expr_tainted(
        self, tokens: list[tuple[str, str, int]], start: int, end: int,
        env: dict[str, bool],
    ) -> bool:
        index = start
        while index < end:
            kind, value, _ = tokens[index]
            if kind == "word" and value in env and env[value]:
                return True
            # r.URL.Query() ... / r.FormValue("x") / r.URL.Path
            if kind == "word" and value in _SOURCE_RECEIVERS:
                if self._is_source_usage(tokens, index, end):
                    return True
            if kind == "raw" and "$_{" not in value:
                # Raw strings interpolate nothing in Go; safe unless built.
                pass
            # fmt.Sprintf(...) with any tainted argument
            if (
                kind == "word" and value in _SPRINTF
                and index + 1 < end and tokens[index + 1][1] == "("
            ):
                args_end = self._matching(tokens, index + 1, end, "(", ")")
                if args_end is not None and self._any_arg_tainted(tokens, index + 2, args_end, env):
                    return True
            index += 1
        return False

    @staticmethod
    def _is_source_usage(tokens: list[tuple[str, str, int]], index: int, end: int) -> bool:
        # r.URL.Query() / r.FormValue("x") / r.PostFormValue("x") / r.URL.Path
        window = [tokens[i][1] if i < end else "" for i in range(index, min(index + 8, end))]
        compact = "".join(part for part in window if part not in {" ", ";", "\n"})
        after_receiver = compact[len(tokens[index][1]):] if compact.startswith(tokens[index][1]) else compact
        return (
            after_receiver.startswith(".URL.Query()")
            or after_receiver.startswith(".URL.Path")
            or after_receiver.startswith(".FormValue(")
            or after_receiver.startswith(".PostFormValue(")
        )

    # -- call handling -----------------------------------------------------
    def _handle_call(
        self, tokens: list[tuple[str, str, int]], start: int, end: int,
        env: dict[str, bool], path: str, functions: dict[str, _Function],
        steps: list[str], line: int,
    ) -> None:
        index = start
        while index < end:
            if tokens[index][0] == "word" and index + 1 < end and tokens[index + 1][1] == "(":
                name = tokens[index][1]
                args_end = self._matching(tokens, index + 1, end, "(", ")")
                if args_end is None:
                    return
                args_start = index + 2
                arg_taints = self._split_args(tokens, args_start, args_end, env)
                if name in _EXEC_SINKS and self._exec_is_unsafe(tokens, args_start, args_end, arg_taints):
                    self._emit(path, line, "CWE-78", "shell injection",
                               "untrusted request input reaches an exec.Command sink", steps)
                elif name in _QUERY_SINKS and arg_taints[:1] == [True]:
                    # Parameterized queries pass taint in later arguments on
                    # purpose; only a tainted query STRING is the flaw.
                    self._emit(path, line, "CWE-89", "sql injection",
                               "untrusted request input reaches a Query/Exec sink", steps)
                elif name in functions and any(arg_taints) and self._interpretations < _MAX_INTERPRETATIONS:
                    self._call_function(functions[name], tokens, args_start, args_end, env, path, functions, steps)
                index = args_end
            index += 1

    @staticmethod
    def _exec_is_unsafe(
        tokens: list[tuple[str, str, int]], start: int, end: int, arg_taints: list[bool],
    ) -> bool:
        # Safe Go: exec.Command("git", taintedArg) — separate argv, no shell.
        # Unsafe: tainted program name, or a shell ("-c") invoked with any
        # tainted argument, or one string command built from input.
        if arg_taints[:1] == [True]:
            return True
        if not any(arg_taints):
            return False
        for index in range(start, end):
            if tokens[index][0] in {"string", "raw"} and tokens[index][1].strip('"`') in {"sh", "bash", "-c"}:
                return True
        return False

    def _call_function(
        self, function: _Function, tokens: list[tuple[str, str, int]],
        args_start: int, args_end: int, env: dict[str, bool],
        path: str, functions: dict[str, _Function], steps: list[str],
    ) -> None:
        self._interpretations += 1
        child = {param: tainted for param, tainted in zip(
            function.params, self._split_args(tokens, args_start, args_end, env)
        )}
        self._run_block(tokens, function.body_start, function.body_end, child, path, functions, steps)

    def _split_args(
        self, tokens: list[tuple[str, str, int]], start: int, end: int, env: dict[str, bool],
    ) -> list[bool]:
        parts: list[bool] = []
        depth = 0
        segment_start = start
        index = start
        while index < end:
            value = tokens[index][1]
            if value in "([{":
                depth += 1
            elif value in ")]}":
                depth -= 1
            elif value == "," and depth == 0:
                parts.append(self._expr_tainted(tokens, segment_start, index, env))
                segment_start = index + 1
            index += 1
        parts.append(self._expr_tainted(tokens, segment_start, end, env))
        return parts

    def _any_arg_tainted(
        self, tokens: list[tuple[str, str, int]], start: int, end: int, env: dict[str, bool],
    ) -> bool:
        return any(self._split_args(tokens, start, end, env))

    # -- statement walker --------------------------------------------------
    def _run_block(
        self, tokens: list[tuple[str, str, int]], start: int, end: int,
        env: dict[str, bool], path: str, functions: dict[str, _Function],
        steps: list[str],
    ) -> None:
        index = start
        while index < end:
            kind, value, line = tokens[index]
            if kind == "nl" or (kind == "punct" and value == ";"):
                index += 1
                continue
            # name := expr
            if (
                kind == "word" and index + 2 < end
                and tokens[index + 1][1] == ":" and tokens[index + 2][1] == "="
            ):
                stmt_end = self._statement_end(tokens, index, end)
                self._handle_call(tokens, index + 3, stmt_end, env, path, functions, steps, line)
                env[value] = self._expr_tainted(tokens, index + 3, stmt_end, env)
                if env[value]:
                    steps.append(f"{path}:{line} {value} carries request input")
                index = stmt_end
                continue
            # name = expr  (not ==)
            if (
                kind == "word" and index + 1 < end and tokens[index + 1][1] == "="
                and not (index + 2 < end and tokens[index + 2][1] == "=")
            ):
                stmt_end = self._statement_end(tokens, index, end)
                self._handle_call(tokens, index + 2, stmt_end, env, path, functions, steps, line)
                env[value] = self._expr_tainted(tokens, index + 2, stmt_end, env)
                index = stmt_end
                continue
            if kind == "word" and value in {"if", "for", "switch", "select", "return", "go", "defer"}:
                index = self._skip_control(tokens, index, end)
                continue
            if kind == "word" and value == "func":
                index = self._skip_function(tokens, index, end)
                continue
            stmt_end = self._statement_end(tokens, index, end)
            self._handle_call(tokens, index, stmt_end, env, path, functions, steps, line)
            index = stmt_end

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _matching(
        tokens: list[tuple[str, str, int]], start: int, end: int, opens: str, closes: str,
    ) -> int | None:
        depth = 0
        for index in range(start, end):
            value = tokens[index][1]
            if value == opens:
                depth += 1
            elif value == closes:
                depth -= 1
                if depth == 0:
                    return index
        return None

    @classmethod
    def _statement_end(cls, tokens: list[tuple[str, str, int]], start: int, end: int) -> int:
        index = start
        depth = 0
        while index < end:
            kind, value, _ = tokens[index]
            if kind == "nl" and depth == 0:
                # Go terminates statements at newlines (semicolon insertion).
                return index
            if value in "([{":
                depth += 1
            elif value in ")]}":
                if depth == 0:
                    return index
                depth -= 1
            elif value == ";" and depth == 0:
                return index + 1
            elif value == "{" and depth == 0:
                # Composite literal or block: skip it whole (subset).
                close = cls._matching(tokens, index, end, "{", "}")
                return (close + 1) if close is not None else end
            index += 1
        return end

    @classmethod
    def _skip_control(cls, tokens: list[tuple[str, str, int]], start: int, end: int) -> int:
        index = start + 1
        # Skip the condition (Go has no parens header; scan to first block).
        while index < end and tokens[index][1] != "{":
            index += 1
        if index >= end:
            return end
        close = cls._matching(tokens, index, end, "{", "}")
        return (close + 1) if close is not None else end

    @classmethod
    def _skip_function(cls, tokens: list[tuple[str, str, int]], start: int, end: int) -> int:
        index = start + 1
        while index < end and tokens[index][1] != "{":
            index += 1
        close = cls._matching(tokens, index, end, "{", "}") if index < end else None
        return (close + 1) if close is not None else end

    def _collect_functions(self, tokens: list[tuple[str, str, int]], end: int) -> dict[str, _Function]:
        functions: dict[str, _Function] = {}
        index = 0
        while index < end:
            if tokens[index][1] == "func" and index + 1 < end and tokens[index + 1][0] == "word":
                name = tokens[index + 1][1]
                paren = index + 2
                params: list[str] = []
                if paren < end and tokens[paren][1] == "(":
                    close = self._matching(tokens, paren, end, "(", ")")
                    if close is not None:
                        cursor = paren + 1
                        # Params look like (w http.ResponseWriter, r *http.Request)
                        # or bare types; collect plain words that precede a type.
                        words: list[str] = []
                        while cursor < close:
                            if tokens[cursor][0] == "word":
                                words.append(tokens[cursor][1])
                            elif tokens[cursor][1] == ",":
                                if words:
                                    params.append(words[0])
                                words = []
                            cursor += 1
                        if words:
                            params.append(words[0])
                        body = close + 1
                        if body < end and tokens[body][1] == "{":
                            body_end = self._matching(tokens, body, end, "{", "}")
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
        self.result.findings.append(ThreatFinding(
            finding_id=f"TAINT-GO-{digest}",
            cwe=cwe,
            severity=Severity.CRITICAL if cwe == "CWE-78" else Severity.HIGH,
            summary=f"Potential {summary} (deterministic Go subset analysis)",
            affected_nodes=[path],
            evidence=steps[-6:] + [f"{path}:{line} reaches {name} sink"],
        ))

    # -- entry -------------------------------------------------------------
    def run(self) -> GoTaintResult:
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
            # Handler breadth pass: net/http handlers take (w, r) but are
            # registered via HandleFunc, never called at module level.
            for name in sorted(functions):
                if self._interpretations >= _MAX_INTERPRETATIONS:
                    break
                function = functions[name]
                child = {param: False for param in function.params}
                self._interpretations += 1
                self._run_block(tokens, function.body_start, function.body_end, child, path, functions, [])
            self.result.analyzed_paths.append(path)
            self.result.notes.append({"reason": "go_subset", "path": path, "detail": "go subset analysis"})
        self.result.interpretations = self._interpretations
        return self.result


def analyze_go_taint(sources: dict[str, str]) -> GoTaintResult:
    return _GoAnalyzer(sources).run()


__all__ = ["GoTaintResult", "analyze_go_taint"]
