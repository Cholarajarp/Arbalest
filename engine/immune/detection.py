"""Deterministic detection tripwire for the Immune System.

Zero-LLM, sub-millisecond static rules that locate real sinks. These findings
are the input to topological blast-radius tracing and the adversarial
war-game; they are never the final verdict — the Crucible is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class DetectionFinding:
    rule_id: str
    name: str
    cwe: str
    severity: str            # critical | high | medium | low
    file: str                # repo-relative posix path
    line: int                # 1-based
    col: int                 # 1-based
    evidence: str            # matched source line
    hint: str = ""
    learned: bool = False    # True when fired by a synthesized antibody

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return (SEV_RANK.get(self.severity, 9), self.file, self.line)


class _Rule:
    __slots__ = ("rule_id", "name", "cwe", "severity", "regex", "languages", "hint", "exclude")

    def __init__(self, rule_id: str, name: str, cwe: str, severity: str,
                 pattern: str, languages: tuple[str, ...], hint: str,
                 exclude: str = "") -> None:
        self.rule_id = rule_id
        self.name = name
        self.cwe = cwe
        self.severity = severity
        self.regex = re.compile(pattern)
        self.languages = frozenset(languages)
        self.hint = hint
        self.exclude = re.compile(exclude) if exclude else None


_PY = ("py",)
_JS = ("js", "jsx", "ts", "tsx")
_BOTH = ("py", "js", "jsx", "ts", "tsx")

_SECRET_ASSIGN = (
    r"(?i)\b(password|passwd|secret|api_?key|apikey|access_token|auth_token)\b"
    r"\s*[:=]\s*[\"'][^\"']{8,}[\"']"
)
_ENV_EXCLUDE = r"os\.environ|process\.env|getenv|environ\[|mask|redact"

RULES: tuple[_Rule, ...] = (
    _Rule("SENT-PY-001", "Command injection (shell=True)", "CWE-78", "critical",
          r"shell\s*=\s*True", _PY, "Pass an argv list and keep shell=False"),
    _Rule("SENT-PY-002", "Dynamic code evaluation (eval)", "CWE-95", "critical",
          r"\beval\s*\(", _PY, "Use ast.literal_eval for structured data"),
    _Rule("SENT-PY-003", "Dynamic execution (exec)", "CWE-95", "high",
          r"\bexec\s*\(", _PY, "Remove runtime code execution"),
    _Rule("SENT-PY-004", "Unsafe deserialization (pickle)", "CWE-502", "critical",
          r"\bpickle\.loads\s*\(", _PY, "Prefer JSON or signed envelopes"),
    _Rule("SENT-PY-005", "Unsafe yaml.load", "CWE-502", "high",
          r"\byaml\.load\s*\((?![^)]*Loader\s*=)", _PY, "Use yaml.safe_load"),
    _Rule("SENT-PY-006", "SQL query built with f-string", "CWE-89", "high",
          r"\.execute\s*\(\s*f[\"']", _PY, "Use parameterized queries (%s placeholders)"),
    _Rule("SENT-PY-007", "SQL query built with .format", "CWE-89", "high",
          r"\.execute\s*\([^)]*\.format\s*\(", _PY, "Use parameterized queries"),
    _Rule("SENT-PY-008", "Shell command via os.system", "CWE-78", "high",
          r"\bos\.system\s*\(", _PY, "Use subprocess with argv list"),
    _Rule("SENT-PY-009", "TLS verification disabled", "CWE-295", "high",
          r"verify\s*=\s*False", _PY, "Keep certificate verification enabled"),
    _Rule("SENT-PY-010", "Weak hash (md5/sha1)", "CWE-327", "medium",
          r"\bmd5\s*\(|\bsha1\s*\(", _PY, "Use SHA-256 or better"),
    _Rule("SENT-PY-011", "Predictable temp path (mktemp)", "CWE-377", "medium",
          r"tempfile\.mktemp\s*\(", _PY, "Use mkstemp"),
    _Rule("SENT-PY-012", "Hardcoded credential", "CWE-798", "high",
          _SECRET_ASSIGN, _PY, "Move secrets to env/secret manager", exclude=_ENV_EXCLUDE),
    _Rule("SENT-PY-013", "AWS access key literal", "CWE-798", "critical",
          r"\bAKIA[0-9A-Z]{16}\b", _BOTH, "Rotate and remove the key"),
    _Rule("SENT-PY-014", "Debug mode enabled", "CWE-489", "low",
          r"debug\s*=\s*True", _PY, "Disable debug in production paths"),
    _Rule("SENT-JS-001", "Dynamic code evaluation (eval)", "CWE-95", "critical",
          r"\beval\s*\(", _JS, "Use JSON.parse or a safe interpreter"),
    _Rule("SENT-JS-002", "Dynamic Function constructor", "CWE-95", "high",
          r"new\s+Function\s*\(", _JS, "Remove runtime code synthesis"),
    _Rule("SENT-JS-003", "Shell exec with template injection", "CWE-78", "high",
          r"exec(?:Sync)?\(\s*`[^`]*\$\{", _JS, "Use execFile with argv array"),
    _Rule("SENT-JS-004", "TLS verification disabled", "CWE-295", "medium",
          r"rejectUnauthorized\s*:\s*false", _JS, "Keep rejectUnauthorized true"),
    _Rule("SENT-JS-005", "Raw HTML injection (dangerouslySetInnerHTML)", "CWE-79", "high",
          r"dangerouslySetInnerHTML", _JS, "Sanitize or use text nodes"),
    _Rule("SENT-JS-006", "document.write sink", "CWE-79", "medium",
          r"document\.write\s*\(", _JS, "Use DOM APIs with textContent"),
    _Rule("SENT-JS-007", "JWT algorithm none", "CWE-347", "high",
          r"algorithm\s*[:=]\s*[\"']none[\"']", _JS, "Use an HMAC/RSA algorithm"),
    _Rule("SENT-JS-008", "Deprecated weak cipher (createCipher)", "CWE-327", "medium",
          r"createCipher\s*\(", _JS, "Use createCipheriv with AEAD"),
    _Rule("SENT-JS-009", "Hardcoded credential", "CWE-798", "high",
          _SECRET_ASSIGN, _JS, "Move secrets to env/secret manager", exclude=_ENV_EXCLUDE),
    _Rule("SENT-JS-010", "innerHTML assignment sink", "CWE-79", "medium",
          r"\binnerHTML\s*=", _JS, "Use textContent for untrusted data"),
)

_KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "return", "function", "typeof", "await", "async"})

_EXT_LANG = {".py": "py", ".js": "js", ".jsx": "js", ".ts": "ts", ".tsx": "ts"}


def _language_of(rel_path: str) -> str | None:
    dot = rel_path.rfind(".")
    return _EXT_LANG.get(rel_path[dot:].lower()) if dot >= 0 else None


def sweep_file(rel_path: str, content: str) -> list[DetectionFinding]:
    """Run all language-applicable rules against one file. Line-based, no LLM."""
    lang = _language_of(rel_path)
    if lang is None:
        return []
    findings: list[DetectionFinding] = []
    for line_no, raw_line in enumerate(content.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("#", "//", "*", "/*")):
            continue
        for rule in RULES:
            if lang not in rule.languages:
                continue
            match = rule.regex.search(raw_line)
            if not match:
                continue
            if rule.exclude and rule.exclude.search(raw_line):
                continue
            findings.append(DetectionFinding(
                rule_id=rule.rule_id, name=rule.name, cwe=rule.cwe, severity=rule.severity,
                file=rel_path, line=line_no, col=match.start() + 1,
                evidence=stripped[:200], hint=rule.hint,
            ))
    return findings


def sweep_sources(sources: dict[str, str]) -> list[DetectionFinding]:
    """Sweep a whole tree; findings sorted by severity, then file, then line."""
    findings: list[DetectionFinding] = []
    for rel, content in sources.items():
        findings.extend(sweep_file(rel, content))
    findings.sort(key=lambda f: f.sort_key)
    return findings
