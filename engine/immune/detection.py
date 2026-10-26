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
_PHP = ("php",)
_GO = ("go",)
_RB = ("ruby",)
_JAVA = ("java",)
_CS = ("cs",)
_BOTH = ("py", "js", "jsx", "ts", "tsx", "php", "go", "ruby", "java", "cs")

_SECRET_ASSIGN = (
    r"(?i)\b(?:(?:db|aws|smtp|redis|mongo|sql|admin|jwt|session)[_-]?)?"
    r"(?:password|passwd|secret|api_?key|apikey|access_token|auth_token)\b"
    r"\s*[:=]\s*[\"'][^\"']{8,}[\"']"
)
_ENV_EXCLUDE = r"os\.environ|process\.env|getenv|environ\[|mask|redact"

# PHP request superglobals reaching a sink is the webshell signature that
# lands on servers exploited through interpreter RCEs such as PHP2Shell.
_PHP_REQUEST = r"\$_(?:GET|POST|REQUEST|COOKIE)"
_PHP_EXEC = r"\b(?:system|shell_exec|passthru|popen|proc_open)\s*\("

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
    _Rule("SENT-JS-011", "Shell exec built by concatenation", "CWE-78", "high",
          r"exec(?:Sync)?\(\s*[\"'][^\"']*[\"']\s*\+", _JS, "Use execFile with argv array"),
    # ── SaaS feature classes: session, token and browser-trust weaknesses ──
    _Rule("SENT-PY-015", "JWT signature verification disabled", "CWE-347", "critical",
          r"verify_signature[\"']?\s*:\s*False", _PY,
          "Always verify JWT signatures and algorithms"),
    _Rule("SENT-PY-016", "Session cookie flags disabled", "CWE-614", "medium",
          r"set_cookie\s*\([^)]*(?:secure|httponly)\s*=\s*False", _PY,
          "Set Secure and HttpOnly on session cookies"),
    _Rule("SENT-PY-017", "CORS wildcard origin", "CWE-942", "medium",
          r"allow_origins\s*=\s*\[[^\]]*[\"][*][\"]", _PY,
          "List explicit origins; never pair wildcard with credentials"),
    _Rule("SENT-JS-012", "JWT signature verification disabled", "CWE-347", "critical",
          r"verifySignature[\"']?\s*:\s*(?:false|'false'|\"false\")|verify\s*:\s*false", _JS,
          "Always verify JWT signatures and algorithms"),
    _Rule("SENT-JS-013", "Session cookie flags disabled", "CWE-614", "medium",
          r"\.cookie\s*\([^)]*(?:secure|httpOnly)\s*:\s*false", _JS,
          "Set Secure and HttpOnly on session cookies"),
    _Rule("SENT-JS-014", "CORS wildcard origin", "CWE-942", "medium",
          r"origin[\"']?\s*:\s*[\"'][*][\"']|Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"'][*][\"']", _JS,
          "List explicit origins; never pair wildcard with credentials"),
    _Rule("SENT-PHP-011", "Session cookie flags disabled", "CWE-614", "medium",
          r"session_set_cookie_params\s*\([^)]*(?:secure|httponly)\s*=>\s*(?:false|FALSE|0)", _PHP,
          "Set Secure and HttpOnly on session cookies"),
    _Rule("SENT-PHP-012", "CORS wildcard origin", "CWE-942", "medium",
          r"Access-Control-Allow-Origin[\"']?\s*[,.:]\s*[\"'][*][\"']", _PHP,
          "List explicit origins; never pair wildcard with credentials"),
    _Rule("SENT-PHP-001", "Webshell: request input into command execution", "CWE-78", "critical",
          r"(?:\bsystem\s*\(|" + _PHP_EXEC + r")[^;)]*" + _PHP_REQUEST, _PHP,
          "Never pass request superglobals to command execution"),
    _Rule("SENT-PHP-002", "Webshell: eval of request input", "CWE-95", "critical",
          r"\beval\s*\([^;)]*" + _PHP_REQUEST, _PHP, "Remove runtime code evaluation"),
    _Rule("SENT-PHP-003", "Dynamic code evaluation (eval)", "CWE-95", "high",
          r"\beval\s*\(", _PHP, "Remove runtime code evaluation"),
    _Rule("SENT-PHP-004", "File inclusion of request input (RFI/LFI)", "CWE-98", "critical",
          r"\b(?:include|require)(?:_once)?\s*\(\s*" + _PHP_REQUEST, _PHP,
          "Map allowed paths explicitly; never include request input"),
    _Rule("SENT-PHP-005", "Unsafe deserialization of request input", "CWE-502", "critical",
          r"\bunserialize\s*\([^;)]*" + _PHP_REQUEST, _PHP, "Use JSON or an allowlist of classes"),
    _Rule("SENT-PHP-006", "SQL query built from request input", "CWE-89", "critical",
          r"\bmysqli?_(?:query|real_query|multi_query)\s*\([^;)]*" + _PHP_REQUEST, _PHP,
          "Use prepared statements with bound parameters"),
    _Rule("SENT-PHP-007", "Command execution sink (system/shell_exec/passthru)", "CWE-78", "high",
          _PHP_EXEC, _PHP, "Use escapeshellarg on every argument, or avoid shell calls"),
    _Rule("SENT-PHP-008", "Unsafe deserialization (unserialize)", "CWE-502", "high",
          r"\bunserialize\s*\(", _PHP, "Use JSON or an allowlist of classes"),
    _Rule("SENT-PHP-009", "Hardcoded credential", "CWE-798", "high",
          _SECRET_ASSIGN, _PHP, "Move secrets to env/secret manager", exclude=_ENV_EXCLUDE),
    _Rule("SENT-PHP-010", "TLS verification disabled", "CWE-295", "medium",
          r"verify_peer(?:_name)??[\"']?\s*=>\s*false", _PHP, "Keep peer verification enabled"),
    _Rule("SENT-GO-001", "Shell command built with Sprintf", "CWE-78", "high",
          r"exec\.Command(?:Context)?\([^)]*fmt\.Sprintf", _GO,
          "Pass argv arguments directly; never build shell strings"),
    _Rule("SENT-GO-002", "Shell interpreter invocation", "CWE-78", "high",
          r"exec\.Command(?:Context)?\(\s*\"(?:/bin/)?(?:ba)?sh\"\s*,\s*\"-c\"", _GO,
          "Avoid shell -c with dynamic input"),
    _Rule("SENT-GO-003", "SQL query built with Sprintf", "CWE-89", "high",
          r"\.(?:Query|Exec)(?:Context)?\([^)]*fmt\.Sprintf", _GO, "Use $1 placeholders with args"),
    _Rule("SENT-RB-001", "Shell command with interpolation", "CWE-78", "high",
          r"\bsystem\s*\([^)]*#\{|\b`[^`]*#\{", _RB, "Use system with an argument array (shellout gems)"),
    _Rule("SENT-RB-002", "Dynamic code evaluation (eval)", "CWE-95", "high",
          r"\beval\s*\(", _RB, "Remove runtime code evaluation"),
    _Rule("SENT-RB-003", "Unsafe deserialization (Marshal.load)", "CWE-502", "high",
          r"Marshal\.load\s*\(", _RB, "Use JSON or signed payloads"),
    _Rule("SENT-RB-004", "SQL fragment with interpolation", "CWE-89", "high",
          r"\bwhere\s*\(\s*[\"'][^\"']*#\{", _RB, "Use parameterized conditions (array/hash forms)"),
    _Rule("SENT-JAVA-001", "Runtime command execution", "CWE-78", "high",
          r"Runtime\.getRuntime\(\)\.exec\s*\(", _JAVA, "Use ProcessBuilder with argv and validation"),
    _Rule("SENT-JAVA-002", "Unsafe Java deserialization (readObject)", "CWE-502", "high",
          r"\breadObject\s*\(", _JAVA, "Prefer JSON; or apply an ObjectInputFilter allowlist"),
    _Rule("SENT-JAVA-003", "ProcessBuilder with concatenation", "CWE-78", "medium",
          r"new\s+ProcessBuilder\([^)]*\+", _JAVA, "Pass discrete, validated arguments"),
    _Rule("SENT-JAVA-004", "SQL statement built by concatenation", "CWE-89", "high",
          r"\.execute(?:Query|Update|Batch)?\(\s*\"[^\"]*\"\s*\+", _JAVA, "Use PreparedStatement parameters"),
    _Rule("SENT-CS-001", "Process.Start with concatenation", "CWE-78", "high",
          r"Process\.Start\s*\([^)]*\+", _CS, "Pass a validated ArgumentList"),
    _Rule("SENT-CS-002", "Unsafe deserialization (BinaryFormatter)", "CWE-502", "high",
          r"new\s+BinaryFormatter\b|new\s+NetDataContractSerializer\b|LosFormatter\s*\(", _CS,
          "Use System.Text.Json; BinaryFormatter is unsafe by default"),
    _Rule("SENT-CS-003", "SQL command built by concatenation", "CWE-89", "high",
          r"new\s+SqlCommand\s*\([^)]*\+", _CS, "Use parameterized SqlCommand parameters"),
)

_KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "return", "function", "typeof", "await", "async"})

_EXT_LANG = {
    ".py": "py", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "ts", ".tsx": "ts", ".php": "php", ".phtml": "php",
    ".go": "go", ".rb": "ruby", ".java": "java", ".jsp": "java", ".cs": "cs",
}


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
