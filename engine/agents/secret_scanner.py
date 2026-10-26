"""Deterministic, local-only hardcoded-secret detection and redaction."""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass

from engine.agents.architect_agent import Severity, ThreatFinding
from engine.services.ai_provider import AIProvider

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _SecretPattern:
    kind: str
    regex: re.Pattern[str]
    group: str = "secret"
    severity: Severity = Severity.HIGH


_PATTERNS: tuple[_SecretPattern, ...] = (
    _SecretPattern(
        "credential assignment",
        re.compile(
            r"(?i)\b(?:(?:db|aws|smtp|redis|mongo|sql|admin|jwt|session)[_-]?)?"
            r"(?:api[_-]?key|secret|password|passwd|token|credential|auth[_-]?token)\b"
            r"\s*[:=]\s*[\"'](?P<secret>[^\"'\r\n]{8,})[\"']"
        ),
        severity=Severity.HIGH,
    ),
    _SecretPattern("AWS access key", re.compile(r"(?P<secret>AKIA[0-9A-Z]{16})"), severity=Severity.CRITICAL),
    _SecretPattern("GitHub token", re.compile(r"(?P<secret>gh[pousr]_[A-Za-z0-9_]{30,255})"), severity=Severity.CRITICAL),
    _SecretPattern("private key", re.compile(r"(?P<secret>-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----)"), severity=Severity.CRITICAL),
    _SecretPattern(
        "database credential",
        re.compile(r"(?i)(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql)://[^\s:/@]+:(?P<secret>[^\s@/]{4,})@"),
        severity=Severity.CRITICAL,
    ),
    _SecretPattern("provider API key", re.compile(r"(?P<secret>(?:sk-|sk_live_|sk_test_)[A-Za-z0-9_-]{20,})"), severity=Severity.CRITICAL),
    _SecretPattern("bearer token", re.compile(r"(?i)\bbearer\s+(?P<secret>[A-Za-z0-9._~-]{20,})"), severity=Severity.CRITICAL),
)

_PLACEHOLDER = re.compile(
    r"(?i)^(?:example|sample|dummy|fake|test|testing|placeholder|changeme|replace[_-]?me|your[_-]|xxx+|todo|null|none|<.*>|\$\{.*\})"
)
_ENV_READ = re.compile(r"(?i)(?:getenv|os\.environ|process\.env|secretstr|environment)")


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}{'*' * min(len(value) - 6, 16)}{value[-3:]}"


def _iter_matches(text: str):
    for pattern in _PATTERNS:
        for match in pattern.regex.finditer(text):
            try:
                value = match.group(pattern.group)
            except (IndexError, KeyError):
                continue
            if not value or _PLACEHOLDER.match(value.strip()):
                continue
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end < 0:
                line_end = len(text)
            line = text[line_start:line_end]
            if _ENV_READ.search(line) and not re.search(r"[\"'][^\"']{8,}[\"']", line):
                continue
            yield pattern, match, value, line_start, line_end


def redact_secrets(text: str) -> str:
    """Mask recognized secret values before content crosses a model boundary."""
    replacements: list[tuple[int, int, str]] = []
    for pattern, match, value, _line_start, _line_end in _iter_matches(text):
        start, end = match.span(pattern.group)
        replacements.append((start, end, _mask(value)))
    redacted = text
    for start, end, replacement in sorted(replacements, reverse=True):
        redacted = redacted[:start] + replacement + redacted[end:]
    return redacted


class SecretScannerAgent:
    """Find hardcoded credentials locally without disclosing them to an AI provider."""

    def __init__(self, provider: AIProvider | None = None) -> None:
        # Kept for API compatibility. Secret material is never sent to this provider.
        self._provider = provider

    async def analyze(self, legacy_sources: Mapping[str, str]) -> list[ThreatFinding]:
        findings: list[ThreatFinding] = []
        seen: set[tuple[str, int, int]] = set()

        for file_path, content in legacy_sources.items():
            if len(content.encode("utf-8", errors="ignore")) > 256 * 1024:
                continue
            for pattern, match, value, line_start, line_end in _iter_matches(content):
                line_number = content.count("\n", 0, match.start()) + 1
                value_start, value_end = match.span(pattern.group)
                identity = (file_path, value_start, value_end)
                if identity in seen:
                    continue
                seen.add(identity)
                line = content[line_start:line_end]
                relative_start = value_start - line_start
                relative_end = value_end - line_start
                masked_line = line[:relative_start] + _mask(value) + line[relative_end:]
                digest = hashlib.sha256(f"{file_path}:{line_number}:{pattern.kind}".encode()).hexdigest()[:12]
                findings.append(
                    ThreatFinding(
                        finding_id=f"SECRET-{digest}",
                        cwe="CWE-798",
                        severity=pattern.severity,
                        summary=f"Hardcoded {pattern.kind} in {file_path}",
                        affected_nodes=[file_path],
                        evidence=[f"line {line_number}: {masked_line.strip()[:300]}"],
                    )
                )

        logger.info("Local secret scan completed", extra={"findings": len(findings)})
        return findings


__all__ = ["SecretScannerAgent", "redact_secrets"]
