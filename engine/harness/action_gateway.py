"""Deny-by-default policy gate for agent-generated actions.

Agents produce commands and file artifacts. The gateway is the single choke
point every such artifact passes before execution: privilege escalation,
container/VM escape, network egress, destructive filesystem operations,
supply-chain installs, and host-secret access are denied with a named rule;
everything else is allowed. Deny rules are fail-closed — an evaluation error
is a denial.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

_MAX_COMMAND_CHARS = 64_000

# (rule, pattern) — order is report order. Matched against the whole artifact
# text, not line starts: attackers hide operators behind ; && || newlines.
_DENY_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "privilege_escalation",
        re.compile(
            r"(?im)(?:^|[;&|]\s*|\bsudo\s+-\w+\s+)(?:sudo|su|doas|pkexec)\s"
            r"|\bchmod\s+(?:777|[uvsg]\+s)\s+/(?:etc|usr|bin|sbin)\b"
            r"|\bchown\b[^;\n|]{0,40}\broot\b"
        ),
    ),
    (
        "container_escape",
        re.compile(
            r"(?i)\bdocker\s+(?:run|exec|pull|build|cp)\b"
            r"|\bkubectl\b|\bnsenter\b|\bmount\s+-\b"
            r"|/var/run/docker\.sock|/proc/1/root|cgroup(?:s)?/release_agent"
        ),
    ),
    (
        "network_egress",
        re.compile(
            r"(?i)\b(?:curl|wget|fetch|ftp|telnet|nc|ncat|netcat)\b"
            r"|\bssh\b(?!/)|/dev/tcp/|\bping\b\s+-[cf]\b|\bpip\s+download\b"
        ),
    ),
    (
        "destructive_fs",
        re.compile(
            r"(?i)\brm\s+(-[a-z]*[rf][a-z]*\s+)+/(?:\s|$)"
            r"|\bmkfs\b|\bdd\b[^;\n]{0,60}\bof=/dev/\b"
            r"|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"
            r"|>\s*/dev/sd[a-z]\b|\bshred\b[^;\n]{0,40}/dev/"
        ),
    ),
    (
        "supply_chain",
        re.compile(
            r"(?i)\b(?:apt-get|apt|yum|apk)\s+install\b"
            r"|\bpip(?:3)?\s+install\b|\bnpm\s+(?:install|i)\b"
            r"|\bcargo\s+install\b|\bgem\s+install\b"
        ),
    ),
    (
        "host_secrets",
        re.compile(
            r"(?i)/etc/(?:passwd|shadow|sudoers)\b"
            r"|\.ssh/(?:id_[a-z]+|authorized_keys)\b"
            r"|\.aws/credentials|\.kube/config|\.docker/config\.json"
        ),
    ),
)


class GatewayVerdict(BaseModel):
    """The outcome of one gateway evaluation."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    rule: str = "default"
    reason: str = ""


class ActionGateway:
    """Fail-closed policy evaluation for agent-generated command artifacts."""

    def __init__(self, *, extra_deny_rules: tuple[tuple[str, re.Pattern[str]], ...] = ()) -> None:
        self._deny_rules = _DENY_RULES + extra_deny_rules

    def evaluate_command(self, command_text: str) -> GatewayVerdict:
        """Evaluate a shell/command artifact. Deny on any rule match."""
        if not command_text or not command_text.strip():
            return GatewayVerdict(allowed=False, rule="empty", reason="Empty command artifact")
        if len(command_text) > _MAX_COMMAND_CHARS:
            return GatewayVerdict(
                allowed=False,
                rule="oversized",
                reason=f"Command artifact exceeds {_MAX_COMMAND_CHARS} characters",
            )
        try:
            for rule, pattern in self._deny_rules:
                match = pattern.search(command_text)
                if match:
                    excerpt = " ".join(match.group(0).split())[:160]
                    return GatewayVerdict(
                        allowed=False,
                        rule=rule,
                        reason=f"Denied by harness policy {rule!r}: {excerpt}",
                    )
        except re.error as exc:  # pragma: no cover — fail-closed by construction
            return GatewayVerdict(allowed=False, rule="gateway_error", reason=f"Gateway evaluation failed: {exc}")
        return GatewayVerdict(allowed=True, rule="default", reason="No harness policy violation")

    def evaluate_write_path(self, path: str) -> GatewayVerdict:
        """Evaluate a relative write target. Absolute, traversal, and drive paths are denied."""
        if not path or not path.strip():
            return GatewayVerdict(allowed=False, rule="empty", reason="Empty write path")
        if "\\" in path or ":" in path or path.startswith("/"):
            return GatewayVerdict(allowed=False, rule="unsafe_path", reason=f"Absolute or host-bound path {path!r}")
        parts = path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            return GatewayVerdict(allowed=False, rule="path_traversal", reason=f"Traversal in path {path!r}")
        return GatewayVerdict(allowed=True, rule="default", reason="Relative workspace path")


__all__ = ["ActionGateway", "GatewayVerdict"]
