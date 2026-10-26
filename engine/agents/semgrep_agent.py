"""Optional bounded Semgrep integration for deterministic static analysis."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from engine.agents.architect_agent import Severity, ThreatFinding

logger = logging.getLogger(__name__)
_MAX_OUTPUT = 8 * 1024 * 1024


class SemgrepAgent:
    """Run an operator-configured Semgrep ruleset with argv-safe subprocess execution."""

    def __init__(self, ruleset: str | None = None) -> None:
        self.executable = shutil.which("semgrep") or shutil.which("semgrep.exe")
        self.ruleset = (ruleset or os.environ.get("ARBALEST_SEMGREP_CONFIG", "")).strip()

    @property
    def available(self) -> bool:
        return bool(self.executable and self.ruleset)

    async def analyze(self, legacy_sources: Mapping[str, str]) -> list[ThreatFinding]:
        if not legacy_sources or not self.available:
            return []
        temp_root = Path(tempfile.mkdtemp(prefix="arbalest-semgrep-"))
        try:
            for relative, content in list(legacy_sources.items())[:2_000]:
                normalized = relative.replace("\\", "/")
                path = PurePosixPath(normalized)
                if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
                    continue
                destination = temp_root.joinpath(*path.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content, encoding="utf-8")
            process = await asyncio.create_subprocess_exec(
                str(self.executable), "scan", "--config", self.ruleset, "--json", "--quiet", "--metrics", "off", str(temp_root),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=180)
            except TimeoutError:
                process.kill()
                await process.wait()
                raise RuntimeError("Semgrep exceeded the 180 second limit")
            if len(stdout) > _MAX_OUTPUT or len(stderr) > _MAX_OUTPUT:
                raise RuntimeError("Semgrep output exceeded the configured safety limit")
            if process.returncode not in (0, 1):
                raise RuntimeError(f"Semgrep failed with exit {process.returncode}: {stderr.decode(errors='replace')[:300]}")
            try:
                payload = json.loads(stdout or b"{}")
            except json.JSONDecodeError as exc:
                raise RuntimeError("Semgrep returned invalid JSON") from exc
            findings: list[ThreatFinding] = []
            for index, result in enumerate(payload.get("results", [])[:1_000]):
                if not isinstance(result, dict):
                    continue
                extra = result.get("extra", {}) if isinstance(result.get("extra"), dict) else {}
                metadata = extra.get("metadata", {}) if isinstance(extra.get("metadata"), dict) else {}
                raw_path = str(result.get("path", ""))
                try:
                    relative = Path(raw_path).resolve().relative_to(temp_root.resolve()).as_posix()
                except ValueError:
                    continue
                raw_cwe = metadata.get("cwe", "CWE-20")
                if isinstance(raw_cwe, list):
                    raw_cwe = raw_cwe[0] if raw_cwe else "CWE-20"
                severity = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}.get(
                    str(extra.get("severity", "WARNING")).upper(), Severity.MEDIUM
                )
                line = int((result.get("start") or {}).get("line", 1))
                rule_id = str(result.get("check_id", f"rule-{index + 1}"))
                findings.append(ThreatFinding(
                    finding_id=f"SEMGREP-{rule_id}-{relative}-{line}"[:128],
                    summary=str(extra.get("message") or f"Semgrep rule {rule_id} matched")[:4000],
                    cwe=str(raw_cwe)[:64], severity=severity, affected_nodes=[relative],
                    evidence=[f"line {max(line, 1)}: deterministic Semgrep rule {rule_id}"],
                ))
            return findings
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)


__all__ = ["SemgrepAgent"]
