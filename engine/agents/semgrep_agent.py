import json
import logging
import asyncio
import tempfile
import os
import shutil

from typing import Mapping

from engine.agents.architect_agent import ThreatFinding, Severity

logger = logging.getLogger(__name__)

class SemgrepAgent:
    """Deterministic static analysis using the Semgrep CLI."""
    
    def __init__(self, ruleset: str = "p/ci"):
        self.ruleset = ruleset

    async def analyze(self, legacy_sources: Mapping[str, str]) -> list[ThreatFinding]:
        """Runs semgrep on the source directory to find known deterministic flaws."""
        if not legacy_sources:
            return []
            
        findings: list[ThreatFinding] = []
        temp_dir = tempfile.mkdtemp(prefix="arbalest_semgrep_")
        
        try:
            # Write sources to disk for Semgrep CLI
            for file_path, content in legacy_sources.items():
                full_path = os.path.join(temp_dir, file_path.lstrip("/"))
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(content)
            
            # Run semgrep subprocess
            cmd = [
                "semgrep", "scan",
                "--config", self.ruleset,
                "--json",
                "--quiet",
                temp_dir
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stdout:
                try:
                    data = json.loads(stdout)
                    results = data.get("results", [])
                    for i, r in enumerate(results):
                        severity_map = {
                            "ERROR": Severity.CRITICAL,
                            "WARNING": Severity.MEDIUM,
                            "INFO": Severity.LOW
                        }
                        sev = severity_map.get(r.get("extra", {}).get("severity", "WARNING"), Severity.MEDIUM)
                        path_str = r.get("path", "")
                        # Remove temp_dir prefix
                        if path_str.startswith(temp_dir):
                            path_str = path_str[len(temp_dir):].lstrip("/\\")
                        
                        f = ThreatFinding(
                            finding_id=f"semgrep-{i+1}",
                            summary=r.get("extra", {}).get("message", "Semgrep Finding"),
                            cwe=r.get("extra", {}).get("metadata", {}).get("cwe", ["Unknown"])[0],
                            severity=sev,
                            evidence=[f"File: {path_str}", f"Line: {r.get('start', {}).get('line', 0)}"],
                            affected_nodes=[]
                        )
                        findings.append(f)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse Semgrep JSON output.")
                    
        except Exception as e:
            logger.error(f"SemgrepAgent failed: {e}")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            
        return findings
