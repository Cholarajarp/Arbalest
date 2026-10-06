"""Static Application Security Testing (SAST) Agent for identifying logic vulnerabilities in source code."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

from engine.agents.architect_agent import Severity, ThreatFinding
from engine.services.ai_provider import AIProvider, StructuredOutputRequest

logger = logging.getLogger(__name__)


class SastVulnerability(BaseModel):
    """A vulnerability found in a source code file."""
    
    model_config = ConfigDict(extra="forbid")
    
    vulnerability_name: str = Field(description="Name of the vulnerability (e.g., Path Traversal, SQL Injection)")
    cwe: str = Field(description="CWE ID, e.g., CWE-22, CWE-89")
    severity: Severity = Field(description="Severity of the vulnerability")
    description: str = Field(description="Detailed description of the logic flaw")
    affected_file: str = Field(description="The path of the source file where this was found")
    evidence: str = Field(description="Snippet or explanation of why the code is vulnerable")


class SastAnalysisResult(BaseModel):
    """The structured output from the LLM for SAST."""
    
    model_config = ConfigDict(extra="forbid")
    
    vulnerabilities: list[SastVulnerability] = Field(
        description="List of logic vulnerabilities found in the provided source code files."
    )


_SAST_SCHEMA = SastAnalysisResult.model_json_schema()


class SastAgent:
    """Agent that analyzes source code files to find logic vulnerabilities."""

    def __init__(self, provider: AIProvider) -> None:
        self._provider = provider

    async def analyze(self, legacy_sources: Mapping[str, str]) -> list[ThreatFinding]:
        """Analyze source files for logic vulnerabilities."""
        source_files: dict[str, str] = {}
        
        # Look for common source and config files that might contain logic flaws
        target_extensions = {".ts", ".js", ".py", ".go", ".rs", ".php", ".java", ".rb"}
        
        for file_path, content in legacy_sources.items():
            if any(file_path.endswith(ext) for ext in target_extensions):
                source_files[file_path] = content

        if not source_files:
            logger.info("No source files found for SAST.")
            return []

        # Bound context size for SAST to prevent massive token usage.
        # Prioritize files that might have routing, config, or sensitive logic
        priority_files = {}
        total_chars = 0
        MAX_CHARS = 40_000
        
        # Simple heuristic: sort files by length (ascending) to fit more context, 
        # but prioritize certain keywords like "config", "route", "app", "main"
        sorted_files = sorted(
            source_files.items(), 
            key=lambda x: (
                0 if any(kw in x[0].lower() for kw in ["config", "route", "app", "main", "server"]) else 1,
                len(x[1])
            )
        )
        
        for filepath, content in sorted_files:
            if total_chars + len(content) > MAX_CHARS and total_chars > 0:
                continue
            priority_files[filepath] = content
            total_chars += len(content)

        logger.info(f"Analyzing {len(priority_files)} source files for SAST: {list(priority_files.keys())}")
        
        file_sections = []
        for filepath, content in priority_files.items():
            file_sections.append(f"--- {filepath} ---\n{content}")
        input_text = "\n\n".join(file_sections)

        try:
            raw = await self._provider.generate_structured(
                StructuredOutputRequest(
                    instructions=(
                        "You are an expert Static Application Security Testing (SAST) tool.\n"
                        "Analyze the following source code and configuration files to identify any critical or high severity logic vulnerabilities.\n"
                        "Focus on OWASP Top 10 issues such as Path Traversal (CWE-22), SQL Injection (CWE-89), Command Injection, XSS, etc.\n"
                        "For each vulnerability, include the vulnerability name, CWE ID, severity, description, affected file, and evidence.\n"
                        "Return a JSON object matching the schema."
                    ),
                    input_text=input_text,
                    schema_name="sast-analysis-result",
                    json_schema=_SAST_SCHEMA,
                    max_output_tokens=4_000,
                )
            )
            result = SastAnalysisResult.model_validate_json(raw)
        except Exception as e:
            # Never masquerade a provider outage as a clean scan — the pipeline
            # degrades per-agent and surfaces the failure in the swarm status.
            logger.warning(f"SAST Agent analysis failed: {e}")
            raise

        threat_findings = []
        for vuln in result.vulnerabilities:
            finding_id = f"SAST-{uuid.uuid4().hex[:8]}"
            threat_findings.append(ThreatFinding(
                finding_id=finding_id,
                cwe=vuln.cwe,
                severity=vuln.severity,
                summary=f"SAST: {vuln.vulnerability_name} — {vuln.cwe}. {vuln.description}",
                affected_nodes=[vuln.affected_file],
                evidence=[vuln.evidence]
            ))
            
        return threat_findings
