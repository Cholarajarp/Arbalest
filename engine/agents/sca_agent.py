"""Software Composition Analysis (SCA) Agent for identifying known vulnerable dependencies."""

from __future__ import annotations

import logging
from collections.abc import Mapping
import uuid

from pydantic import BaseModel, ConfigDict, Field

from engine.agents.architect_agent import Severity, ThreatFinding
from engine.services.ai_provider import AIProvider, StructuredOutputRequest

logger = logging.getLogger(__name__)


class ScaDependencyVulnerability(BaseModel):
    """A vulnerability found in a dependency file."""
    
    model_config = ConfigDict(extra="forbid")
    
    package_name: str = Field(description="Name of the vulnerable package")
    version: str = Field(description="Version found in the dependency file")
    cve_or_id: str = Field(description="CVE ID or vulnerability identifier, e.g. CVE-2024-1234 or PYSEC-2026-1852")
    severity: Severity = Field(description="Severity of the vulnerability")
    description: str = Field(description="Brief description of the vulnerability")
    affected_file: str = Field(description="The path of the dependency file where this was found")


class ScaAnalysisResult(BaseModel):
    """The structured output from the LLM for SCA."""
    
    model_config = ConfigDict(extra="forbid")
    
    vulnerabilities: list[ScaDependencyVulnerability] = Field(
        description="List of vulnerabilities found in the provided dependency files."
    )


_SCA_SCHEMA = ScaAnalysisResult.model_json_schema()


class ScaAgent:
    """Agent that analyzes dependency manifest files to find known vulnerabilities."""

    def __init__(self, provider: AIProvider) -> None:
        self._provider = provider

    async def analyze(self, legacy_sources: Mapping[str, str]) -> list[ThreatFinding]:
        """Analyze the dependency files in the sources for known vulnerabilities."""
        dependency_files: dict[str, str] = {}
        
        # Look for common dependency files
        target_files = {"requirements.txt", "package.json", "Gemfile", "go.mod", "pom.xml", "Cargo.toml", "pyproject.toml", "setup.cfg", "build.gradle"}
        for file_path, content in legacy_sources.items():
            filename = file_path.split("/")[-1]
            if filename in target_files:
                dependency_files[file_path] = content

        if not dependency_files:
            logger.info("No dependency manifest files found for SCA.")
            return []

        logger.info(f"Analyzing {len(dependency_files)} dependency files for SCA: {list(dependency_files.keys())}")
        
        file_sections = []
        for filepath, content in dependency_files.items():
            file_sections.append(f"--- {filepath} ---\n{content[:16_000]}")
        input_text = "\n\n".join(file_sections)

        try:
            raw = await self._provider.generate_structured(
                StructuredOutputRequest(
                    instructions=(
                        "You are an expert Software Composition Analysis (SCA) tool.\n"
                        "Analyze the following dependency manifest files and identify any packages with known vulnerabilities (CVEs).\n"
                        "Focus on real, well-known CVEs. For each vulnerability, include the package name, version, CVE ID, severity, and a brief description.\n"
                        "Return a JSON object matching the schema."
                    ),
                    input_text=input_text,
                    schema_name="sca-analysis-result",
                    json_schema=_SCA_SCHEMA,
                    max_output_tokens=4_000,
                )
            )
            result = ScaAnalysisResult.model_validate_json(raw)
        except Exception as e:
            # Never masquerade a provider outage as a clean scan — the pipeline
            # degrades per-agent and surfaces the failure in the swarm status.
            logger.warning(f"SCA Agent analysis failed: {e}")
            raise

        threat_findings = []
        for vuln in result.vulnerabilities:
            finding_id = f"SCA-{uuid.uuid4().hex[:8]}"
            threat_findings.append(ThreatFinding(
                finding_id=finding_id,
                cwe=vuln.cve_or_id,
                severity=vuln.severity,
                summary=f"SCA: {vuln.package_name} {vuln.version} — {vuln.cve_or_id}. {vuln.description}",
                affected_nodes=[vuln.affected_file],
                evidence=[f"Found {vuln.package_name} version {vuln.version} in {vuln.affected_file}."]
            ))
            
        return threat_findings
