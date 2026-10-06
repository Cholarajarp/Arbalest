"""Secret Scanner Agent for identifying hardcoded credentials and tokens in the codebase."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
import uuid

from pydantic import BaseModel, ConfigDict, Field

from engine.agents.architect_agent import Severity, ThreatFinding
from engine.services.ai_provider import AIProvider, StructuredOutputRequest

logger = logging.getLogger(__name__)


class HardcodedSecret(BaseModel):
    """A hardcoded secret found in a source file."""
    
    model_config = ConfigDict(extra="forbid")
    
    secret_type: str = Field(description="The type of secret found (e.g. 'AWS Access Key', 'Database Password', 'API Token')")
    affected_file: str = Field(description="The file where the secret was found")
    line_snippet: str = Field(description="A short snippet of the code containing the secret (masking the actual secret value)")
    severity: Severity = Field(description="Severity of the exposed secret (usually CRITICAL or HIGH)")
    description: str = Field(description="Brief explanation of why this secret is dangerous")


class SecretAnalysisResult(BaseModel):
    """The structured output from the LLM for Secret Scanning."""
    
    model_config = ConfigDict(extra="forbid")
    
    secrets: list[HardcodedSecret] = Field(
        description="List of hardcoded secrets found in the codebase."
    )


_SECRET_SCHEMA = SecretAnalysisResult.model_json_schema()


class SecretScannerAgent:
    """Agent that scans source code for hardcoded secrets using regex heuristics and LLM verification."""

    def __init__(self, provider: AIProvider) -> None:
        self._provider = provider

        # Basic regex heuristics to find files worth sending to the LLM (to save tokens)
        self._heuristics = [
            re.compile(r"(?i)(api[_-]?key|secret|password|token|credentials|auth)[\s:=]+[\"'][a-zA-Z0-9_\-\+=\/]{8,}[\"']"),
            re.compile(r"AKIA[0-9A-Z]{16}"), # AWS Access Key
            re.compile(r"ghp_[a-zA-Z0-9]{36}"), # GitHub Personal Access Token
            re.compile(r"-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----"), # Private Keys
            re.compile(r"postgres://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@"), # Postgres connection string
            re.compile(r"mongodb(\+srv)?://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@"), # MongoDB connection string
            re.compile(r"(?i)(sk-|sk_live_|sk_test_)[a-zA-Z0-9]{20,}"),  # Stripe/OpenAI keys
            re.compile(r"(?i)bearer\s+[a-zA-Z0-9._\-]{20,}"),  # Bearer tokens
        ]

    def _might_contain_secrets(self, content: str) -> bool:
        """Check if the content triggers any secret regex heuristics."""
        for pattern in self._heuristics:
            if pattern.search(content):
                return True
        return False

    async def analyze(self, legacy_sources: Mapping[str, str]) -> list[ThreatFinding]:
        """Analyze the source files for hardcoded secrets."""
        suspicious_files: dict[str, str] = {}
        
        for file_path, content in legacy_sources.items():
            # Skip likely binary or very large files
            if len(content) > 100_000:
                continue
            
            # Skip dependency manifests (SCA handles these) and lockfiles
            if any(file_path.endswith(ext) for ext in [".lock", "package-lock.json", "yarn.lock"]):
                continue

            if self._might_contain_secrets(content):
                suspicious_files[file_path] = content

        if not suspicious_files:
            logger.info("No suspicious files found for Secret Scanning.")
            return []

        logger.info(f"Analyzing {len(suspicious_files)} suspicious files for secrets.")
        
        file_sections = []
        for filepath, content in suspicious_files.items():
            file_sections.append(f"--- {filepath} ---\n{content[:16_000]}")
        input_text = "\n\n".join(file_sections)

        try:
            raw = await self._provider.generate_structured(
                StructuredOutputRequest(
                    instructions=(
                        "You are an expert DevSecOps Secret Scanner tool.\n"
                        "Analyze the following source code files and identify any hardcoded secrets "
                        "(API keys, passwords, tokens, private keys, connection strings, etc.).\n"
                        "Return a list of secrets found. IMPORTANT: In the line_snippet, you MUST mask "
                        "the actual secret value (e.g. 'api_key = \"AKIA********\"'). Do not return the "
                        "raw secret in the JSON output.\n"
                        "Return a JSON object matching the schema."
                    ),
                    input_text=input_text,
                    schema_name="secret-analysis-result",
                    json_schema=_SECRET_SCHEMA,
                    max_output_tokens=4_000,
                )
            )
            result = SecretAnalysisResult.model_validate_json(raw)
        except Exception as e:
            # Never masquerade a provider outage as a clean scan — the pipeline
            # degrades per-agent and surfaces the failure in the swarm status.
            logger.warning(f"Secret Scanner Agent analysis failed: {e}")
            raise

        threat_findings = []
        for secret in result.secrets:
            finding_id = f"SECRET-{uuid.uuid4().hex[:8]}"
            threat_findings.append(ThreatFinding(
                finding_id=finding_id,
                cwe="CWE-798",  # Use of Hard-coded Credentials
                severity=secret.severity,
                summary=f"Hardcoded {secret.secret_type} in {secret.affected_file}: {secret.description}",
                affected_nodes=[secret.affected_file],
                evidence=[f"Found masked secret: `{secret.line_snippet}`"]
            ))
            
        return threat_findings
