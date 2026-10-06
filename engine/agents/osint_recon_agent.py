"""OSINT Recon Agent.

Autonomously simulates the recon phase of a threat actor by mapping out the
external attack surface of a target SaaS via public APIs (DNS, WHOIS, Shodan).
Outputs ThreatFindings for external footprint weaknesses.
"""

import asyncio
import logging
import socket
from urllib.parse import urlparse

from engine.agents.architect_agent import ThreatFinding, Severity
from engine.services.ai_provider import AIProvider

logger = logging.getLogger(__name__)


class OsintReconAgent:
    """Discovers external attack surface weaknesses before an AI attacker does."""

    def __init__(self, provider: AIProvider) -> None:
        self._provider = provider

    async def analyze_target(self, target_url: str) -> list[ThreatFinding]:
        """Perform OSINT recon on a target URL."""
        logger.info("OsintReconAgent beginning external attack surface mapping for %s", target_url)
        findings: list[ThreatFinding] = []
        
        parsed = urlparse(target_url)
        domain = parsed.hostname
        if not domain or domain in ("localhost", "127.0.0.1") or domain.endswith(".internal") or domain.endswith(".invalid"):
            logger.info("Skipping OSINT for local or internal domain: %s", domain)
            return findings

        # 1. DNS Recon (Simulated basic check)
        try:
            # We run this in an executor to avoid blocking the async event loop
            ip_address = await asyncio.get_running_loop().run_in_executor(None, socket.gethostbyname, domain)
            logger.info("Resolved %s to %s", domain, ip_address)
            
            # In a real implementation, we would query Shodan API or a certificate transparency log here.
            # For demonstration, we will emit an informational finding about the exposed infrastructure.
            findings.append(
                ThreatFinding(
                    finding_id="OSINT-DNS-RECON",
                    severity=Severity.INFO,
                    summary=f"External footprint mapped. Domain {domain} resolves to {ip_address}.",
                    cwe="CWE-200",  # Information Exposure
                    affected_nodes=[],  # External infrastructure, not a local code node
                    evidence=[
                        f"Target Domain: {domain}",
                        f"Resolved IP: {ip_address}",
                        "Note: Ensure this IP is protected by a WAF and not exposing direct management ports (SSH/RDP)."
                    ]
                )
            )
        except Exception as e:
            logger.warning("DNS resolution failed for OSINT recon: %s", e)

        # 2. Open-Source Intelligence Synthesis (AI-driven)
        # If we had access to GitHub search logs or leaked credentials, we would pass them to the AIProvider here.
        # This lays the architectural foundation for the external threat pipeline.
        
        return findings
