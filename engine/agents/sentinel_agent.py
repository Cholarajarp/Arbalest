"""Sentinel Agent for Runtime Application Self-Protection (RASP).

Monitors live WAF logs or incoming HTTP traffic streams to detect novel,
zero-day AI-generated payloads in real-time. Correlates attacks directly
to the Neo4j Architecture Graph and triggers emergency remediation.
"""

import json
import logging

from pydantic import BaseModel, Field

from engine.agents.architect_agent import ThreatFinding, Severity, ArchitectureGraphContext
from engine.services.ai_provider import AIProvider, StructuredOutputRequest

logger = logging.getLogger(__name__)


class TrafficEvent(BaseModel):
    """A single intercepted HTTP request or WAF log."""
    source_ip: str
    method: str
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    timestamp: str = ""


class SentinelFinding(BaseModel):
    """The result of analyzing a traffic event."""
    is_malicious: bool = Field(description="True if the traffic contains a known or novel exploit payload")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score of the classification")
    threat_type: str = Field(description="CWE category or descriptive threat name (e.g., SQLi, Path Traversal)")
    reasoning: str = Field(description="Explanation of why this payload was flagged")
    affected_route: str = Field(description="The API route or path targeted by the payload")
    extracted_payload: str = Field(description="The specific string or object containing the malicious vector")


class SentinelAgent:
    """Analyzes live production traffic to detect attacks."""

    def __init__(self, provider: AIProvider) -> None:
        self._provider = provider

    async def analyze_traffic(self, event: TrafficEvent, graph_context: ArchitectureGraphContext) -> ThreatFinding | None:
        """Analyze a live traffic event against the known architecture graph."""
        logger.info("SentinelAgent analyzing traffic event on %s", event.path)
        
        # Serialize available routes from the graph to give the AI context on the attack surface
        available_routes = [
            {"path": r.path, "method": r.method, "framework": r.framework}
            for r in graph_context.routes
        ]
        
        prompt = f"""You are the Sentinel Agent, a Runtime Application Self-Protection (RASP) AI.
Your objective is to analyze the following incoming HTTP request and determine if it contains an exploit payload.

Traffic Event:
{event.model_dump_json(indent=2)}

Known Architecture Routes (Neo4j Graph):
{json.dumps(available_routes, indent=2)}

Determine if the request is malicious. AI attackers often generate novel, highly-obfuscated payloads. 
If it is malicious, identify the targeted route and extract the exact payload.
"""
        
        request = StructuredOutputRequest(
            input_text=prompt,
            response_schema=SentinelFinding,
            max_output_tokens=1000,
        )
        
        try:
            response = await self._provider.generate_structured(request)
            finding = SentinelFinding.model_validate_json(response)
        except Exception as e:
            logger.error("SentinelAgent failed to analyze traffic: %s", e)
            return None
            
        if not finding.is_malicious or finding.confidence < 0.7:
            return None
            
        logger.warning("SentinelAgent detected live attack: %s on %s", finding.threat_type, finding.affected_route)
        
        # Convert to a standard ThreatFinding so the ArchitectAgent can remediate it
        return ThreatFinding(
            finding_id=f"SENTINEL-{finding.threat_type.replace(' ', '').upper()}",
            severity=Severity.CRITICAL,
            summary=f"Sentinel Agent intercepted live attack: {finding.threat_type} on {event.path}",
            cwe=finding.threat_type,
            affected_nodes=[finding.affected_route],
            evidence=[
                f"Source IP: {event.source_ip}",
                f"Targeted Route: {finding.affected_route}",
                f"Intercepted Payload: {finding.extracted_payload}"
            ]
        )
