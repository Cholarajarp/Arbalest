"""Example of using Sentinel Agent to ingest a WAF log and trigger Arbalest."""

import asyncio
import os
from engine.agents.sentinel_agent import TrafficEvent, SentinelAgent
from engine.services.ai_provider import CustomOpenAICompatibleProvider, AIProviderSettings

async def main():
    # 1. Simulate a malicious payload hitting your live SaaS API
    # This could be piped directly from an AWS WAF, Cloudflare Logpush, or Nginx access.log
    malicious_event = TrafficEvent(
        source_ip="198.51.100.23",
        method="POST",
        path="/api/v1/user/update_profile",
        headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"},
        body='{"username": "admin", "bio": "test", "role": "admin"}' # Mass Assignment / IDOR attempt
    )
    
    # 2. Initialize the Sentinel Agent with your enterprise custom AI provider
    settings = AIProviderSettings(
        provider="meta",
        api_key=os.environ.get("AI_API_KEY", "dummy-key-123"),
        selected_model="meta/llama-3.1-70b-instruct"
    )
    provider = CustomOpenAICompatibleProvider(settings=settings)
    sentinel = SentinelAgent(provider=provider)
    
    print(f"[*] Sentinel Agent initialized: {sentinel.__class__.__name__}. Monitoring live traffic...")
    print(f"[*] Intercepted payload from {malicious_event.source_ip} on {malicious_event.path}")
    
    # 3. If running in a real environment, you would pass this event into run_pipeline
    # which we updated in arbalest_master_loop.py to ingest traffic_events directly.
    print("[*] Forwarding to Arbalest Orchestrator to generate an emergency hotfix...")
    
    # Example pseudo-code for calling the orchestrator:
    # async for event in run_pipeline(
    #     target_url="https://production-saas.internal",
    #     engagement_id="RASP-HOTFIX-001",
    #     sentinel_agent=sentinel,
    #     traffic_events=[malicious_event],
    #     ...
    # ):
    #     print(event)

if __name__ == "__main__":
    asyncio.run(main())
