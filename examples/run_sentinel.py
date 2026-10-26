"""Run the experimental Sentinel traffic-event analyzer with the configured provider.

This example uses synthetic data only. Sentinel is not part of the default
`arbalest scan` command; it demonstrates the current standalone agent API.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from engine.agents.architect_agent import ArchitectureGraphContext, ArchitectureNode  # noqa: E402
from engine.agents.sentinel_agent import SentinelAgent, TrafficEvent  # noqa: E402
from engine.services.runtime import build_provider, load_env_file  # noqa: E402


async def main() -> None:
    repository_root = _REPOSITORY_ROOT
    load_env_file((repository_root, Path.cwd()))
    provider, provider_name, model = build_provider(None, None)
    try:
        event = TrafficEvent(
            source_ip="198.51.100.23",  # RFC 5737 documentation address
            method="GET",
            path="/api/v1/users",
            headers={"User-Agent": "Arbalest-Synthetic-Sentinel-Demo/1.0"},
            body='{"search": "\' OR 1=1 --"}',
            timestamp="2026-01-01T00:00:00Z",
        )
        graph = ArchitectureGraphContext(
            project_id="sentinel-example",
            nodes=[ArchitectureNode(
                id="route:users",
                labels=["Route"],
                properties={"path": "/api/v1/users", "method": "GET", "framework": "synthetic"},
            )],
            edges=[],
        )
        finding = await SentinelAgent(provider).analyze_traffic(event, graph)
        print(f"provider={provider_name} model={model}")
        if finding is None:
            print("verdict=not-malicious")
        else:
            print(finding.model_dump_json(indent=2))
    finally:
        await provider.aclose()


if __name__ == "__main__":
    asyncio.run(main())
