"""FleetPatternExchange — global-registry antibody sharing for the ImmuneSystemAgent.

The per-organism ``ImmuneSystemAgent`` synthesizes a read-only detection
pattern from a confirmed exploit. The exchange is its fleet-grade upgrade:

* ``publish`` records the pattern in the HiveRegistry (global memory) and
  fans it out to every reachable Neo4j threat graph — one pattern, every
  organism's graph memory.
* ``outstanding`` / ``acknowledge`` implement P2P sync: repositories pull
  patterns they have not yet incorporated and acknowledge integration.

Every record is bounded, read-only, and derived from real sandbox evidence.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from engine.hive.registry import HiveRegistry

logger = logging.getLogger("arbalest.hive.exchange")


@dataclass
class BroadcastReceipt:
    pattern_id: str
    registry_path: str
    graphs_updated: list[str] = field(default_factory=list)
    graph_errors: list[str] = field(default_factory=list)


class FleetPatternExchange:
    def __init__(self, registry: HiveRegistry) -> None:
        self._registry = registry

    async def publish(
        self,
        *,
        threat_name: str,
        cwe_category: str,
        cypher_pattern: str,
        origin_repo: str,
        source_finding: str,
        graph_managers: list[tuple[str, Any]] | None = None,
    ) -> BroadcastReceipt:
        """Persist a learned pattern globally and fan out to reachable graphs."""
        pattern_id = f"pattern-{uuid.uuid4().hex[:10]}"
        record = {
            "pattern_id": pattern_id,
            "threat_name": threat_name,
            "cwe_category": cwe_category,
            "cypher_pattern": cypher_pattern,
            "origin_repo": origin_repo,
            "source_finding": source_finding[:200],
            "published_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "acknowledged_by": [origin_repo],
        }
        self._registry.save_pattern(record)

        receipt = BroadcastReceipt(pattern_id=pattern_id, registry_path=str(self._registry._patterns_path))
        for label, manager in (graph_managers or []):
            try:
                await manager.add_vulnerability_pattern(
                    project_id=f"fleet:{label}",
                    threat_name=threat_name,
                    cwe_category=cwe_category,
                    cypher_pattern=cypher_pattern,
                )
                receipt.graphs_updated.append(label)
            except Exception as exc:  # noqa: BLE001 — one offline graph never blocks the fleet
                receipt.graph_errors.append(f"{label}: {exc}")
                logger.warning("graph fan-out failed for %s: %s", label, exc)
        return receipt

    def outstanding(self, repo: str) -> list[dict[str, Any]]:
        return self._registry.outstanding_for(repo)

    def acknowledge(self, repo: str, pattern_id: str) -> bool:
        return self._registry.acknowledge(repo, pattern_id)
