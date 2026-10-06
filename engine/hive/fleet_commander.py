"""FleetCommanderAgent — orchestrates cross-repo war-games and fleet remediation.

Given a proven federated blast radius, the commander decides — deterministically,
from real topology — which repositories need what:

* ORIGIN WARGAME: the repository containing the sink fights the full minimax loop.
* DOWNSTREAM WARGAME: a downstream repository that has its own sink findings for
  the same CWE fights its own war-game in an independent sandbox.
* INTEGRATION AUDIT: a downstream repository that merely imports the vulnerable
  code (no sink of its own) is healed transitively by the origin patch; the
  commander verifies its integration with the fleet antibody sweep instead of
  inventing work.

Every order is backed by graph evidence — nothing is dispatched on suspicion.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from engine.immune.detection import DetectionFinding
from engine.hive.federation import FleetTopology


@dataclass
class DispatchOrder:
    repo: str
    kind: str                       # origin | downstream | integration_audit
    finding: DetectionFinding | None
    rationale: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.repo}"


@dataclass
class FleetPlan:
    origin_repo: str
    origin_finding: DetectionFinding
    affected_repos: list[str]
    orders: list[DispatchOrder] = field(default_factory=list)

    @property
    def wargame_orders(self) -> list[DispatchOrder]:
        return [o for o in self.orders if o.kind in {"origin", "downstream"}]

    @property
    def audit_orders(self) -> list[DispatchOrder]:
        return [o for o in self.orders if o.kind == "integration_audit"]


class FleetCommanderAgent:
    """Turns federated topology into a fleet dispatch plan."""

    def plan_response(
        self,
        topology: FleetTopology,
        origin_repo: str,
        finding: DetectionFinding,
        radius,
        findings_by_repo: dict[str, list[DetectionFinding]],
    ) -> FleetPlan:
        plan = FleetPlan(
            origin_repo=origin_repo,
            origin_finding=finding,
            affected_repos=list(radius.affected_repos),
        )
        plan.orders.append(DispatchOrder(
            repo=origin_repo, kind="origin", finding=finding,
            rationale=f"hosts the sink ({finding.rule_id} @ {finding.file}:{finding.line}) — full minimax war-game",
        ))
        for repo in radius.affected_repos:
            if repo == origin_repo:
                continue
            same_cwe = [f for f in findings_by_repo.get(repo, []) if f.cwe == finding.cwe]
            if same_cwe:
                worst = same_cwe[0]
                plan.orders.append(DispatchOrder(
                    repo=repo, kind="downstream", finding=worst,
                    rationale=f"downstream in proven blast radius with its own {worst.cwe} sink — independent war-game",
                ))
            else:
                hops = [
                    n for chain in radius.chains for n in chain
                    if n.get("repo") == repo
                ]
                detail = f"{len(hops)} hop(s) through this repo" if hops else "imports the vulnerable code"
                plan.orders.append(DispatchOrder(
                    repo=repo, kind="integration_audit", finding=None,
                    rationale=f"downstream in blast radius, no sink of its own — {detail}; "
                              "origin patch heals transitively, integration verified by fleet antibody sweep",
                ))
        return plan
