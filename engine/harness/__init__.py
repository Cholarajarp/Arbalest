"""Arbalest Agent Harness — defense-in-depth for AI security agents.

The harness treats three facts as axioms:
1. Every scanned repository is HOSTILE until proven otherwise. Its source,
   READMEs, and output can carry prompt-injection payloads aimed at the
   agents reading them (a "clean bill of health" social-engineering attack
   on the scanner itself).
2. Every agent-issued action is UNTRUSTED until a policy gateway approves it.
3. Every verdict that matters is auditable. The mission ledger is a
   tamper-evident, hash-chained record of what the swarm did and why.

Modules:
- injection_defense: detection + neutralization of prompt/terminal injection.
- action_gateway: deny-by-default policy gate for agent-generated commands.
- mission_ledger: append-only hash-chained audit trail.
"""

from engine.harness.action_gateway import ActionGateway, GatewayVerdict
from engine.harness.injection_defense import (
    InjectionHit,
    sanitize_for_terminal,
    scan_untrusted,
    wrap_untrusted,
)
from engine.harness.mission_ledger import LedgerEntry, MissionLedger

__all__ = [
    "ActionGateway",
    "GatewayVerdict",
    "InjectionHit",
    "LedgerEntry",
    "MissionLedger",
    "sanitize_for_terminal",
    "scan_untrusted",
    "wrap_untrusted",
]
