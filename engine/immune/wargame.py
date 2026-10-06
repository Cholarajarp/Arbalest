"""The Minimax Loop — adversarial war-gaming inside the Nebius Token Factory Sandbox.

Architect and Red Team no longer run sequentially. Each iteration:

    Architect drafts a patch  →  Red Team writes a custom Bash harness to
    breach it  →  Architect reads the sandbox failure evidence and repairs  → …

The loop terminates only when the Red Team cannot breach the sandboxed patch
(conservative verdict) or when the iteration budget is spent. Every red-team
result in the breach history is real sandbox evidence — nothing is simulated.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from engine.agents.architect_agent import (
    ArchitectureGraphContext,
    ArchitectAgent,
    CodeLanguage,
    MutationPlan,
    Severity,
    ThreatFinding,
)
from engine.agents.polyglot_translator import GeneratedCodeBundle, PolyglotTranslator
from engine.agents.red_team_swarm import RedTeamResult, RedTeamSwarm
from engine.services.docker_manager import DockerSandboxManager

logger = logging.getLogger("arbalest.wargame")

LogLine = Callable[[str], None]


class WargameError(RuntimeError):
    """The war-game could not be executed (sandbox, provider, or budget failure)."""


@dataclass
class WargameIteration:
    index: int                    # 1-based
    action: str                   # initial | repair
    language: str
    files: list[str]
    attack_objective: str = ""
    exploit_successful: bool = False
    inconclusive: bool = False
    sandbox_status: str = ""
    sandbox_exit_code: int | None = None
    reasoning: str = ""
    evidence: list[str] = field(default_factory=list)
    verdict: str = ""


@dataclass
class WargameResult:
    resolved: bool                          # final patch survived the swarm
    iterations: list[WargameIteration] = field(default_factory=list)
    final_bundle: GeneratedCodeBundle | None = None
    final_plan: MutationPlan | None = None
    breach_history: list[dict[str, Any]] = field(default_factory=list)
    last_result: RedTeamResult | None = None
    last_breach: RedTeamResult | None = None   # last confirmed successful exploit


class WargameEngine:
    """Compose ArchitectAgent + PolyglotTranslator + RedTeamSwarm as a minimax loop."""

    def __init__(
        self,
        *,
        provider,
        sandbox: DockerSandboxManager,
        max_iterations: int = 4,
        left_log: LogLine | None = None,
        right_log: LogLine | None = None,
    ) -> None:
        if max_iterations < 1:
            raise ValueError("max_iterations must be >= 1")
        self._provider = provider
        self._sandbox = sandbox
        self._max_iterations = max_iterations
        self._left = left_log or (lambda _line: None)
        self._right = right_log or (lambda _line: None)

    async def run(self, sources: dict[str, str], finding: ThreatFinding) -> WargameResult:
        result = WargameResult()
        architect = ArchitectAgent(provider=self._provider)
        translator = PolyglotTranslator(provider=self._provider)
        red_team = RedTeamSwarm(sandbox=self._sandbox, provider=self._provider)

        for iteration in range(1, self._max_iterations + 1):
            if iteration == 1:
                self._left(f"iter {iteration}: ARCHITECT-01 drafting mutation plan for {finding.cwe}")
                plan = await architect.create_plan(
                    graph_context=ArchitectureGraphContext(project_id="immune-wargame", nodes=[], edges=[]),
                    findings=[finding],
                    developer_task=(
                        f"Eradicate {finding.cwe} ({finding.summary[:200]}) proven reachable from the "
                        f"public API surface. Enforce the fix at the sink and harden the full attack chain."
                    ),
                    available_files=sources,
                    target_language=CodeLanguage.AUTO,
                )
                self._left(f"iter {iteration}: plan {plan.plan_id} — {len(plan.mutations)} mutation(s) "
                           f"→ {plan.target_language.value}")
                for mutation in plan.mutations[:6]:
                    self._left(f"  ▸ {mutation.action.value} {mutation.target_file}: {mutation.rationale[:90]}")
                self._left(f"iter {iteration}: POLYGLOT forging {plan.target_language.value} bundle")
                bundle = await translator.translate(legacy_sources=sources, mutation_plan=plan)
                action = "initial"
            else:
                self._left(f"iter {iteration}: ARCHITECT-01 reads breach evidence from iteration {iteration - 1}")
                bundle = await translator.repair_after_verification(
                    candidate=result.final_bundle,  # type: ignore[arg-type]
                    mutation_plan=result.final_plan,  # type: ignore[arg-type]
                    verification_evidence=result.breach_history[-1],
                )
                self._left(f"iter {iteration}: repaired bundle forged — {len(bundle.files)} file(s), "
                           f"countermeasure targeting the demonstrated bypass")
                action = "repair"

            result.final_bundle = bundle
            result.final_plan = plan if iteration == 1 else result.final_plan
            record = WargameIteration(
                index=iteration, action=action, language=bundle.language.value,
                files=[f.path for f in bundle.files],
            )
            self._left(f"iter {iteration}: bundle ready — {record.files}")

            self._right(f"iter {iteration}: REDTEAM-SWARM crafting breach harness "
                        f"({len(result.breach_history)} prior breach(es) on record)")
            red_team_result = await red_team.execute(
                generated_code=bundle,
                mutation_plan=plan if iteration == 1 else result.final_plan,  # type: ignore[arg-type]
                findings=[finding],
                log_sink=self._sandbox_sink(iteration),
                adversary_history=result.breach_history or None,
            )
            result.last_result = red_team_result
            record.attack_objective = red_team_result.attack.objective
            record.exploit_successful = red_team_result.analysis.exploit_successful
            record.inconclusive = red_team_result.analysis.inconclusive
            record.sandbox_status = red_team_result.sandbox.status.value
            record.sandbox_exit_code = red_team_result.sandbox.exit_code
            record.reasoning = red_team_result.analysis.reasoning
            record.evidence = list(red_team_result.analysis.evidence[:6])

            if red_team_result.deployment_allowed:
                record.verdict = "PATCH HELD — swarm repelled"
                self._right(f"iter {iteration}: ✗ BREACH FAILED — patch held ({record.sandbox_status})")
                result.iterations.append(record)
                result.resolved = True
                return result

            if red_team_result.analysis.inconclusive:
                record.verdict = "INCONCLUSIVE — deployment blocked"
                self._right(f"iter {iteration}: ? inconclusive — {record.reasoning[:120]}")
                result.iterations.append(record)
                return result

            record.verdict = "BREACHED — architect must counter"
            self._right(f"iter {iteration}: ✓ BREACH — {record.attack_objective[:110]}")
            for ev in record.evidence[:3]:
                self._right(f"    evidence: {ev[:110]}")
            result.iterations.append(record)
            result.last_breach = red_team_result
            result.breach_history.append(_bounded_breach(iteration, record, red_team_result))
            logger.info("Wargame iteration %d breached: %s", iteration, record.attack_objective[:120])

        self._left(f"iteration budget exhausted ({self._max_iterations}) — patch rejected")
        return result

    def _sandbox_sink(self, iteration: int) -> Callable[[str, str], Awaitable[None]]:
        async def sink(stream: str, chunk: str) -> None:
            for line in chunk.rstrip().splitlines():
                self._right(f"    [{stream}] {line[:140]}")

        return sink


def _bounded_breach(
    iteration: int, record: WargameIteration, red_team_result: RedTeamResult
) -> dict[str, Any]:
    """Bounded adversary record fed back into both sides of the next debate turn."""
    return {
        "iteration": iteration,
        "attack_objective": record.attack_objective[:2_000],
        "attack_script": red_team_result.attack.content[:6_000],
        "success_marker": red_team_result.attack.success_marker,
        "exploit_successful": record.exploit_successful,
        "reasoning": record.reasoning[:2_000],
        "evidence": record.evidence,
        "sandbox": {
            "status": record.sandbox_status,
            "exit_code": record.sandbox_exit_code,
            "stdout": red_team_result.sandbox.stdout[:8_000],
            "stderr": red_team_result.sandbox.stderr[:8_000],
        },
    }


def finding_from_detection(finding, blast_summary: dict[str, object] | None = None) -> ThreatFinding:
    """Convert a deterministic detection finding into the engine's ThreatFinding."""
    summary = f"{finding.name} at {finding.file}:{finding.line}"
    if blast_summary:
        summary += f" — {blast_summary.get('verdict', '')}"
    return ThreatFinding(
        finding_id=f"IMMUNE-{finding.rule_id}-{finding.file.replace('/', '_')}-{finding.line}",
        cwe=finding.cwe,
        severity=Severity(finding.severity),
        summary=summary[:4_000],
        affected_nodes=[finding.file],
        evidence=[finding.evidence[:1_000], finding.hint][:50] if finding.hint else [finding.evidence[:1_000]],
    )
