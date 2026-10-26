"""Sandbox-only adversarial validation of generated Rust and Go code."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from engine.agents.architect_agent import MutationPlan, ThreatFinding
from engine.agents.polyglot_translator import GeneratedCodeBundle
from engine.harness.action_gateway import ActionGateway
from engine.services.ai_provider import AIProvider, AIProviderError, AIProviderRefusal, StructuredOutputRequest
from engine.services.docker_manager import (
    SandboxBackend,
    SandboxResult,
    SandboxRunSpec,
    SandboxStatus,
    SandboxValidationError,
)

logger = logging.getLogger(__name__)

LogSink = Callable[[str, str], Awaitable[None] | None]
_FORBIDDEN_ATTACK_TOKENS = re.compile(
    r"(?i)"
    r"(?:^|[;&|]\s*)(?:ssh|telnet|sudo|kubectl)\s"
    r"|(?:^|[;&|]\s*)docker\s+(?:run|exec|pull|build)"
    r"|(?:^|[;&|]\s*)mount\s+-"
    # Recursive deletes are allowed only inside the sandbox's own scratch
    # areas (the workspace and /tmp); any other absolute target is refused.
    r"|rm\s+-[a-z]*r[a-z]*\s+(?:-\S+\s+)*/(?!run/arbalest-build/|tmp/)"
    r"|/etc/(?:passwd|shadow)",
    re.MULTILINE,
)
_GATEWAY = ActionGateway()
_MEANINGFUL_PROBE = re.compile(
    r"(?im)\b(?:grep|pytest|python|node|npm\s+test|go\s+test|cargo\s+test|test|\[)\b"
)

# Fixed literal every harness must print once all of its checks have actually
# run. Its absence means the harness itself failed (build error, crash, refusal
# stub), which is *inconclusive* and must never be read as "the patch held".
HARNESS_COMPLETED_MARKER = "ARBALEST_HARNESS_COMPLETED"
_DETERMINISTIC_FILENAME = "arbalest-deterministic-probe.sh"

# Refusal markers: when the provider declines to draft an attack harness the
# mission degrades to a deterministic probe instead of failing. Arbalest never
# attempts to circumvent a provider's safety systems.
_REFUSAL_MARKERS = re.compile(
    r"(?i)\bi (?:cannot|can't|won't|will not|am unable to)\b"
    r"|\bi'm unable\b|\bcannot assist\b|\bnot able to help\b"
    r"|\bI can't help with\b"
)


class RedTeamError(RuntimeError):
    """The adversarial validation could not be safely executed or assessed."""


class AttackLanguage(StrEnum):
    BASH = "bash"
    PYTHON = "python"


class AttackScript(BaseModel):
    """Strict attack artifact that is mounted only inside the isolated runner."""

    model_config = ConfigDict(extra="forbid")

    language: AttackLanguage
    filename: str = Field(min_length=1, max_length=256)
    content: str = Field(min_length=1, max_length=64_000)
    success_marker: str = Field(min_length=8, max_length=128)
    objective: str = Field(min_length=1, max_length=2_000)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or ":" in normalized or any(part in {"", ".", ".."} for part in normalized.split("/")):
            raise ValueError("Attack filename must be a safe relative path")
        return normalized


class AttackAnalysis(BaseModel):
    """Structured verdict. Inconclusive results must block auto-deployment."""

    model_config = ConfigDict(extra="forbid")

    exploit_successful: bool
    inconclusive: bool
    reasoning: str = Field(min_length=1, max_length=4_000)
    evidence: list[str] = Field(max_length=20)
    confidence: float = Field(ge=0.0, le=1.0)


@dataclass(frozen=True, slots=True)
class RedTeamResult:
    attack: AttackScript
    sandbox: SandboxResult
    analysis: AttackAnalysis

    @property
    def harness_completed(self) -> bool:
        """True only when the harness ran to completion inside the sandbox."""
        return self.sandbox.succeeded and HARNESS_COMPLETED_MARKER in self.sandbox.stdout

    @property
    def exploit_marker_seen(self) -> bool:
        transcript = f"{self.sandbox.stdout}\n{self.sandbox.stderr}"
        return self.attack.success_marker in transcript

    @property
    def verification_held(self) -> bool:
        """The harness completed and observed no evidence that the exploit survived."""
        return (
            self.harness_completed
            and not self.exploit_marker_seen
            and not self.analysis.exploit_successful
            and not self.analysis.inconclusive
        )

    @property
    def verification_tier(self) -> str:
        if self.attack.filename == _DETERMINISTIC_FILENAME:
            return "signature-only"
        if self.analysis.confidence < 0.7:
            return "limited-adversarial"
        return "adversarial"

    @property
    def deployment_allowed(self) -> bool:
        """Require strong adversarial evidence before any source write or delivery."""
        return self.verification_held and self.verification_tier == "adversarial"

    @property
    def automated_deployment_allowed(self) -> bool:
        """Backward-compatible explicit name for the strong deployment gate."""
        return self.deployment_allowed


class RedTeamSwarm:
    """Generate local attack harnesses and assess only sandbox-observed behavior."""

    def __init__(
        self,
        *,
        sandbox: SandboxBackend,
        provider: AIProvider,
    ) -> None:
        self._sandbox = sandbox
        self._provider = provider

    async def aclose(self) -> None:
        """Compatibility no-op; the application owns the injected provider."""

    async def execute(
        self,
        *,
        generated_code: GeneratedCodeBundle,
        mutation_plan: MutationPlan,
        findings: list[ThreatFinding],
        log_sink: LogSink | None = None,
        adversary_history: list[dict[str, Any]] | None = None,
    ) -> RedTeamResult:
        """Attack generated code locally; no external host is reachable from the runner.

        adversary_history — bounded record of previous wargame iterations
        (breached patches, successful attacks, sandbox evidence). Each prior
        breach forces this attack generation to craft a *different* exploit;
        this is the multi-turn debate protocol.
        """
        if not findings:
            raise ValueError("Red-team validation needs at least one target finding")
        attack = await self._generate_attack(generated_code, mutation_plan, findings, adversary_history)
        sandbox_result = await _execute_attack_in_sandbox(
            self._sandbox,
            generated_code,
            attack,
            log_sink=log_sink,
        )
        analysis = await self._analyze(attack, generated_code, mutation_plan, findings, sandbox_result)
        analysis = _enforce_conservative_verdict(attack, sandbox_result, analysis)
        result = RedTeamResult(attack=attack, sandbox=sandbox_result, analysis=analysis)

        # Execution feedback loop: when the harness itself failed to run to
        # completion (crash, timeout, missing marker) the verdict is
        # inconclusive for infrastructure reasons. Feed the sandbox output
        # back and let the model refine the harness ONCE. Refusals are still
        # respected — refinement never rewords a declined request.
        if (
            attack.filename != _DETERMINISTIC_FILENAME
            and (not result.harness_completed or analysis.inconclusive)
            and not analysis.exploit_successful
        ):
            refined = await self._refine_attack(
                generated_code, mutation_plan, findings, attack, sandbox_result,
            )
            if refined is not None:
                retry_sandbox = await _execute_attack_in_sandbox(
                    self._sandbox, generated_code, refined, log_sink=log_sink,
                )
                retry_analysis = await self._analyze(
                    refined, generated_code, mutation_plan, findings, retry_sandbox,
                )
                retry_analysis = _enforce_conservative_verdict(refined, retry_sandbox, retry_analysis)
                retry_result = RedTeamResult(attack=refined, sandbox=retry_sandbox, analysis=retry_analysis)
                if retry_result.harness_completed:
                    logger.info("Red-team harness refined after execution feedback; retry completed")
                    return retry_result
                logger.info("Refined red-team harness still did not complete; keeping conservative result")

        logger.info(
            "Red-team sandbox completed",
            extra={
                "status": sandbox_result.status.value,
                "exploit_successful": analysis.exploit_successful,
                "inconclusive": analysis.inconclusive,
            },
        )
        return result

    async def _refine_attack(
        self,
        generated_code: GeneratedCodeBundle,
        mutation_plan: MutationPlan,
        findings: list[ThreatFinding],
        failed_attack: AttackScript,
        sandbox_result: SandboxResult,
    ) -> AttackScript | None:
        """One execution-feedback refinement of a harness that failed to run."""
        transcript = f"{sandbox_result.stdout}\n{sandbox_result.stderr}"[:8_000]
        try:
            raw = await self._request(
                instructions=(
                    _attack_instructions(generated_code.language.value)
                    + "\n\nYour previous attack harness failed to run correctly inside the sandbox "
                    "(crash, import error, nonzero exit, or no conclusive result). A harness must exit 0 "
                    "and print the completion marker whenever it ran its test, whether the exploit "
                    "succeeded or not. "
                    "Using the execution output below, rewrite the harness so it runs cleanly, always "
                    "prints the completion marker on its own line at the end (including on failure "
                    "paths), and stays within the stated policy. This is the same authorized "
                    "verification mission; it is a harness bug fix, not a new attack."
                ),
                input=json.dumps(
                    {
                        "generated_code": generated_code.model_dump(mode="json"),
                        "mutation_plan": mutation_plan.model_dump(mode="json"),
                        "findings": [finding.model_dump(mode="json") for finding in findings],
                        "failed_harness": failed_attack.model_dump(mode="json"),
                        "execution_output": transcript,
                    },
                    separators=(",", ":"),
                ),
                text=_attack_script_format(),
                max_output_tokens=16_000,
            )
        except AIProviderRefusal:
            logger.info("Provider declined harness refinement; keeping the original result")
            return None
        try:
            refined = AttackScript.model_validate_json(raw)
        except ValidationError:
            logger.info("Refined harness was not valid JSON; keeping the original result")
            return None
        try:
            _validate_attack(refined, generated_code)
        except RedTeamError as exc:
            corrected = await self._correct_rejected_attack(generated_code, findings, refined, str(exc))
            if corrected is None:
                logger.info("Refined harness rejected by policy: %s", exc)
            return corrected
        return refined

    async def _generate_attack(
        self,
        generated_code: GeneratedCodeBundle,
        mutation_plan: MutationPlan,
        findings: list[ThreatFinding],
        adversary_history: list[dict[str, Any]] | None = None,
    ) -> AttackScript:
        source_json = json.dumps(generated_code.model_dump(mode="json"), separators=(",", ":"))
        if len(source_json) > 180_000:
            raise RedTeamError("Generated code bundle exceeds the red-team context budget")
        instructions = _attack_instructions(generated_code.language.value)
        if adversary_history:
            instructions += _debate_instructions()
        try:
            raw = await self._request(
                instructions=instructions,
                input=json.dumps(
                    {
                        "generated_code": generated_code.model_dump(mode="json"),
                        "mutation_plan": mutation_plan.model_dump(mode="json"),
                        "findings": [finding.model_dump(mode="json") for finding in findings],
                        **({"adversary_history": adversary_history} if adversary_history else {}),
                    },
                    separators=(",", ":"),
                ),
                text=_attack_script_format(),
                max_output_tokens=16_000,
            )
        except AIProviderRefusal:
            # The provider's safety layer declined. Respect it: do not retry or
            # rephrase around it; fall back to the model-free probe instead.
            logger.info("Provider declined attack drafting; degrading to deterministic harness")
            return _deterministic_attack(findings)
        except RedTeamError as exc:
            if "output-token limit" not in str(exc):
                raise
            logger.warning("Attack draft exceeded the output-token limit; using deterministic probe")
            return _deterministic_attack(findings)
        try:
            attack = AttackScript.model_validate_json(raw)
        except ValidationError:
            try:
                repair = await self._request(
                    instructions="Return only a valid local Bash attack-script JSON object matching the schema.",
                    input=raw[:32_000],
                    text=_attack_script_format(),
                    max_output_tokens=16_000,
                )
            except AIProviderRefusal:
                logger.info("Provider declined attack repair; degrading to deterministic harness")
                return _deterministic_attack(findings)
            try:
                attack = AttackScript.model_validate_json(repair)
            except ValidationError as second_error:
                if _REFUSAL_MARKERS.search(raw) or _REFUSAL_MARKERS.search(repair):
                    logger.info("Provider declined attack drafting; degrading to deterministic harness")
                    return _deterministic_attack(findings)
                raise RedTeamError("Attack-script output failed strict JSON validation") from second_error

        # A syntactically valid model response can still request prohibited
        # host, network, privilege, or destructive operations.  Never run it;
        # use the bounded model-free signature probe instead so an overreaching
        # adversary cannot abort verification of an otherwise valid patch.
        try:
            _validate_attack(attack, generated_code)
        except RedTeamError as exc:
            corrected = await self._correct_rejected_attack(generated_code, findings, attack, str(exc))
            if corrected is not None:
                return corrected
            logger.warning("Generated attack rejected by the policy gateway; using deterministic probe: %s", exc)
            return _deterministic_attack(findings)
        return attack

    async def _correct_rejected_attack(
        self,
        generated_code: GeneratedCodeBundle,
        findings: list[ThreatFinding],
        rejected: AttackScript,
        reason: str,
    ) -> AttackScript | None:
        """One policy-feedback rewrite of a harness the gateway refused to run.

        The corrected harness goes through the same validation; the policy is
        never relaxed, only explained.
        """
        try:
            raw = await self._request(
                instructions=(
                    _attack_instructions(generated_code.language.value)
                    + "\n\nYour previous harness was REJECTED before execution by the sandbox policy gate. "
                    f"Rejection reason: {reason}\nRewrite it so it satisfies every constraint above. "
                    "The gate rejects the literal text anywhere in the script, including inside payload "
                    "strings and comments. "
                    "The policy cannot be bypassed; change the technique instead. Keep the same objective."
                ),
                input=json.dumps(
                    {
                        "generated_code": generated_code.model_dump(mode="json"),
                        "findings": [finding.model_dump(mode="json") for finding in findings],
                        "rejected_harness": rejected.model_dump(mode="json"),
                    },
                    separators=(",", ":"),
                ),
                text=_attack_script_format(),
                max_output_tokens=16_000,
            )
            corrected = AttackScript.model_validate_json(raw)
            _validate_attack(corrected, generated_code)
        except (AIProviderRefusal, ValidationError, RedTeamError) as exc:
            logger.info("Policy-feedback rewrite of the attack harness failed: %s", _compact_error(exc))
            return None
        logger.info("Attack harness rewritten after policy feedback; running the corrected harness")
        return corrected

    async def _analyze(
        self,
        attack: AttackScript,
        generated_code: GeneratedCodeBundle,
        mutation_plan: MutationPlan,
        findings: list[ThreatFinding],
        sandbox: SandboxResult,
    ) -> AttackAnalysis:
        if attack.filename == _DETERMINISTIC_FILENAME:
            # Model-free probe: judge it from sandbox evidence only, so a
            # provider that declined to draft cannot also stall the verdict.
            return _deterministic_analysis(attack, sandbox)
        output = {
            "stdout": sandbox.stdout[:16_000],
            "stderr": sandbox.stderr[:16_000],
            "exit_code": sandbox.exit_code,
            "status": sandbox.status.value,
            "timed_out": sandbox.status is SandboxStatus.TIMED_OUT,
        }
        try:
            raw = await self._request(
                instructions=(
                    "You are a red-team results evaluator. Judge only the supplied local sandbox output and code. "
                    "A success marker is evidence only when it demonstrates the stated finding. Mark uncertain "
                    "compiler, timeout, or harness failures inconclusive. Return JSON only."
                ),
                input=json.dumps(
                    {
                        "attack": attack.model_dump(mode="json"),
                        "code_language": generated_code.language.value,
                        "mutation_plan": mutation_plan.model_dump(mode="json"),
                        "findings": [finding.model_dump(mode="json") for finding in findings],
                        "sandbox_output": output,
                    },
                    separators=(",", ":"),
                ),
                text=_attack_analysis_format(),
                max_output_tokens=4_000,
            )
        except AIProviderRefusal as exc:
            # Never guess a verdict when the evaluator declined: block deployment.
            raise RedTeamError("Provider declined to evaluate the sandbox evidence; deployment blocked") from exc
        try:
            return AttackAnalysis.model_validate_json(raw)
        except ValidationError:
            repair = await self._request(
                instructions="Return only valid JSON matching the attack-analysis schema. Be conservative and mark uncertainty inconclusive.",
                input=raw[:12_000],
                text=_attack_analysis_format(),
                max_output_tokens=4_000,
            )
            try:
                return AttackAnalysis.model_validate_json(repair)
            except ValidationError as second_error:
                raise RedTeamError("Attack-analysis output failed strict JSON validation") from second_error

    async def _request(
        self,
        *,
        instructions: str,
        input: str,
        text: dict[str, Any],
        max_output_tokens: int,
    ) -> str:
        try:
            format_spec = text["format"]
            return await self._provider.generate_structured(
                StructuredOutputRequest(
                    instructions=instructions,
                    input_text=input,
                    schema_name=str(format_spec["name"]),
                    json_schema=dict(format_spec["schema"]),
                    max_output_tokens=max_output_tokens,
                )
            )
        except AIProviderRefusal:
            raise
        except (AIProviderError, KeyError, TypeError, ValueError) as exc:
            raise RedTeamError(f"AI provider red-team request failed: {_compact_error(exc)}") from exc


async def execute_deterministic_verification(
    sandbox: SandboxBackend,
    generated_code: GeneratedCodeBundle,
    findings: list[ThreatFinding],
    *,
    attack: AttackScript | None = None,
    log_sink: LogSink | None = None,
) -> RedTeamResult:
    """Run and assess a bundle locally without consulting an AI provider."""
    if not findings:
        raise ValueError("Deterministic verification needs at least one target finding")
    expected_attack = deterministic_attack(findings)
    selected_attack = attack if attack is not None else expected_attack
    if selected_attack.filename == _DETERMINISTIC_FILENAME and selected_attack != expected_attack:
        raise RedTeamError("Supplied attack cannot impersonate the deterministic verification harness")
    sandbox_result = await _execute_attack_in_sandbox(
        sandbox,
        generated_code,
        selected_attack,
        log_sink=log_sink,
    )
    # The analysis is always computed server-side from sandbox evidence alone;
    # a host agent never supplies the verdict. The model-free probe uses the
    # signature-based reading, while a host-authored harness is judged purely
    # by its declared markers and exit status.
    if selected_attack.filename == _DETERMINISTIC_FILENAME:
        analysis = _deterministic_analysis(selected_attack, sandbox_result)
    else:
        analysis = _host_harness_analysis(selected_attack, sandbox_result)
    analysis = _enforce_conservative_verdict(selected_attack, sandbox_result, analysis)
    return RedTeamResult(attack=selected_attack, sandbox=sandbox_result, analysis=analysis)


async def _execute_attack_in_sandbox(
    sandbox: SandboxBackend,
    generated_code: GeneratedCodeBundle,
    attack: AttackScript,
    *,
    log_sink: LogSink | None = None,
) -> SandboxResult:
    _validate_attack(attack, generated_code)
    files = generated_code.file_mapping()
    if attack.filename == _DETERMINISTIC_FILENAME:
        # The signature probe must judge only the patched source. Generated
        # tests legitimately contain the vulnerable pattern as test input and
        # would otherwise be reported as a persisting vulnerability.
        files = {path: content for path, content in files.items() if not _is_test_file(path)}
    files[attack.filename] = attack.content
    try:
        return await sandbox.run(
            SandboxRunSpec(
                runtime=generated_code.sandbox_runtime,
                command=("sh", attack.filename),
                files=files,
                name_hint="red-team",
            ),
            log_sink=log_sink,
        )
    except SandboxValidationError as exc:
        raise RedTeamError(f"Sandbox rejected the generated verification bundle: {exc}") from exc


_TEST_FILE = re.compile(r"(?:^|/)(?:tests?/|test_[^/]*$|[^/]*_test\.[^/]+$|[^/]*\.(?:test|spec)\.[^/]+$)")


def _is_test_file(path: str) -> bool:
    return bool(_TEST_FILE.search(path.replace("\\", "/")))


def _validate_attack(attack: AttackScript, generated_code: GeneratedCodeBundle) -> None:
    # Rust and Go base images deliberately do not include Python. Bash is the
    # portable harness language across the two approved build images.
    if attack.filename in generated_code.file_mapping():
        raise RedTeamError("Attack filename collides with a generated bundle file")
    if attack.language is not AttackLanguage.BASH or not attack.filename.endswith(".sh"):
        raise RedTeamError("Rust/Go sandbox attacks must use a Bash script")
    if _FORBIDDEN_ATTACK_TOKENS.search(attack.content):
        raise RedTeamError("Attack script requested a prohibited host/network/privilege operation")
    verdict = _GATEWAY.evaluate_command(attack.content)
    if not verdict.allowed:
        raise RedTeamError(f"Harness gateway denied attack script [{verdict.rule}]: {verdict.reason}")
    if attack.success_marker not in attack.content:
        raise RedTeamError("Attack script must emit its declared success marker only on demonstrated exploit success")
    if attack.filename != _DETERMINISTIC_FILENAME:
        if generated_code.entrypoint not in attack.content:
            raise RedTeamError("Attack harness does not exercise the generated entrypoint")
        if attack.content.count(HARNESS_COMPLETED_MARKER) != 1:
            raise RedTeamError("Attack harness must emit exactly one completion marker")
        if not _MEANINGFUL_PROBE.search(attack.content):
            raise RedTeamError("Attack harness contains no observable test or probe operation")
        marker_line = next((line for line in attack.content.splitlines() if attack.success_marker in line), "")
        prefix = attack.content[:attack.content.find(marker_line) + len(marker_line)]
        if "&&" not in marker_line and not re.search(r"(?m)^\s*(?:if|case)\b", prefix):
            raise RedTeamError("Exploit success marker is not guarded by a test condition")
    if len(generated_code.file_mapping()) + 1 > 64:
        raise RedTeamError("Combined generated-code and attack files exceed sandbox file limit")


# Deterministic, model-free verification probes. When a provider declines to
# draft an attack harness, the wargame degrades to these signature probes
# instead of aborting: the mission never depends on an AI being willing to
# write exploits, and no provider safety system is ever circumvented.
_DETERMINISTIC_SIGNATURES: dict[str, str] = {
    "CWE-89": r"(SELECT|INSERT|UPDATE|DELETE)[^\n]{0,120}([{]|\+|%|format[(])",
    "CWE-798": r"(password|passwd|secret|api[_-]?key|access[_-]?key|token)[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}[\"']",
    "CWE-79": r"(<script|innerHTML|document\.write)[^\n]{0,80}(f[\"']|\+|\$\()",
    "CWE-78": r"(os\.system\(|shell[[:space:]]*=[[:space:]]*True|child_process\.exec\()",
    "CWE-95": r"(^|[^A-Za-z0-9_.])(eval|exec)[[:space:]]*\(|new[[:space:]]+Function[[:space:]]*\(",
}
_DETERMINISTIC_SIGNATURES["CWE-94"] = _DETERMINISTIC_SIGNATURES["CWE-95"]

# The pattern lives in a temp file *outside* the scanned workspace and the probe
# excludes its own files, otherwise the probe would match its own signature text
# (the CWE-89 pattern contains "SELECT", "+" and "{") and always report a breach.
_DETERMINISTIC_TEMPLATE = """#!/bin/sh
# Arbalest deterministic verification harness — sandbox-local, offline.
set -u
cd /run/arbalest-build/workspace || exit 3
PAT="$(mktemp)" || exit 3
cat > "$PAT" <<'ARBALEST_EOF'
{signature}
ARBALEST_EOF
grep -RiEnf "$PAT" --exclude-dir=.git --exclude='arbalest-*.sh' --exclude='.arbalest-*' . >/dev/null 2>&1
rc=$?
rm -f "$PAT"
case "$rc" in
  0) echo "{marker}"; echo "{completed}"; exit 0 ;;
  1) echo "deterministic probe: signature not present"; echo "{completed}"; exit 0 ;;
  *) echo "deterministic probe: grep error rc=$rc"; exit 3 ;;
esac
"""

# CWEs with no signature must fail closed. An empty pattern file matches every
# line, which would be a false breach, and "not present" would be a false pass.
_UNSUPPORTED_TEMPLATE = """#!/bin/sh
# Arbalest deterministic verification harness — no offline probe for this CWE.
# {marker}
echo "deterministic probe: no offline signature for {cwe}; verification inconclusive"
exit 3
"""


def deterministic_attack(findings: list[ThreatFinding]) -> AttackScript:
    cwe = (findings[0].cwe if findings else "CWE-UNKNOWN").upper()
    marker = f"ARBALEST_EXPLOIT_SUCCESS_{cwe.replace('-', '_')}"
    signature = _DETERMINISTIC_SIGNATURES.get(cwe, "")
    if signature:
        content = _DETERMINISTIC_TEMPLATE.format(signature=signature, marker=marker, completed=HARNESS_COMPLETED_MARKER)
    else:
        content = _UNSUPPORTED_TEMPLATE.format(marker=marker, cwe=re.sub(r"[^A-Z0-9-]", "", cwe))
    return AttackScript(
        language=AttackLanguage.BASH,
        filename=_DETERMINISTIC_FILENAME,
        content=content,
        success_marker=marker,
        objective=f"Deterministic sandbox probe for {cwe} persistence in generated code",
    )


# Backward-compatible private alias retained for existing callers and tests.
_deterministic_attack = deterministic_attack


def _deterministic_analysis(attack: AttackScript, sandbox: SandboxResult) -> AttackAnalysis:
    """Judge the model-free probe from sandbox evidence alone (no AI involved)."""
    transcript = f"{sandbox.stdout}\n{sandbox.stderr}"
    completed = sandbox.succeeded and HARNESS_COMPLETED_MARKER in sandbox.stdout
    if attack.success_marker in transcript:
        return AttackAnalysis(
            exploit_successful=True,
            inconclusive=False,
            reasoning="Signature probe found the vulnerable pattern still present in the generated code.",
            evidence=[attack.success_marker],
            confidence=0.6,
        )
    if completed:
        return AttackAnalysis(
            exploit_successful=False,
            inconclusive=False,
            reasoning=(
                "Signature probe did not find the vulnerable pattern. This is weaker evidence than a live "
                "exploit attempt because the AI provider declined to draft an attack harness."
            ),
            evidence=[],
            confidence=0.4,
        )
    return AttackAnalysis(
        exploit_successful=False,
        inconclusive=True,
        reasoning="Signature probe could not run to completion or has no offline signature for this CWE.",
        evidence=[],
        confidence=0.0,
    )


def _host_harness_analysis(attack: AttackScript, sandbox: SandboxResult) -> AttackAnalysis:
    """Judge a host-agent-authored harness from its declared markers alone.

    No AI provider and no host-supplied verdict are consulted: the reasoning is
    derived only from what the sandbox actually printed and how it exited.
    ``_enforce_conservative_verdict`` still has the final word afterwards.
    """
    transcript = f"{sandbox.stdout}\n{sandbox.stderr}"
    if attack.success_marker in transcript:
        return AttackAnalysis(
            exploit_successful=True,
            inconclusive=False,
            reasoning="Host harness emitted its declared exploit-success marker inside the sandbox.",
            evidence=[attack.success_marker],
            confidence=0.6,
        )
    if sandbox.succeeded and HARNESS_COMPLETED_MARKER in sandbox.stdout:
        return AttackAnalysis(
            exploit_successful=False,
            inconclusive=False,
            reasoning=(
                "Host harness ran to completion and never emitted its exploit-success marker. "
                "The patch held against this harness, but a host-authored harness is weaker "
                "evidence than a provider-driven adversarial war-game."
            ),
            evidence=[],
            confidence=0.5,
        )
    return AttackAnalysis(
        exploit_successful=False,
        inconclusive=True,
        reasoning="Host harness did not run to completion; nothing is proven.",
        evidence=[],
        confidence=0.0,
    )


def _enforce_conservative_verdict(
    attack: AttackScript,
    sandbox: SandboxResult,
    analysis: AttackAnalysis,
) -> AttackAnalysis:
    transcript = f"{sandbox.stdout}\n{sandbox.stderr}"
    if attack.success_marker in transcript and not analysis.exploit_successful:
        return analysis.model_copy(
            update={
                "exploit_successful": True,
                "inconclusive": False,
                "reasoning": "The sandbox emitted the declared exploit-success marker. " + analysis.reasoning,
                "evidence": [*analysis.evidence, attack.success_marker],
            }
        )
    if not (sandbox.succeeded and HARNESS_COMPLETED_MARKER in sandbox.stdout):
        # No completion literal means the harness never finished its checks
        # (build error, crash, timeout, partial run). That is not "held".
        return analysis.model_copy(
            update={
                "exploit_successful": False,
                "inconclusive": True,
                "reasoning": "Harness did not run to completion; deployment must remain blocked. " + analysis.reasoning,
            }
        )
    return analysis


def _attack_script_format() -> dict[str, Any]:
    return {
        "format": {
            "type": "json_schema",
            "name": "red_team_attack_script",
            "strict": True,
            "schema": AttackScript.model_json_schema(),
        }
    }


def _attack_analysis_format() -> dict[str, Any]:
    return {
        "format": {
            "type": "json_schema",
            "name": "red_team_analysis",
            "strict": True,
            "schema": AttackAnalysis.model_json_schema(),
        }
    }


def _debate_instructions() -> str:
    return """

DEBATE PROTOCOL (multi-turn war-game — CRITICAL):
The adversary_history payload lists every previous iteration of this war-game:
the patches the Architect produced, the attacks you ran, and why they breached
or failed. You are the attacking side of a minimax loop.
- NEVER re-run an attack from history that failed — the Architect has already
  hardened the code against it.
- Exploit a DIFFERENT property than previous attempts: alternate sinks, encode
  payloads differently, attack the patch's own assumptions or new helper logic,
  or chain the patched function with adjacent code in the bundle.
- If every previous attack failed, find the weakest invariant in the current
  patch and target it precisely. One of the two sides must concede."""


def _attack_instructions(language: str) -> str:
    return f"""You are RedTeamSwarm. Write one local Bash test harness for the supplied {language}
code and approved vulnerability findings.

ENVIRONMENT CONSTRAINTS (CRITICAL — violating these will abort the pipeline):
- The sandbox has NO network access. Do not use curl, wget, nc, or any network tools.
- Do not start any HTTP server (no python -m http.server, no cargo run --release with actix/axum serving).
- Do not reference external URLs, read host paths, install packages, use Docker, or attempt privilege escalation.
- Do not use the words ssh, telnet, sudo, kubectl, or docker as commands.

YOUR APPROACH:
0. The harness is executed with `sh` (POSIX shell, not bash): never use `[[`, arrays, or `source`.
   Test ONLY the CWE(s) in the supplied findings; do not add checks for other vulnerability classes.
   Keep it short: one focused Python helper written with a quoted heredoc (<<'EOF'), at most ~80 lines,
   with no more than 6 payloads.
1. The harness starts in /run/arbalest-build/workspace (a writable copy of /workspace inputs).
2. For Python targets: the target files are in the current directory, not on sys.path by default. Write
   helper scripts inside the workspace (e.g. ./arbalest_test.py, never /tmp) and run them from there, or
   start them with `sys.path.insert(0, '/run/arbalest-build/workspace')` before importing the target.
   You CANNOT pip install anything. When Flask is mocked, route handlers return MagicMock objects, so
   never judge the result from a handler's return value; judge it only from an observable side effect
   (a canary file, a recorded subprocess/sqlite call, an exception) that you inspect yourself.
   Mock ONLY the flask module; never mock or replace the target module or its functions. Make the
   `app.route` mock return the decorated function unchanged (`route=lambda *a, **k: (lambda f: f)`),
   otherwise every route handler becomes a MagicMock and the test exercises nothing. If a payload is
   rejected with an exception (ValueError, SyntaxError), that is evidence the patch held. If the target code imports external packages (like Flask, Django, requests), you MUST dynamically mock them in your test script using `sys.modules['module_name'] = MagicMock()` BEFORE importing the target code.
3. To test for SQL injection or logic flaws: write a unit test script that calls the vulnerable function directly. Do not attempt to start a web server or send HTTP requests. Craft a malicious input string and pass it directly to the function. Check if the output contains data that should not be accessible.
4. To test for hardcoded secrets: grep the generated source code for secret/key/token/password strings.
   If they still exist in the generated code, the vulnerability persists.
5. To test for missing authorization: check if the code enforces caller identity before returning
   sensitive data. A function that returns data without checking auth is vulnerable.
6. To test for command or code injection (CWE-78, CWE-94, CWE-95): never read or touch host files such
   as /etc/passwd and never delete anything. Use a canary inside the workspace instead: pass a payload
   such as `x; touch ./arbalest_canary #` or `__import__('pathlib').Path('arbalest_canary').touch()`
   to the vulnerable function (mock subprocess only if the real command cannot run offline), then check
   whether ./arbalest_canary exists. If it exists, the injection executed. For path traversal payloads
   target a workspace file (e.g. `../workspace/app.py`). The text `/etc/passwd`, `/etc/shadow` or `rm -rf /`
   must not appear anywhere in the script, not even inside a payload string or comment.
7. The harness MUST contain the generated bundle's exact `entrypoint` path string verbatim (for example
   `import app` is not enough; also reference the file path itself, e.g. `test -f app.py`). Print the declared
   ARBALEST_EXPLOIT_SUCCESS marker exactly once and only inside an `if`/`case` branch (or an `&&` chain)
   whose condition is the observed exploit result. After ALL checks have run, print the exact line
   {HARNESS_COMPLETED_MARKER} and exit 0, whether or not the exploit worked. If the harness itself cannot
   run (build error, missing file), exit nonzero WITHOUT printing it; that is reported as inconclusive.
8. Return structured JSON data only, never Markdown."""


def _compact_error(error: Exception) -> str:
    return str(error).replace("\n", " ")[:500] or error.__class__.__name__

__all__ = [
    "AttackAnalysis",
    "AttackLanguage",
    "AttackScript",
    "HARNESS_COMPLETED_MARKER",
    "RedTeamError",
    "RedTeamResult",
    "RedTeamSwarm",
    "deterministic_attack",
    "execute_deterministic_verification",
]
