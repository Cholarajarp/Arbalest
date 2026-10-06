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
from engine.services.ai_provider import AIProvider, AIProviderError, StructuredOutputRequest
from engine.services.docker_manager import (
    DockerSandboxManager,
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
    r"|rm\s+-rf\s+/"
    r"|/etc/(?:passwd|shadow)",
    re.MULTILINE,
)
_GATEWAY = ActionGateway()

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
    def deployment_allowed(self) -> bool:
        return self.sandbox.succeeded and not self.analysis.exploit_successful and not self.analysis.inconclusive


class RedTeamSwarm:
    """Generate local attack harnesses and assess only sandbox-observed behavior."""

    def __init__(
        self,
        *,
        sandbox: DockerSandboxManager,
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
        _validate_attack(attack, generated_code)

        files = generated_code.file_mapping()
        files[attack.filename] = attack.content
        try:
            sandbox_result = await self._sandbox.run(
                SandboxRunSpec(
                    runtime=generated_code.sandbox_runtime,
                    command=("sh", attack.filename),
                    files=files,
                    name_hint="red-team",
                ),
                log_sink=log_sink,
            )
        except SandboxValidationError as exc:
            # A model-generated bundle can exceed a sandbox structural limit
            # before Docker starts. Surface that as a red-team failure so the
            # orchestrator emits a controlled deployment-blocked result rather
            # than aborting the WebSocket pipeline.
            raise RedTeamError(f"Sandbox rejected the generated verification bundle: {exc}") from exc
        analysis = await self._analyze(attack, generated_code, mutation_plan, findings, sandbox_result)
        analysis = _enforce_conservative_verdict(attack, sandbox_result, analysis)
        logger.info(
            "Red-team sandbox completed",
            extra={
                "status": sandbox_result.status.value,
                "exploit_successful": analysis.exploit_successful,
                "inconclusive": analysis.inconclusive,
            },
        )
        return RedTeamResult(attack=attack, sandbox=sandbox_result, analysis=analysis)

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
        try:
            return AttackScript.model_validate_json(raw)
        except ValidationError:
            repair = await self._request(
                instructions="Return only a valid local Bash attack-script JSON object matching the schema.",
                input=raw[:32_000],
                text=_attack_script_format(),
                max_output_tokens=16_000,
            )
            try:
                return AttackScript.model_validate_json(repair)
            except ValidationError as second_error:
                if _REFUSAL_MARKERS.search(raw) or _REFUSAL_MARKERS.search(repair):
                    logger.info("Provider declined attack drafting; degrading to deterministic harness")
                    return _deterministic_attack(findings)
                raise RedTeamError("Attack-script output failed strict JSON validation") from second_error

    async def _analyze(
        self,
        attack: AttackScript,
        generated_code: GeneratedCodeBundle,
        mutation_plan: MutationPlan,
        findings: list[ThreatFinding],
        sandbox: SandboxResult,
    ) -> AttackAnalysis:
        output = {
            "stdout": sandbox.stdout[:16_000],
            "stderr": sandbox.stderr[:16_000],
            "exit_code": sandbox.exit_code,
            "status": sandbox.status.value,
            "timed_out": sandbox.status is SandboxStatus.TIMED_OUT,
        }
        raw = await self._request(
            instructions=(
                "You are a red-team results evaluator. Judge only the supplied local sandbox output and code. "
                "A success marker is evidence only when it demonstrates the stated finding. Mark uncertain compiler, "
                "timeout, or harness failures inconclusive. Return JSON only."
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
        except (AIProviderError, KeyError, TypeError, ValueError) as exc:
            raise RedTeamError(f"AI provider red-team request failed: {_compact_error(exc)}") from exc


def _validate_attack(attack: AttackScript, generated_code: GeneratedCodeBundle) -> None:
    # Rust and Go base images deliberately do not include Python. Bash is the
    # portable harness language across the two approved build images.
    if attack.language is not AttackLanguage.BASH or not attack.filename.endswith(".sh"):
        raise RedTeamError("Rust/Go sandbox attacks must use a Bash script")
    if _FORBIDDEN_ATTACK_TOKENS.search(attack.content):
        raise RedTeamError("Attack script requested a prohibited host/network/privilege operation")
    verdict = _GATEWAY.evaluate_command(attack.content)
    if not verdict.allowed:
        raise RedTeamError(f"Harness gateway denied attack script [{verdict.rule}]: {verdict.reason}")
    if attack.success_marker not in attack.content:
        raise RedTeamError("Attack script must emit its declared success marker only on demonstrated exploit success")
    if len(generated_code.file_mapping()) + 1 > 64:
        raise RedTeamError("Combined generated-code and attack files exceed sandbox file limit")


# Deterministic, model-free verification probes. When a provider declines to
# draft an attack harness, the wargame degrades to these signature probes
# instead of aborting: the mission never depends on an AI being willing to
# write exploits, and no provider safety system is ever circumvented.
_DETERMINISTIC_SIGNATURES: dict[str, str] = {
    "CWE-89": r"(SELECT|INSERT|UPDATE|DELETE)[^\n]{0,120}([{]|\+|%|format[(])",
    "CWE-798": r"(password|passwd|secret|api[_-]?key|access[_-]?key|token)[[:space:]]*[:=][[:space:]]*[\"'][^\"'\n]{8,}[\"']",
    "CWE-79": r"(<script|innerHTML|document\.write)[^\n]{0,80}(f[\"']|\+|\$\()",
    "CWE-78": r"(os\.system\(|shell[[:space:]]*=[[:space:]]*True|child_process\.exec\()",
}

_DETERMINISTIC_TEMPLATE = """#!/bin/sh
# Arbalest deterministic verification harness — sandbox-local, offline.
set -u
cd /run/arbalest-build/workspace || exit 1
cat > .arbalest-probe.pat <<'ARBALEST_EOF'
{signature}
ARBALEST_EOF
if [ -s .arbalest-probe.pat ] && grep -RiEnf .arbalest-probe.pat --exclude-dir=.git --exclude-dir=.arbalest . >/dev/null 2>&1; then
  echo "{marker}"
  exit 0
fi
echo "deterministic probe: signature not present"
exit 1
"""


def _deterministic_attack(findings: list[ThreatFinding]) -> AttackScript:
    cwe = (findings[0].cwe if findings else "CWE-UNKNOWN").upper()
    marker = f"ARBALEST_EXPLOIT_SUCCESS_{cwe.replace('-', '_')}"
    signature = _DETERMINISTIC_SIGNATURES.get(cwe, "")
    return AttackScript(
        language=AttackLanguage.BASH,
        filename="arbalest-deterministic-probe.sh",
        content=_DETERMINISTIC_TEMPLATE.format(signature=signature, marker=marker),
        success_marker=marker,
        objective=f"Deterministic sandbox probe for {cwe} persistence in generated code",
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
    if sandbox.status is not SandboxStatus.COMPLETED or sandbox.exit_code not in {0, 1}:
        return analysis.model_copy(
            update={
                "inconclusive": True,
                "reasoning": "Sandbox execution did not complete cleanly; deployment must remain blocked. " + analysis.reasoning,
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
1. The harness starts in /run/arbalest-build/workspace (a writable copy of /workspace inputs).
2. For Python targets: you CANNOT pip install anything. If the target code imports external packages (like Flask, Django, requests), you MUST dynamically mock them in your test script using `sys.modules['module_name'] = MagicMock()` BEFORE importing the target code.
3. To test for SQL injection or logic flaws: write a unit test script that calls the vulnerable function directly. Do not attempt to start a web server or send HTTP requests. Craft a malicious input string and pass it directly to the function. Check if the output contains data that should not be accessible.
4. To test for hardcoded secrets: grep the generated source code for secret/key/token/password strings.
   If they still exist in the generated code, the vulnerability persists.
5. To test for missing authorization: check if the code enforces caller identity before returning
   sensitive data. A function that returns data without checking auth is vulnerable.
6. Print the declared ARBALEST_EXPLOIT_SUCCESS marker ONLY when the vulnerability is demonstrably
   exploitable in the generated code. Otherwise print diagnostic failure output and exit nonzero.
7. Return structured JSON data only, never Markdown."""


def _compact_error(error: Exception) -> str:
    return str(error).replace("\n", " ")[:500] or error.__class__.__name__
