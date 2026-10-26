"""Adversarial self-verification of SAST findings: annotate, never delete.

A second model pass re-checks each candidate finding against the actual
fenced source and returns confirmed/rejected verdicts. Following the
platform's fail-closed philosophy nothing is dropped: rejected findings are
annotated so operators can review them, and every failure mode (transport,
parse, budget) simply leaves all findings untouched.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from engine.agents.architect_agent import ThreatFinding
from engine.agents.secret_scanner import redact_secrets
from engine.harness.injection_defense import wrap_untrusted
from engine.services.ai_provider import AIProvider, StructuredOutputRequest

logger = logging.getLogger(__name__)

_MAX_FINDINGS = 30
_MAX_SOURCE_CHARS = 48_000
_MAX_PER_FILE = 6_000

_VERIFY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdicts"],
    "properties": {
        "verdicts": {
            "type": "array",
            "maxItems": _MAX_FINDINGS,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["finding_id", "verdict", "reason"],
                "properties": {
                    "finding_id": {"type": "string", "minLength": 1, "maxLength": 128},
                    "verdict": {"type": "string", "enum": ["confirmed", "rejected"]},
                    "reason": {"type": "string", "minLength": 4, "maxLength": 500},
                },
            },
        }
    },
}


class _Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=128)
    verdict: str
    reason: str = Field(min_length=4, max_length=500)


class _VerifyResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdicts: list[_Verdict]


class FindingVerifier:
    """One bounded model call that adversarially re-checks candidate findings."""

    def __init__(self, provider: AIProvider, *, model_override: str | None = None) -> None:
        self._provider = provider
        self._model_override = model_override

    async def verify(
        self, findings: list[ThreatFinding], sources: dict[str, str],
    ) -> dict[str, str]:
        """Return ``finding_id -> "confirmed"|"rejected"`` for bounded findings."""
        if not findings:
            return {}
        bounded = findings[:_MAX_FINDINGS]
        known_ids = {finding.finding_id for finding in bounded}

        excerpts: list[str] = []
        total = 0
        affected = {node for finding in bounded for node in finding.affected_nodes}
        ordered = [path for path in sorted(sources) if path in affected] + [
            path for path in sorted(sources) if path not in affected
        ]
        for path in ordered:
            if total >= _MAX_SOURCE_CHARS:
                break
            fenced = wrap_untrusted(redact_secrets(sources[path][:_MAX_PER_FILE]), path)
            if total + len(fenced) > _MAX_SOURCE_CHARS:
                fenced = fenced[: _MAX_SOURCE_CHARS - total]
            excerpts.append(fenced)
            total += len(fenced)
        if not excerpts:
            return {}

        candidates = [
            {
                "finding_id": finding.finding_id,
                "cwe": finding.cwe,
                "severity": str(finding.severity.value),
                "summary": finding.summary[:600],
                "evidence": [item[:300] for item in finding.evidence[:3]],
            }
            for finding in bounded
        ]
        payload = {
            "candidate_findings": candidates,
            "source_code": excerpts,
        }
        raw = await self._provider.generate_structured(
            StructuredOutputRequest(
                instructions=(
                    "You are an adversarial verification reviewer. For each candidate finding, check "
                    "the fenced source code: does the claimed vulnerable code actually exist and does "
                    "the claim hold? Confirm findings grounded in the source. Reject only when the "
                    "claimed code or behavior is factually absent or the claim misreads the source. "
                    "When uncertain, confirm and say why. Judge only from the fenced data."
                ),
                input_text=wrap_untrusted(json.dumps(payload, default=str), "verification-input"),
                schema_name="finding-verification",
                json_schema=_VERIFY_SCHEMA,
                max_output_tokens=3_000,
                model=self._model_override,
            )
        )
        return self.parse(raw, known_ids)

    @staticmethod
    def parse(raw: str, known_ids: set[str]) -> dict[str, str]:
        try:
            result = _VerifyResult.model_validate_json(raw)
        except ValidationError:
            try:
                payload = json.loads(raw)
                items = payload.get("verdicts", []) if isinstance(payload, dict) else []
                result = _VerifyResult(verdicts=[
                    _Verdict(
                        finding_id=str(item.get("finding_id", ""))[:128],
                        verdict=str(item.get("verdict", "confirmed")),
                        reason=str(item.get("reason", "unparsed reason"))[:500],
                    )
                    for item in items[:_MAX_FINDINGS]
                    if isinstance(item, dict) and item.get("finding_id")
                ])
            except (ValueError, ValidationError, AttributeError):
                logger.warning("Finding-verification output unusable; all findings kept")
                return {}
        return {
            verdict.finding_id: verdict.verdict
            for verdict in result.verdicts
            if verdict.finding_id in known_ids and verdict.verdict in {"confirmed", "rejected"}
        }


__all__ = ["FindingVerifier"]
