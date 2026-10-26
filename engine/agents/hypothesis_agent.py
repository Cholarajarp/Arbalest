"""Recon-driven review hypotheses: target-specific SAST steering.

Deterministic rules and package databases only find vulnerability classes the
world already knows. This agent reads what RECON actually observed about THIS
target (entrypoints, frameworks, manifests, sink signatures — secret-redacted
and DATA-fenced like every other untrusted input) and asks the model to
hypothesize attack surfaces specific to the application's own features. The
priorities are injected as advisory review directives into every SAST batch,
so a payments SaaS gets amount-tampering and webhook-forgery hypotheses and a
multi-tenant API gets tenant-isolation hypotheses — without anyone pre-writing
rules for them.

Failure is failure-tolerant: any error yields no priorities and the scan
proceeds unchanged with the standard reviewer instructions.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from engine.agents.secret_scanner import redact_secrets
from engine.harness.injection_defense import wrap_untrusted
from engine.services.ai_provider import AIProvider, StructuredOutputRequest

logger = logging.getLogger(__name__)

_MAX_PRIORITIES = 8
_MAX_SUMMARY_CHARS = 12_000
_MAX_PRIORITY_CHARS = 240

_HYPOTHESIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["review_priorities"],
    "properties": {
        "review_priorities": {
            "type": "array",
            "maxItems": _MAX_PRIORITIES,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["area", "rationale"],
                "properties": {
                    "area": {"type": "string", "minLength": 4, "maxLength": 120},
                    "rationale": {"type": "string", "minLength": 8, "maxLength": 400},
                },
            },
        }
    },
}


class ReviewPriority(BaseModel):
    model_config = ConfigDict(extra="forbid")

    area: str = Field(min_length=1, max_length=120)
    rationale: str = Field(min_length=1, max_length=400)


class HypothesisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_priorities: list[ReviewPriority]


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[\x40-\x5f]")


def _clean(value: str) -> str:
    """Model output re-enters prompts as advisory data: printable and bounded."""
    stripped = _ANSI_ESCAPE.sub("", value)
    return "".join(ch for ch in stripped if ch.isprintable())[:_MAX_PRIORITY_CHARS]


class HypothesisAgent:
    """Generate target-specific review priorities from the recon summary."""

    def __init__(self, provider: AIProvider, *, model_override: str | None = None) -> None:
        self._provider = provider
        self._model_override = model_override

    async def generate(self, recon_summary: dict[str, Any]) -> list[str]:
        summary_text = redact_secrets(json.dumps(recon_summary, default=str))[:_MAX_SUMMARY_CHARS]
        raw = await self._provider.generate_structured(
            StructuredOutputRequest(
                instructions=(
                    "You are an autonomous security reviewer planning a code review. You are given "
                    "the reconnaissance summary of ONE target application: its entrypoints, frameworks, "
                    "manifests, languages and dangerous-sink signatures. Hypothesize the attack surfaces "
                    "SPECIFIC to this application's features — the classes a generic checklist would miss "
                    "(for example tenant isolation for multi-tenant APIs, amount or currency tampering for "
                    "payments, webhook signature forgery, privilege boundaries between roles, upload abuse, "
                    "async/background-job authorization, cache or state poisoning). Only hypothesize areas "
                    "plausibly grounded in the observed surface; do not invent technologies not present. "
                    "Return JSON matching the schema with at most 8 priorities, highest impact first."
                ),
                input_text=wrap_untrusted(summary_text, "recon-summary"),
                schema_name="review-hypotheses",
                json_schema=_HYPOTHESIS_SCHEMA,
                max_output_tokens=1_200,
                model=self._model_override,
            )
        )
        return self.parse(raw)

    @staticmethod
    def parse(raw: str) -> list[str]:
        try:
            result = HypothesisResult.model_validate_json(raw)
        except ValidationError:
            try:
                payload = json.loads(raw)
                items = payload.get("review_priorities", []) if isinstance(payload, dict) else []
                if not isinstance(items, list):
                    raise ValueError("review_priorities must be a list")
                result = HypothesisResult(review_priorities=[
                    ReviewPriority(
                        area=str(item.get("area", ""))[:120],
                        rationale=str(item.get("rationale", ""))[:400],
                    )
                    for item in items[:_MAX_PRIORITIES]
                    if isinstance(item, dict) and item.get("area") and item.get("rationale")
                ])
            except (ValueError, ValidationError, AttributeError):
                logger.warning("Review-hypothesis output was unusable; continuing with standard instructions")
                return []
        priorities = [
            _clean(f"{item.area}: {item.rationale}")
            for item in result.review_priorities[:_MAX_PRIORITIES]
        ]
        return [item for item in priorities if item]


__all__ = ["HypothesisAgent"]
