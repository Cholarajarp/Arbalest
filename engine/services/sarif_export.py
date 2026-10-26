"""Safe SARIF 2.1.0 export with explicit scan-completeness semantics."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

from engine import __version__ as _TOOL_VERSION
from engine.agents.architect_agent import ThreatFinding

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_TOOL_NAME = "Arbalest"
_TOOL_URI = "https://github.com/Cholarajarp/Arbalest"
_SEVERITY_TO_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SEVERITY_TO_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 1.0}
_LINE = re.compile(r"(?i)(?:\bline\s*|:)([1-9][0-9]{0,8})\b")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _safe_uri(value: str) -> str | None:
    normalized = value.replace("\\", "/")
    if normalized.startswith("/source/"):
        normalized = normalized[8:]
    if not normalized or _CONTROL.search(normalized) or ":" in normalized.split("/", 1)[0]:
        return None
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return quote(path.as_posix(), safe="/@._-~")


def _line_number(finding: ThreatFinding) -> int:
    for evidence in finding.evidence:
        match = _LINE.search(evidence)
        if match:
            return max(1, int(match.group(1)))
    return 1


def findings_to_sarif(
    findings: Sequence[ThreatFinding],
    *,
    run_id: str = "",
    target_url: str = "",
    legacy_sources: Mapping[str, str] | None = None,
    execution_successful: bool = True,
    notifications: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Convert normalized findings to GitHub-compatible SARIF 2.1.0."""
    del legacy_sources  # retained for API compatibility
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_index_map: dict[str, int] = {}
    artifacts: list[dict[str, Any]] = []
    artifact_index_map: dict[str, int] = {}

    for finding in findings:
        rule_id = finding.cwe if finding.cwe.startswith("CWE-") else f"arbalest/{finding.cwe or 'finding'}"
        if rule_id not in rule_index_map:
            rule_index_map[rule_id] = len(rules)
            numeric_cwe = finding.cwe[4:] if re.fullmatch(r"CWE-[0-9]+", finding.cwe) else ""
            rules.append({
                "id": rule_id,
                "name": _rule_name_from_cwe(finding.cwe),
                "shortDescription": {"text": f"Security finding classified as {finding.cwe}"},
                "fullDescription": {"text": "Arbalest finding supported by source, scanner, or sandbox evidence."},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{numeric_cwe}.html" if numeric_cwe else _TOOL_URI,
                "properties": {
                    "tags": ["security"],
                    "security-severity": str(_SEVERITY_TO_SCORE.get(finding.severity.value, 5.0)),
                },
            })

        locations: list[dict[str, Any]] = []
        for raw_node in finding.affected_nodes[:5]:
            uri = _safe_uri(raw_node)
            if uri is None:
                continue
            if uri not in artifact_index_map:
                artifact_index_map[uri] = len(artifacts)
                artifacts.append({"location": {"uri": uri, "uriBaseId": "%SRCROOT%"}})
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%", "index": artifact_index_map[uri]},
                    "region": {"startLine": _line_number(finding)},
                }
            })
        if not locations:
            locations = [{"physicalLocation": {"artifactLocation": {"uri": "unknown"}, "region": {"startLine": 1}}}]

        stable_material = "\x1f".join([
            finding.cwe.lower(), finding.summary.strip().lower(),
            ",".join(sorted(node.replace("\\", "/") for node in finding.affected_nodes)),
        ])
        fingerprint = hashlib.sha256(stable_material.encode("utf-8")).hexdigest()[:32]
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index_map[rule_id],
            "level": _SEVERITY_TO_LEVEL.get(finding.severity.value, "warning"),
            "message": {"text": finding.summary},
            "locations": locations,
            "partialFingerprints": {"primaryLocationLineHash": fingerprint},
            "properties": {
                "arbalest-finding-id": finding.finding_id,
                "arbalest-severity": finding.severity.value,
                "evidence": finding.evidence[:5],
            },
        })

    tool_notifications = [
        {"level": "error" if not execution_successful else "warning", "message": {"text": str(message)[:1000]}}
        for message in (notifications or [])
    ]
    run: dict[str, Any] = {
        "tool": {"driver": {
            "name": _TOOL_NAME, "version": _TOOL_VERSION, "semanticVersion": _TOOL_VERSION,
            "informationUri": _TOOL_URI, "rules": rules,
        }},
        "results": results,
        "invocations": [{
            "executionSuccessful": execution_successful,
            "endTimeUtc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "toolExecutionNotifications": tool_notifications,
        }],
        "properties": {"arbalest-run-id": run_id, "arbalest-target": target_url,
                       "arbalest-status": "complete" if execution_successful else "incomplete"},
        "columnKind": "utf16CodeUnits",
    }
    if artifacts:
        run["artifacts"] = artifacts
    return {"version": _SARIF_VERSION, "$schema": _SARIF_SCHEMA, "runs": [run]}


def sarif_to_json(sarif: dict[str, Any]) -> str:
    return json.dumps(sarif, separators=(",", ":"), ensure_ascii=False)


def sarif_to_pretty_json(sarif: dict[str, Any]) -> str:
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _rule_name_from_cwe(cwe: str) -> str:
    names = {
        "CWE-89": "SQLInjection", "CWE-798": "HardcodedCredentials", "CWE-862": "MissingAuthorization",
        "CWE-639": "AuthorizationBypassIDOR", "CWE-20": "ImproperInputValidation", "CWE-693": "MissingSecurityHeaders",
        "CWE-200": "InformationDisclosure", "CWE-1295": "ExposedDebugEndpoint", "CWE-942": "CORSMisconfiguration",
        "CWE-1021": "Clickjacking", "CWE-79": "CrossSiteScripting", "CWE-22": "PathTraversal",
        "CWE-502": "InsecureDeserialization", "CWE-918": "ServerSideRequestForgery", "CWE-327": "BrokenCryptography",
    }
    return names.get(cwe, re.sub(r"[^A-Za-z0-9]", "", cwe) or "SecurityFinding")
