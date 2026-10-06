"""SARIF 2.1.0 export — industry-standard static analysis output.

Converts Arbalest pipeline findings into the OASIS SARIF 2.1.0 format
understood by GitHub Code Scanning, VS Code, Azure DevOps, and every major
security tool in the ecosystem.

References:
  - https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
  - https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from engine.agents.architect_agent import ThreatFinding

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_TOOL_NAME = "Arbalest"
_TOOL_VERSION = "1.0.0"
_TOOL_URI = "https://github.com/Cholarajarp/Arbalest"

# Map Arbalest severity → SARIF level
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Map Arbalest severity → SARIF security-severity (numeric for GitHub)
_SEVERITY_TO_SCORE: dict[str, float] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "info": 1.0,
}


def findings_to_sarif(
    findings: Sequence[ThreatFinding],
    *,
    run_id: str = "",
    target_url: str = "",
    legacy_sources: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Convert a list of ThreatFindings into a complete SARIF 2.1.0 document.

    The output is directly compatible with ``github/codeql-action/upload-sarif``.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_index_map: dict[str, int] = {}
    artifacts: list[dict[str, Any]] = []
    artifact_index_map: dict[str, int] = {}

    for finding in findings:
        # Build or reuse rule entry
        rule_id = finding.cwe if finding.cwe.startswith("CWE-") else f"arbalest/{finding.finding_id}"
        if rule_id not in rule_index_map:
            rule_index_map[rule_id] = len(rules)
            rule_entry: dict[str, Any] = {
                "id": rule_id,
                "name": _rule_name_from_cwe(finding.cwe),
                "shortDescription": {"text": finding.summary[:200]},
                "fullDescription": {"text": finding.summary},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe.replace('CWE-', '')}.html" if finding.cwe.startswith("CWE-") else _TOOL_URI,
                "properties": {
                    "tags": ["security"],
                    "security-severity": str(_SEVERITY_TO_SCORE.get(finding.severity.value, 5.0)),
                },
            }
            rules.append(rule_entry)

        rule_index = rule_index_map[rule_id]
        severity_level = _SEVERITY_TO_LEVEL.get(finding.severity.value, "warning")

        # Build locations from affected_nodes
        locations: list[dict[str, Any]] = []
        for node in finding.affected_nodes[:5]:  # Bound locations
            # Normalize path
            file_path = node.replace("\\", "/")
            if file_path.startswith("/source/"):
                file_path = file_path[8:]  # Strip synthetic /source/ prefix

            # Get or create artifact
            if file_path not in artifact_index_map:
                artifact_index_map[file_path] = len(artifacts)
                artifacts.append({
                    "location": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                })

            locations.append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path,
                        "uriBaseId": "%SRCROOT%",
                        "index": artifact_index_map[file_path],
                    },
                    "region": {"startLine": 1},  # Default to line 1 if we don't have exact location
                },
            })

        if not locations:
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "unknown",
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1},
                },
            })

        # Partial fingerprint for deduplication
        fingerprint_input = f"{finding.finding_id}:{finding.cwe}:{','.join(finding.affected_nodes)}"
        partial_fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()[:32]

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": severity_level,
            "message": {
                "text": finding.summary,
            },
            "locations": locations,
            "partialFingerprints": {
                "primaryLocationLineHash": partial_fingerprint,
            },
            "properties": {
                "arbalest-finding-id": finding.finding_id,
                "arbalest-severity": finding.severity.value,
                "evidence": finding.evidence[:5],
            },
        }
        results.append(result)

    # Build the complete SARIF document
    sarif: dict[str, Any] = {
        "version": _SARIF_VERSION,
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "semanticVersion": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    },
                },
                "results": results,
                "artifacts": artifacts if artifacts else None,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "toolConfigurationNotifications": [],
                    }
                ],
                "properties": {
                    "arbalest-run-id": run_id,
                    "arbalest-target": target_url,
                },
                "columnKind": "utf16CodeUnits",
            }
        ],
    }

    # Remove None values
    if not artifacts:
        del sarif["runs"][0]["artifacts"]

    return sarif


def sarif_to_json(sarif: dict[str, Any]) -> str:
    """Serialize a SARIF document to a compact JSON string."""
    return json.dumps(sarif, separators=(",", ":"), ensure_ascii=False)


def sarif_to_pretty_json(sarif: dict[str, Any]) -> str:
    """Serialize a SARIF document to a pretty-printed JSON string."""
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _rule_name_from_cwe(cwe: str) -> str:
    """Map common CWE IDs to human-readable rule names."""
    _NAMES: dict[str, str] = {
        "CWE-89": "SQLInjection",
        "CWE-798": "HardcodedCredentials",
        "CWE-862": "MissingAuthorization",
        "CWE-639": "AuthorizationBypassIDOR",
        "CWE-20": "ImproperInputValidation",
        "CWE-693": "MissingSecurityHeaders",
        "CWE-200": "InformationDisclosure",
        "CWE-1295": "ExposedDebugEndpoint",
        "CWE-942": "CORSMisconfiguration",
        "CWE-1021": "Clickjacking",
        "CWE-79": "CrossSiteScripting",
        "CWE-22": "PathTraversal",
        "CWE-502": "InsecureDeserialization",
        "CWE-918": "ServerSideRequestForgery",
        "CWE-327": "BrokenCryptography",
    }
    return _NAMES.get(cwe, cwe.replace("-", ""))
