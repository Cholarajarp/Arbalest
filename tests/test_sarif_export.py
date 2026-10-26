"""SARIF 2.1.0 export — the final report contract."""

from __future__ import annotations

import json

from engine.agents.architect_agent import Severity, ThreatFinding
from engine.services.sarif_export import findings_to_sarif, sarif_to_pretty_json


def _finding(sev: Severity = Severity.HIGH) -> ThreatFinding:
    return ThreatFinding(
        finding_id="SAST-test-001",
        cwe="CWE-89",
        severity=sev,
        summary="SQL query built with user input",
        affected_nodes=["app/db.py"],
        evidence=["cursor.execute(f\"SELECT * FROM users WHERE id={uid}\")"],
    )


def test_sarif_is_valid_json_2_1_0():
    sarif = findings_to_sarif([_finding()], run_id="run-42", target_url="/repo")
    parsed = json.loads(sarif_to_pretty_json(sarif))
    assert parsed["version"] == "2.1.0"
    assert parsed["$schema"].endswith("sarif-schema-2.1.0.json")
    run = parsed["runs"][0]
    assert run["tool"]["driver"]["name"]
    assert run["results"], "SARIF must contain the finding"


def test_sarif_result_fields():
    sarif = findings_to_sarif([_finding(Severity.CRITICAL)], run_id="run-42", target_url="/repo")
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "CWE-89"
    assert result["level"] == "error"          # critical → error
    assert result["message"]["text"]
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app/db.py"
    # GitHub code-scanning convention: security-severity lives on the rule entry.
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.5"


def test_sarif_severity_level_mapping():
    sarif = findings_to_sarif([
        _finding(Severity.CRITICAL), _finding(Severity.MEDIUM), _finding(Severity.INFO),
    ])
    levels = [r["level"] for r in sarif["runs"][0]["results"]]
    assert levels == ["error", "warning", "note"]


def test_sarif_empty_findings_is_valid():
    sarif = findings_to_sarif([])
    parsed = json.loads(sarif_to_pretty_json(sarif))
    assert parsed["runs"][0]["results"] == []
