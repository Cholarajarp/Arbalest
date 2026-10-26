"""fix → verify identity round-trip.

`fix` must plan from the sealed finding the scan actually reported, so the
artifact it seals carries the real finding_id/CWE and `verify --finding <id>`
accepts exactly that artifact. The old synthetic `CLI-<id>`/`CWE-Unknown`
finding made every id-form verify reject its own fix's artifact.
"""

from __future__ import annotations

from engine.agents.architect_agent import (
    CodeLanguage,
    MutationAction,
    MutationPlan,
    MutationStep,
    ThreatFinding,
)
from engine.agents.polyglot_translator import GeneratedCodeBundle, GeneratedFile
from engine.services.remediation_artifact import create_artifact, load_artifact, save_artifact
from engine.services.scan_archive import (
    resolve_archived_finding,
    save_scan_archive,
)
from engine.services.scan_pipeline import AgentStat, SwarmResult

FINDING_ID = "SAST-b99677f07aac5ba8"


def _sealed_finding() -> ThreatFinding:
    return ThreatFinding(
        finding_id=FINDING_ID,
        cwe="CWE-78",
        severity="critical",
        summary="OS command injection via user-controlled repository parameter",
        affected_nodes=["executors.py"],
        evidence=["In executors.py: return os.system(cmd)"],
    )


def _archive_with_finding(tmp_path):
    swarm = SwarmResult(
        findings=[_sealed_finding()],
        stats={"sast": AgentStat("sast")},
        buckets={"sast": [_sealed_finding()]},
    )
    return save_scan_archive(tmp_path, "a1b2c3d4e5f6", swarm, provider="nebius", model="m")


def test_resolve_archived_finding_returns_sealed_record(tmp_path):
    _archive_with_finding(tmp_path)
    finding = resolve_archived_finding(tmp_path, FINDING_ID)
    assert finding is not None
    assert finding.finding_id == FINDING_ID
    assert finding.cwe == "CWE-78"
    assert finding.severity == "critical"
    assert finding.evidence


def test_resolve_archived_finding_unknown_id_is_none(tmp_path):
    _archive_with_finding(tmp_path)
    assert resolve_archived_finding(tmp_path, "SAST-doesnotexist") is None
    assert resolve_archived_finding(tmp_path, "") is None


def test_fix_artifact_is_verifiable_by_finding_id(tmp_path):
    """The exact fix → verify contract: an artifact sealed from the resolved
    finding must load for both the finding id and the CWE form."""
    _archive_with_finding(tmp_path)
    finding = resolve_archived_finding(tmp_path, FINDING_ID)
    assert finding is not None

    plan = MutationPlan(
        plan_id="p1",
        target_language=CodeLanguage.PYTHON,
        mutations=[
            MutationStep(
                target_file="executors.py",
                target_node="executors.py",
                action=MutationAction.ADD_INPUT_VALIDATION,
                rationale="Validate the command before execution.",
                expected_side_effects=[],
                acceptance_criteria=["no shell metacharacters reach os.system"],
            )
        ],
        security_invariants=["no string-built shell commands"],
        test_strategy=["unit test shell metacharacters"],
    )
    bundle = GeneratedCodeBundle(
        language=CodeLanguage.PYTHON,
        entrypoint="executors.py",
        files=[GeneratedFile(path="executors.py", content="import shlex, subprocess\n")],
        build_instructions=["none"],
        test_instructions=["none"],
    )
    artifact = create_artifact(finding, plan, bundle, {"executors.py": "import os\n"})
    save_artifact(tmp_path, artifact)

    loaded, path = load_artifact(tmp_path, artifact.artifact_id, FINDING_ID)
    assert loaded.artifact_id == artifact.artifact_id
    assert "CWE-78" in path.name

    by_cwe, _ = load_artifact(tmp_path, None, "CWE-78")
    assert by_cwe.artifact_id == artifact.artifact_id
