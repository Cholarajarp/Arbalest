"""Antibody lifecycle — build, deterministic self-test, memory, and recall.

These tests exercise the real synthesis pipeline minus the LLM call: the spec
object is constructed directly and pushed through the exact build → self-test →
save → recall path the mission uses.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from engine.immune.antibody import (
    AntibodyLab,
    AntibodySpec,
    antibody_sweep,
    load_antibodies,
)
from engine.immune.detection import DetectionFinding

VULNERABLE = "def run_shell(cmd):\n    return os.system(cmd)\n"
PATCHED = "def run_shell(cmd):\n    return subprocess.run(cmd, shell=False)\n"


def _finding() -> DetectionFinding:
    return DetectionFinding(
        rule_id="SENT-PY-008", name="Shell command via os.system", cwe="CWE-78",
        severity="high", file="executors.py", line=2, col=12,
        evidence="return os.system(cmd)", hint="Use subprocess with argv list",
    )


def _spec() -> AntibodySpec:
    return AntibodySpec(
        rule_name="os-system-sink", cwe="CWE-78", severity="ERROR",
        pattern_regex=r"os\.system\s*\(",
        message="os.system executes shell strings; use subprocess with an argv list.",
    )


def test_antibody_selftest_passes_and_memorizes(tmp_path: Path):
    lab = AntibodyLab(provider=None, root=tmp_path)
    antibody = lab.build_and_test(_spec(), finding=_finding(),
                                  vulnerable_code=VULNERABLE, patched_code=PATCHED)
    assert antibody.validated is True
    assert antibody.vulnerable_match is True
    assert antibody.patched_clean is True
    assert antibody.rule_id == "arbalest-antibody-os-system-sink-cwe-78-cwe-78"

    lab.registry.save(antibody)
    yaml_path = tmp_path / ".arbalest" / "antibodies" / f"{antibody.rule_id}.yml"
    assert yaml_path.is_file()
    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    rule = doc["rules"][0]
    assert rule["id"] == antibody.rule_id
    assert rule["metadata"]["arbalest-antibody"] is True
    assert rule["languages"] == ["python"]


def test_antibody_rejects_regex_matching_patched_code(tmp_path: Path):
    lab = AntibodyLab(provider=None, root=tmp_path)
    sloppy = AntibodySpec(
        rule_name="too-broad", cwe="CWE-78", severity="ERROR",
        pattern_regex=r"run_shell\s*\(",   # matches the patched sample too
        message="too broad",
    )
    antibody = lab.build_and_test(sloppy, finding=_finding(),
                                  vulnerable_code=VULNERABLE, patched_code=PATCHED)
    assert antibody.validated is False
    assert "patched sample" in antibody.validation_detail


def test_registry_dedup_generates_new_rule_id(tmp_path: Path):
    lab = AntibodyLab(provider=None, root=tmp_path)
    first = lab.build_and_test(_spec(), finding=_finding(),
                               vulnerable_code=VULNERABLE, patched_code=PATCHED)
    lab.registry.save(first)
    second = lab.build_and_test(_spec(), finding=_finding(),
                                vulnerable_code=VULNERABLE, patched_code=PATCHED)
    assert second.rule_id != first.rule_id
    assert second.rule_id.startswith(first.rule_id)


def test_learning_loop_recalls_antibody(tmp_path: Path):
    """The closed loop: saved antibody re-arms the sweep and re-detects the sink."""
    lab = AntibodyLab(provider=None, root=tmp_path)
    antibody = lab.build_and_test(_spec(), finding=_finding(),
                                  vulnerable_code=VULNERABLE, patched_code=PATCHED)
    lab.registry.save(antibody)

    loaded = load_antibodies(tmp_path)
    assert len(loaded) == 1
    hits = antibody_sweep("elsewhere/impl.py", VULNERABLE, loaded)
    assert len(hits) == 1
    assert hits[0].learned is True
    assert hits[0].rule_id == antibody.rule_id
    assert hits[0].cwe == "CWE-78"


def test_antibody_sweep_respects_language(tmp_path: Path):
    lab = AntibodyLab(provider=None, root=tmp_path)
    antibody = lab.build_and_test(_spec(), finding=_finding(),
                                  vulnerable_code=VULNERABLE, patched_code=PATCHED)
    lab.registry.save(antibody)
    loaded = load_antibodies(tmp_path)
    assert antibody_sweep("impl.js", VULNERABLE, loaded) == []


def test_known_antibody_patterns_summarize_saved_antibodies(tmp_path):
    from engine.services.scan_pipeline import known_antibody_patterns

    assert known_antibody_patterns(tmp_path) is None
    lab = AntibodyLab(provider=None, root=tmp_path)
    antibody = lab.build_and_test(_spec(), finding=_finding(),
                                  vulnerable_code=VULNERABLE, patched_code=PATCHED)
    lab.registry.save(antibody)
    patterns = known_antibody_patterns(tmp_path)
    assert patterns and patterns[0].startswith(f"{antibody.rule_id} ({antibody.cwe}): ")
