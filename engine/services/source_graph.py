"""File-level architecture graph and evidence for planning without Neo4j.

The ArchitectAgent only accepts a plan whose every mutation targets a node that
exists in the architecture graph it was given. Passing an empty graph therefore
makes a valid plan impossible, which is exactly how ``arbalest fix`` used to
fail on a real run. This module gives the CLI, the MCP server and the missions
a real graph: one node per source file, built from the sources already read.

It is deliberately simple (files, not call edges). The Immune mission has its
own, richer call-graph in ``engine.immune.topology``.
"""

from __future__ import annotations

import posixpath
from collections.abc import Iterable, Mapping

from engine.agents.architect_agent import (
    ArchitectureGraphContext,
    ArchitectureNode,
    Severity,
    ThreatFinding,
)
from engine.immune.detection import DetectionFinding, sweep_sources

MAX_NODES = 600  # ArchitectureGraphContext limit
_MAX_EVIDENCE = 20


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def build_file_graph(
    project_id: str,
    sources: Mapping[str, str],
    *,
    prioritize: Iterable[str] = (),
    entrypoints: Iterable[str] = (),
) -> ArchitectureGraphContext:
    """One node per source file, id = repo-relative posix path.

    ``prioritize`` files (for example the files a finding points at) are kept
    first when the repository is larger than the planner's node budget.
    """
    entry = {_norm(item) for item in entrypoints}
    lookup = {_norm(path): content for path, content in sources.items()}
    ordered: list[str] = []
    seen: set[str] = set()
    for rel in [*(_norm(item) for item in prioritize), *sorted(lookup)]:
        if rel in lookup and rel not in seen:
            seen.add(rel)
            ordered.append(rel)
    nodes = []
    for rel in ordered[:MAX_NODES]:
        content = lookup[rel]
        extension = posixpath.splitext(rel)[1].lstrip(".").lower() or "txt"
        nodes.append(
            ArchitectureNode(
                id=rel,
                labels=["File", extension],
                properties={
                    "path": rel,
                    "language": extension,
                    "lines": content.count("\n") + (0 if content.endswith("\n") or not content else 1),
                    "entrypoint": rel in entry,
                },
            )
        )
    return ArchitectureGraphContext(project_id=project_id, nodes=nodes, edges=[])


def _cwe_key(value: str) -> str:
    return value.strip().upper().replace("_", "-")


def matching_detections(sources: Mapping[str, str], cwe: str) -> list[DetectionFinding]:
    """Deterministic detections whose CWE equals ``cwe`` (no AI involved)."""
    wanted = _cwe_key(cwe)
    return [hit for hit in sweep_sources(dict(sources)) if _cwe_key(hit.cwe) == wanted]


def finding_with_evidence(
    origin: str,
    finding_id: str,
    sources: Mapping[str, str],
    *,
    purpose: str = "Remediation requested",
) -> ThreatFinding:
    """Build the ThreatFinding for a user-supplied id/CWE, grounded in real code.

    When the deterministic detector finds the requested CWE in the sources, the
    affected files and the matching lines are attached, so the planner targets
    the right file instead of guessing. When it finds nothing, the finding is
    returned without locations and the planner works from the CWE alone.
    """
    is_cwe = finding_id.upper().startswith("CWE")
    cwe = _cwe_key(finding_id) if is_cwe else "CWE-Unknown"
    hits = matching_detections(sources, cwe) if is_cwe else []
    files = sorted({hit.file for hit in hits})
    evidence = [f"{hit.file}:{hit.line} {hit.name}: {hit.evidence.strip()[:160]}" for hit in hits[:_MAX_EVIDENCE]]
    severity = Severity.HIGH
    if hits and any(hit.severity == "critical" for hit in hits):
        severity = Severity.CRITICAL
    return ThreatFinding(
        finding_id=f"{origin}-{finding_id}",
        cwe=cwe,
        severity=severity,
        summary=f"{purpose} via {origin} for {finding_id}",
        affected_nodes=files[:100],
        evidence=evidence,
    )
