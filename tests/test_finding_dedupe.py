"""Cross-agent restatement dedupe: one vulnerability, one report row."""

from __future__ import annotations

from engine.agents.architect_agent import Severity, ThreatFinding
from engine.services.scan_pipeline import _summary_tokens


def _finding(fid: str, cwe: str, summary: str, nodes: list[str]) -> ThreatFinding:
    return ThreatFinding(
        finding_id=fid, cwe=cwe, severity=Severity.HIGH, summary=summary,
        affected_nodes=nodes, evidence=["evidence"],
    )


# Real shapes observed in a live scan: the specialist reports, then the
# correlation agent restates the same flaw with its own wording and a
# freshly minted FIND-xxx id.
SAST_OPEN_REDIRECT = _finding(
    "SAST-305f6aa3626e715e", "CWE-601",
    "SAST: Open Redirect — CWE-601. The /go endpoint redirects to a URL supplied by the client without validation.",
    ["subtle.py"],
)
RAG_OPEN_REDIRECT = _finding(
    "FIND-003", "CWE-601",
    "Open redirect in /go endpoint redirects to user-supplied URL without validation.",
    ["subtle.py"],
)
SAST_WEAK_RANDOM = _finding(
    "SAST-0974057a642c31d6", "CWE-311",
    "SAST: Weak Random Token — CWE-311. Session tokens are generated using the predictable random module.",
    ["subtle.py"],
)
RAG_WEAK_RANDOM = _finding(
    "FIND-005", "CWE-311",
    "Session token generated with predictable random module.",
    ["subtle.py"],
)
# A genuinely different flaw in the same file must survive.
SAST_XSS_SAME_FILE = _finding(
    "SAST-6bd1e88ebecc323b", "CWE-79",
    "SAST: Stored XSS — CWE-79. Comment text is embedded into an HTML page without sanitization.",
    ["subtle.py"],
)
# Same CWE, same file, but a *different* sink: must also survive.
XSS_OTHER_SINK = _finding(
    "SAST-aaaaaaaaaaaaaaaa", "CWE-79",
    "SAST: Reflected XSS — CWE-79. The search query is reflected into the page title unescaped.",
    ["subtle.py"],
)


def _dedupe(findings):
    from engine.services.scan_pipeline import _summary_tokens as tokens_of  # noqa: F401

    seen: set = set()
    accepted: list = []
    kept: list = []
    for finding in findings:
        key = (finding.cwe.upper(), " ".join(finding.summary.lower().split()), tuple(sorted(finding.affected_nodes)))
        if finding.finding_id in seen or key in seen:
            continue
        toks = _summary_tokens(finding.summary)
        nodes = tuple(sorted(finding.affected_nodes))
        if any(
            cwe == finding.cwe.upper() and nodes == prior_nodes
            and (len(toks & prior) / len(toks | prior)) >= 0.5
            for prior, cwe, prior_nodes in accepted
        ):
            continue
        seen.add(finding.finding_id)
        seen.add(key)
        accepted.append((toks, finding.cwe.upper(), nodes))
        kept.append(finding)
    return kept


def test_restatement_collapses_to_specialist_original():
    kept = _dedupe([SAST_OPEN_REDIRECT, RAG_OPEN_REDIRECT, SAST_WEAK_RANDOM, RAG_WEAK_RANDOM])
    assert [f.finding_id for f in kept] == ["SAST-305f6aa3626e715e", "SAST-0974057a642c31d6"]


def test_different_flaws_in_same_file_survive():
    kept = _dedupe([SAST_OPEN_REDIRECT, SAST_XSS_SAME_FILE, XSS_OTHER_SINK])
    assert len(kept) == 3


def test_summary_tokens_drop_noise():
    tokens = _summary_tokens("The /go endpoint redirects to a URL supplied by the client")
    assert "endpoint" in tokens and "redirects" in tokens
    assert "the" not in tokens and "user" not in tokens
