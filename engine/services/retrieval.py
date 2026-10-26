"""BM25 lexical retrieval with security-domain synonym expansion.

Standard library only. This replaces raw keyword counting: term-frequency
saturation and length normalization (BM25) plus a security thesaurus so a
"CWE-89" query retrieves "SQL injection" documents and vice versa.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Sequence

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.-]{1,63}", re.IGNORECASE)

# Security thesaurus: a token in the query expands to its group so vocabulary
# mismatches between ids, abbreviations and prose stop losing matches.
_SYNONYM_GROUPS: tuple[set[str], ...] = (
    {"sql", "sqli", "injection"},
    {"xss", "scripting", "html"},
    {"rce", "execution", "shell", "command"},
    {"ssrf", "forgery", "request"},
    {"idor", "reference", "object"},
    {"lfi", "rfi", "inclusion", "traversal", "path"},
    {"eval", "dynamic", "code"},
    {"deserialization", "unserialization", "unserialize", "pickle", "marshal"},
    {"credential", "secret", "password", "key", "hardcoded"},
    {"authorization", "authentication", "auth", "access"},
    {"csrf", "request", "forgery"},
    {"redirect", "open"},
    {"timing", "comparison", "side"},
    {"random", "predictable", "token", "entropy"},
    {"cipher", "crypto", "cryptographic", "weak", "ecb"},
    {"error", "leak", "disclosure", "stack"},
    {"upload", "file"},
    {"webhook", "signature", "verification"},
    {"tenant", "isolation", "bola"},
)

# CWE ids map to the prose tokens used in advisories.
_CWE_EXPANSIONS: dict[str, tuple[str, ...]] = {
    "cwe-89": ("sql", "injection"),
    "cwe-79": ("xss", "scripting"),
    "cwe-78": ("command", "injection", "shell"),
    "cwe-77": ("command", "injection"),
    "cwe-95": ("eval", "code"),
    "cwe-22": ("path", "traversal"),
    "cwe-98": ("file", "inclusion"),
    "cwe-502": ("deserialization", "unserialization"),
    "cwe-918": ("ssrf", "forgery"),
    "cwe-798": ("hardcoded", "credential"),
    "cwe-862": ("authorization", "missing"),
    "cwe-863": ("authorization", "wrong"),
    "cwe-284": ("access", "control"),
    "cwe-352": ("csrf", "forgery"),
    "cwe-601": ("redirect", "open"),
    "cwe-327": ("weak", "cipher"),
    "cwe-326": ("weak", "cipher"),
    "cwe-330": ("random", "predictable"),
    "cwe-340": ("random", "predictable"),
    "cwe-208": ("timing", "comparison"),
    "cwe-209": ("error", "leak"),
    "cwe-614": ("cookie", "flags"),
    "cwe-347": ("jwt", "verification"),
    "cwe-942": ("cors", "wildcard"),
}

_EXPANSION: dict[str, frozenset[str]] = {
    token: frozenset(group)
    for group in _SYNONYM_GROUPS
    for token in group
}


def tokenize(text: str) -> list[str]:
    return [match.group(0).lower() for match in _TOKEN.finditer(text)]


def expand_query(tokens: Iterable[str]) -> list[str]:
    """Tokens plus their security-synonym and CWE-id expansions."""
    base = [token.lower() for token in tokens]
    expanded: list[str] = list(base)
    for token in base:
        expanded.extend(_EXPANSION.get(token, ()))
        expansion = _CWE_EXPANSIONS.get(token)
        if expansion:
            expanded.extend(expansion)
    return expanded


def bm25_rank(
    query: str,
    documents: Sequence[tuple[str, str]],
    *,
    limit: int,
    k1: float = 1.5,
    b: float = 0.75,
) -> list[tuple[float, str]]:
    """Rank ``(doc_id, text)`` documents against the query. Scores > 0 only."""
    query_tokens = expand_query(tokenize(query))
    if not query_tokens or not documents:
        return []
    doc_tokens = [(doc_id, tokenize(text)) for doc_id, text in documents]
    doc_count = len(doc_tokens)
    avg_length = sum(len(tokens) for _, tokens in doc_tokens) / doc_count
    frequencies: dict[str, int] = {}
    for _, tokens in doc_tokens:
        for token in set(tokens):
            frequencies[token] = frequencies.get(token, 0) + 1
    scores: list[tuple[float, str]] = []
    for doc_id, tokens in doc_tokens:
        if not tokens:
            continue
        term_counts: dict[str, int] = {}
        for token in tokens:
            term_counts[token] = term_counts.get(token, 0) + 1
        score = 0.0
        for term in set(query_tokens):
            count = term_counts.get(term, 0)
            if not count:
                continue
            idf = math.log(1.0 + (doc_count - frequencies.get(term, 0) + 0.5) / (frequencies.get(term, 0) + 0.5))
            score += idf * (count * (k1 + 1.0)) / (count + k1 * (1.0 - b + b * len(tokens) / avg_length))
        if score > 0:
            scores.append((score, doc_id))
    scores.sort(key=lambda item: (-item[0], item[1]))
    return scores[: max(limit, 0)]


__all__ = ["bm25_rank", "expand_query", "tokenize"]
