"""The MetacognitiveAgent — governance over Arbalest's own self-modification.

An agent that rewrites its own source needs a constitution. This module is
that constitution, enforced mechanically (never by an LLM's good intentions):

* PROTECTED PATHS — the governor itself, the AI-core arming layer, and the
  sandbox security limits can never appear in a mutation. Mutating the
  governor would be the definition of a logic loop.
* DANGEROUS CONSTRUCTS — the deterministic detection tripwire runs against
  every mutated file; no exploit-class construct (eval, shell=True,
  pickle.loads, hardcoded secrets, …) may enter the organism.
* BOUNDED MUTATIONS — file count and diff size caps keep every evolution
  reviewable.
* LOOP GUARD — mutation hashes are remembered; a mutation identical to any
  previous generation is refused outright.
* CAPABILITY-TEST HYGIENE — generated verification code may not contain
  network, process, or dynamic-execution primitives.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from engine.agents.polyglot_translator import GeneratedCodeBundle, MutationPlan
from engine.immune.detection import sweep_sources
from engine.services.source_collector import collect_sources

PROTECTED_PREFIXES: tuple[str, ...] = (
    "engine/ouroboros/",     # the governor itself — recursion guard
    "engine/services/ai_provider.py",
    "engine/services/docker_manager.py",
    "tests/",
)
FORBIDDEN_RULE_IDS: frozenset[str] = frozenset({
    "SENT-PY-001", "SENT-PY-002", "SENT-PY-003", "SENT-PY-004", "SENT-PY-005",
    "SENT-PY-006", "SENT-PY-007", "SENT-PY-008", "SENT-PY-012", "SENT-PY-013",
})
MAX_MUTATED_FILES = 8
MAX_DIFF_LINES = 400
MAX_MIRROR_CLOSURE = 50   # SandboxLimits.max_source_files = 64; reserve room for
                          # the harness, shims, fixtures and the bundle itself.
_MAX_STATE_HISTORY = 50

_CAPABILITY_FORBIDDEN = re.compile(
    r"\b(subprocess|socket|urllib|requests|httpx|os\.system|pickle|eval\s*\(|exec\s*\(|__import__)\b"
)

_STATE_DIR = ".arbalest/ouroboros"

_STOPWORDS = frozenset({
    "the", "and", "for", "with", "support", "add", "should", "that", "this",
    "into", "from", "its", "are", "can", "new", "use", "when", "then", "own",
})


@dataclass(frozen=True)
class EvolutionTarget:
    """A module of the organism relevant to the requested capability."""

    file: str
    score: float
    matches: list[str]

    @property
    def symbol_hits(self) -> list[str]:
        return self.matches


@dataclass
class GovernanceDecision:
    approved: bool
    vetoes: list[str] = field(default_factory=list)
    mutation_hash: str = ""
    external_deps: list[str] = field(default_factory=list)
    closure: list[str] = field(default_factory=list)


@dataclass
class GenerationState:
    generation: int = 0
    history: list[dict[str, str]] = field(default_factory=list)


class MetacognitiveAgent:
    """Maps the organism inward, and governs every mutation it may accept."""

    def __init__(self, self_root: Path) -> None:
        self.root = Path(self_root).resolve()
        self._state_path = self.root / _STATE_DIR / "state.json"
        self.state = self._load_state()

    # -- organism sensing -----------------------------------------------------
    def self_sources(self) -> dict[str, str]:
        """Arbalest's own source, collected with the same collector it ships."""
        return collect_sources(self.root)

    def request_tokens(self, request: str) -> list[str]:
        return [t for t in re.findall(r"[a-zA-Z]{3,}", request.lower()) if t not in _STOPWORDS]

    def map_meta_graph(self, sources: dict[str, str], request: str) -> list[EvolutionTarget]:
        """Rank the organism's own modules against a capability request.

        Symbol matches (module/function/class names) weigh 3x; body mentions
        weigh 1x. Purely deterministic — the map is evidence, not opinion.
        """
        tokens = self.request_tokens(request)
        targets: list[EvolutionTarget] = []
        for rel, content in sorted(sources.items()):
            if not rel.endswith(".py"):
                continue
            if rel.count("/") > 3:
                continue
            lowered = content.lower()
            matches: list[str] = []
            score = 0.0
            symbol_text = self._symbol_text(rel, content)
            for token in tokens:
                symbol_hits = lowered.count(token) if token in symbol_text else 0
                body_hits = lowered.count(token)
                if symbol_hits:
                    matches.append(f"{token}×{symbol_hits}(symbol)")
                    score += 3 * symbol_hits
                elif body_hits:
                    matches.append(f"{token}×{body_hits}")
                    score += body_hits
            if score > 0:
                targets.append(EvolutionTarget(file=rel, score=score, matches=matches))
        targets.sort(key=lambda t: -t.score)
        return targets

    @staticmethod
    def _symbol_text(rel: str, content: str) -> str:
        parts = [rel.replace("/", " ").replace("_", " ")]
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return " ".join(parts)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                parts.append(node.name.replace("_", " "))
        doc = ast.get_docstring(tree)
        if doc:
            parts.append(doc[:400])
        return " ".join(parts).lower()

    # -- import closure ----------------------------------------------------------
    def import_closure(self, seeds: list[str], sources: dict[str, str], *, cap: int = 48) -> tuple[list[str], list[str]]:
        """Local dependency closure of the mutated files + external dep names.

        Package ``__init__.py`` files along every ancestor path are queued for
        traversal as well — their own imports (re-exports, sibling wiring) are
        part of the closure.
        """
        included: set[str] = set()
        external: set[str] = set()
        queue = list(seeds)
        while queue and len(included) < cap:
            rel = queue.pop(0)
            if rel in included or rel not in sources:
                continue
            included.add(rel)
            for parent in Path(rel).parents:
                init = (parent / "__init__.py").as_posix()
                if init in sources and init not in included:
                    queue.append(init)
            try:
                tree = ast.parse(sources[rel])
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                # (candidate_file, is_primary) — primary misses feed `external`,
                # alias-variant misses are silently dropped.
                candidates: list[tuple[str, bool]] = []
                if isinstance(node, ast.ImportFrom):
                    base_dir = Path(rel).parent
                    if node.level:
                        for _ in range(node.level - 1):
                            base_dir = base_dir.parent
                    if node.level and not node.module:
                        # `from . import sibling` — the package directory itself.
                        for alias in node.names:
                            candidates.append(((base_dir / alias.name).as_posix() + ".py", True))
                            candidates.append(((base_dir / alias.name / "__init__.py").as_posix(), True))
                    else:
                        dotted = (node.module or "").replace(".", "/")
                        module_path = (base_dir / dotted).as_posix() if node.level else dotted
                        if node.module:
                            candidates.append((module_path + ".py", True))
                            candidates.append((module_path + "/__init__.py", True))
                        for alias in node.names:
                            candidates.append((f"{module_path}/{alias.name}.py", False))
                            candidates.append((f"{module_path}/{alias.name}/__init__.py", False))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        base = alias.name.replace(".", "/")
                        candidates.append((base + ".py", True))
                        candidates.append((base + "/__init__.py", True))
                for hit, primary in candidates:
                    if hit in sources:
                        queue.append(hit)
                    elif primary:
                        top = hit.split("/")[0]
                        if top.endswith(".py"):
                            top = top[:-3]
                        if top not in sys.stdlib_module_names:
                            external.add(top)
        return sorted(included), sorted(external)

    # -- governance ----------------------------------------------------------------
    def review_mutation(
        self,
        bundle: GeneratedCodeBundle,
        plan: MutationPlan,
        original_sources: dict[str, str],
    ) -> GovernanceDecision:
        vetoes: list[str] = []
        mutated = {f.path: f.content for f in bundle.files}

        for path in list(mutated) + [m.target_file for m in plan.mutations]:
            for prefix in PROTECTED_PREFIXES:
                if path.startswith(prefix) or path == prefix.rstrip("/"):
                    vetoes.append(f"constitution: {path} is protected ({prefix}*)")

        if len(mutated) > MAX_MUTATED_FILES:
            vetoes.append(f"constitution: {len(mutated)} mutated files exceeds the {MAX_MUTATED_FILES}-file bound")

        diff_lines = 0
        for path, content in mutated.items():
            original = original_sources.get(path, "")
            diff_lines += sum(
                1 for line in difflib.unified_diff(
                    original.splitlines(), content.splitlines(), lineterm="")
                if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
            )
        if diff_lines > MAX_DIFF_LINES:
            vetoes.append(f"constitution: {diff_lines} diff lines exceeds the {MAX_DIFF_LINES}-line bound")

        dangerous = sweep_sources(mutated)
        for finding in dangerous:
            if finding.rule_id in FORBIDDEN_RULE_IDS or finding.severity == "critical":
                vetoes.append(
                    f"constitution: {finding.rule_id} ({finding.name}) at {finding.file}:{finding.line} "
                    f"may not enter the organism — {finding.evidence[:80]}"
                )

        mutation_hash = hashlib.sha256(
            "\n".join(f"{p}:{hashlib.sha256(c.encode()).hexdigest()}" for p, c in sorted(mutated.items())).encode()
        ).hexdigest()[:16]
        if any(h.get("hash") == mutation_hash for h in self.state.history):
            vetoes.append(f"loop guard: mutation {mutation_hash} already applied in a previous generation")

        closure, external_deps = self.import_closure(list(mutated), original_sources)
        if len(closure) >= MAX_MIRROR_CLOSURE:
            vetoes.append(
                f"constitution: mirror install needs {len(closure)} files — exceeds the "
                f"{MAX_MIRROR_CLOSURE}-file sandbox budget"
            )

        return GovernanceDecision(
            approved=not vetoes,
            vetoes=vetoes[:8],
            mutation_hash=mutation_hash,
            external_deps=external_deps,
            closure=closure,
        )

    def review_capability_test(self, code: str) -> list[str]:
        vetoes: list[str] = []
        if len(code) > 16_000:
            vetoes.append("capability test exceeds 16k characters")
        hit = _CAPABILITY_FORBIDDEN.search(code)
        if hit:
            vetoes.append(f"capability test uses prohibited primitive: {hit.group(0)!r}")
        return vetoes

    # -- generation memory ------------------------------------------------------------
    def _load_state(self) -> GenerationState:
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            return GenerationState(generation=int(data.get("generation", 0)), history=list(data.get("history", [])))
        except (OSError, json.JSONDecodeError, ValueError):
            return GenerationState()

    def record_commit(self, mutation_hash: str, issue: str, files: list[str]) -> int:
        self.state.generation += 1
        self.state.history.append({
            "hash": mutation_hash, "issue": issue[:200],
            "files": ", ".join(files[:8]), "generation": str(self.state.generation),
        })
        self.state.history = self.state.history[-_MAX_STATE_HISTORY:]
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._state_path.write_text(json.dumps({
            "generation": self.state.generation, "history": self.state.history,
        }, indent=2), encoding="utf-8")
        return self.state.generation
