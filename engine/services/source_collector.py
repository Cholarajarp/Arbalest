"""Shared source collection + reconnaissance statistics.

Single source of truth for CLI and MCP so both see the same attack surface.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".mypy_cache", ".ruff_cache", ".tox", "dist", "build", ".next",
    ".pytest_cache", ".idea", ".vscode", "chroma_db",
})

SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".rb",
    ".java", ".kt", ".cs", ".php", ".c", ".cpp", ".h", ".hpp",
    ".yaml", ".yml", ".toml", ".json", ".env", ".cfg", ".ini",
    ".tf", ".hcl", ".dockerfile", ".xml", ".gradle",
})

MANIFEST_NAMES = frozenset({
    "requirements.txt", "Pipfile", "pyproject.toml", "poetry.lock",
    "package.json", "package-lock.json", "go.mod", "Cargo.toml", "pom.xml",
})

MAX_FILE_BYTES = 256 * 1024

# Recon heuristics: entrypoint + dangerous-sink signatures (deterministic).
_ENTRYPOINT_RE = re.compile(
    r"@(app|bp|api|router)\.(route|get|post|put|delete|patch)\b"
    r"|APIRouter\(|Flask\(|FastAPI\(|app\.listen\(|createServer\("
    r"|@app\.on_event|@api_view|add_api_route\(",
)
_SINK_RE = re.compile(
    r"\beval\s*\(|\bexec\s*\(|os\.system\s*\(|subprocess\.\w+\s*\("
    r"|\bpickle\.loads\s*\(|yaml\.load\s*\(|cursor\.execute\s*\("
    r"|\binnerHTML\s*=|dangerouslySetInnerHTML|child_process\.exec",
)


@dataclass
class ReconReport:
    """Attack-surface snapshot produced by the RECON phase."""

    files: dict[str, str] = field(default_factory=dict)
    total_files: int = 0
    language_counts: dict[str, int] = field(default_factory=dict)
    manifests: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    sink_hits: int = 0

    def summary(self) -> dict[str, object]:
        return {
            "total_files": self.total_files,
            "languages": self.language_counts,
            "manifests": self.manifests,
            "entrypoints": self.entrypoints,
            "sink_hits": self.sink_hits,
        }


def _language_of(rel_path: str) -> str:
    ext = Path(rel_path).suffix.lower()
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "react", ".tsx": "react", ".go": "go", ".rs": "rust",
        ".rb": "ruby", ".java": "java", ".kt": "kotlin", ".cs": "csharp",
        ".php": "php", ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
    }.get(ext, ext.lstrip(".") or "other")


def collect_sources(target: Path) -> dict[str, str]:
    """Walk *target* and return relative-path → content (both entrypoints)."""
    sources: dict[str, str] = {}
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in SOURCE_EXTENSIONS and fname not in MANIFEST_NAMES:
                continue
            try:
                if fpath.stat().st_size > MAX_FILE_BYTES:
                    continue
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(fpath.relative_to(target)).replace("\\", "/")
            sources[rel] = content
    return sources


def run_recon(target: Path) -> ReconReport:
    """RECON phase: index sources and map the static attack surface."""
    report = ReconReport()
    sources = collect_sources(target)
    report.files = sources
    report.total_files = len(sources)
    for rel, content in sources.items():
        lang = _language_of(rel)
        report.language_counts[lang] = report.language_counts.get(lang, 0) + 1
        if Path(rel).name in MANIFEST_NAMES:
            report.manifests.append(rel)
        if _ENTRYPOINT_RE.search(content):
            report.entrypoints.append(rel)
        report.sink_hits += len(_SINK_RE.findall(content))
    report.entrypoints.sort()
    report.manifests.sort()
    return report
