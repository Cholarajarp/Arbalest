"""Bounded, containment-safe source collection and deterministic recon."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".mypy_cache", ".ruff_cache", ".tox", "dist", "build", ".next",
    ".pytest_cache", ".idea", ".vscode", "chroma_db", ".arbalest",
})

SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".rb",
    ".java", ".kt", ".cs", ".php", ".c", ".cpp", ".h", ".hpp",
    ".yaml", ".yml", ".toml", ".json", ".env", ".cfg", ".ini",
    ".tf", ".hcl", ".dockerfile", ".xml", ".gradle", ".lock",
})

MANIFEST_NAMES = frozenset({
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "pom.xml",
    "Gemfile", "Gemfile.lock", "build.gradle", "setup.cfg",
        "uv.lock", "composer.json", "composer.lock", "packages.lock.json",
})

# Runtime-version declarations collected for base-image/EOL awareness; they
# are not package manifests and never enter dependency coverage.
RUNTIME_DECLARATION_NAMES = frozenset({
    ".nvmrc", ".node-version", ".python-version", ".ruby-version", ".tool-versions",
})


def is_runtime_declaration(fname: str) -> bool:
    lower = fname.lower()
    return (
        lower in RUNTIME_DECLARATION_NAMES
        or lower == "dockerfile"
        or lower.startswith("dockerfile.")
        or lower.endswith(".dockerfile")
    )

MAX_FILE_BYTES = 256 * 1024
MAX_SOURCE_FILES = 2_000
MAX_TOTAL_BYTES = 16 * 1024 * 1024

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
    """Attack-surface snapshot with explicit collection coverage."""

    files: dict[str, str] = field(default_factory=dict)
    total_files: int = 0
    language_counts: dict[str, int] = field(default_factory=dict)
    manifests: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    sink_hits: int = 0
    skipped_files: int = 0
    skipped_bytes: int = 0
    collection_complete: bool = True
    coverage_notes: list[str] = field(default_factory=list)
    root_path: str = ""
    scope_kind: str = "repository"
    base_revision: str | None = None
    head_revision: str | None = None
    changed_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    renamed_files: list[list[str]] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        return {
            "total_files": self.total_files,
            "languages": self.language_counts,
            "manifests": self.manifests,
            "entrypoints": self.entrypoints,
            "sink_hits": self.sink_hits,
            "skipped_files": self.skipped_files,
            "skipped_bytes": self.skipped_bytes,
            "collection_complete": self.collection_complete,
            "coverage_notes": self.coverage_notes,
            "root_path": self.root_path,
            "scope_kind": self.scope_kind,
            "base_revision": self.base_revision,
            "head_revision": self.head_revision,
            "changed_files": self.changed_files,
            "deleted_files": self.deleted_files,
            "renamed_files": self.renamed_files,
        }


def _language_of(rel_path: str) -> str:
    ext = Path(rel_path).suffix.lower()
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "react", ".tsx": "react", ".go": "go", ".rs": "rust",
        ".rb": "ruby", ".java": "java", ".kt": "kotlin", ".cs": "csharp",
        ".php": "php", ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
    }.get(ext, ext.lstrip(".") or "other")


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _collect_sources(target: Path) -> tuple[dict[str, str], int, int, list[str]]:
    root = target.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"source target is not a directory: {target}")

    sources: dict[str, str] = {}
    skipped_files = 0
    skipped_bytes = 0
    notes: set[str] = set()
    total_bytes = 0
    stop = False

    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        safe_dirs: list[str] = []
        for dirname in dirs:
            child = current_path / dirname
            try:
                resolved = child.resolve(strict=True)
            except OSError:
                skipped_files += 1
                notes.add("unreadable directories skipped")
                continue
            if dirname in SKIP_DIRS or child.is_symlink() or not _inside(root, resolved):
                if dirname not in SKIP_DIRS:
                    skipped_files += 1
                    notes.add("symlinked or out-of-root directories skipped")
                continue
            safe_dirs.append(dirname)
        dirs[:] = safe_dirs

        for fname in sorted(files):
            fpath = current_path / fname
            if (fpath.suffix.lower() not in SOURCE_EXTENSIONS and fname not in MANIFEST_NAMES
                    and not is_runtime_declaration(fname)):
                continue
            if len(sources) >= MAX_SOURCE_FILES:
                notes.add(f"source file limit reached ({MAX_SOURCE_FILES})")
                stop = True
                break
            try:
                if fpath.is_symlink():
                    skipped_files += 1
                    notes.add("symlinked files skipped")
                    continue
                resolved = fpath.resolve(strict=True)
                if not _inside(root, resolved) or not resolved.is_file():
                    skipped_files += 1
                    notes.add("non-regular or out-of-root files skipped")
                    continue
                size = resolved.stat().st_size
                if size > MAX_FILE_BYTES:
                    skipped_files += 1
                    skipped_bytes += size
                    notes.add(f"files larger than {MAX_FILE_BYTES} bytes skipped")
                    continue
                if total_bytes + size > MAX_TOTAL_BYTES:
                    skipped_files += 1
                    skipped_bytes += size
                    notes.add(f"aggregate source limit reached ({MAX_TOTAL_BYTES} bytes)")
                    stop = True
                    break
                content = resolved.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                skipped_files += 1
                notes.add("unreadable files skipped")
                continue
            rel = resolved.relative_to(root).as_posix()
            sources[rel] = content
            total_bytes += size
        if stop:
            break

    return sources, skipped_files, skipped_bytes, sorted(notes)


def collect_sources(target: Path) -> dict[str, str]:
    """Return a bounded map of regular files contained by *target*."""
    return _collect_sources(target)[0]


def run_recon(target: Path) -> ReconReport:
    """Index sources, map the static attack surface, and report coverage."""
    sources, skipped_files, skipped_bytes, notes = _collect_sources(target)
    report = ReconReport(
        files=sources,
        total_files=len(sources),
        skipped_files=skipped_files,
        skipped_bytes=skipped_bytes,
        collection_complete=not notes,
        coverage_notes=notes,
        root_path=str(target.resolve()),
    )
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
