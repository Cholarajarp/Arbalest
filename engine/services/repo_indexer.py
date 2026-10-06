"""Bounded legacy-source ingestion for live Arbalest demonstrations."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from pathlib import PurePosixPath


class RepositoryIndexError(ValueError):
    """A source inventory violates the ingestion safety contract."""


class RepoIndexer:
    """Produces validated repository-relative source blobs for coding agents."""

    max_files = 32
    max_file_bytes = 128 * 1024
    max_total_bytes = 256 * 1024
    source_extensions = frozenset(
        {
            ".py",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".dart",
            ".go",
            ".rs",
            ".java",
            ".kt",
            ".kts",
            ".php",
            ".rb",
            ".cs",
            ".json",
            ".toml",
            ".xml",
            ".yaml",
            ".yml",
            ".txt",
            ".sql",
        }
    )
    source_filenames = frozenset(
        {
            "Dockerfile",
            "Gemfile",
            "Makefile",
            "build.gradle",
            "compose.yaml",
            "compose.yml",
            "docker-compose.yaml",
            "docker-compose.yml",
            "go.mod",
            "package.json",
            "pom.xml",
            "pyproject.toml",
            "requirements.txt",
            "setup.cfg",
            "tsconfig.json",
        }
    )
    ignored_directories = frozenset(
        {
            ".git",
            ".hg",
            ".mypy_cache",
            ".next",
            ".pytest_cache",
            ".ruff_cache",
            ".svn",
            "__pycache__",
            "build",
            "coverage",
            "dist",
            "node_modules",
            "target",
            "venv",
            ".venv",
        }
    )
    ignored_filenames = frozenset(
        {
            "Cargo.lock",
            "package-lock.json",
            "pnpm-lock.yaml",
            "poetry.lock",
            "uv.lock",
            "yarn.lock",
        }
    )


    def load_from_directory(self, root_path: str) -> dict[str, str]:
        """Load source files from a real directory for authentic security analysis."""

        root = Path(root_path).resolve()
        if not root.is_dir():
            raise RepositoryIndexError(f"Repository root does not exist or is not a directory: {root_path!r}")

        candidates: list[tuple[tuple[int, int, int, str], Path, str]] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                rel_path = path.relative_to(root).as_posix()
            except ValueError:
                continue
            if not self.is_supported_source_path(rel_path):
                continue
            candidates.append((_source_priority(rel_path), path, rel_path))

        sources: dict[str, str] = {}
        total_bytes = 0
        for _, path, rel_path in sorted(candidates):
            try:
                if path.stat().st_size > self.max_file_bytes:
                    continue
            except OSError:
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue  # Skip binary, non-utf8, or unreadable files

            size = len(content.encode("utf-8"))
            if size > self.max_file_bytes or total_bytes + size > self.max_total_bytes:
                continue
            sources[rel_path] = content
            total_bytes += size
            if len(sources) >= self.max_files:
                break

        return self.validate_sources(sources)

    @classmethod
    def is_supported_source_path(cls, rel_path: str) -> bool:
        """Return true when a repository-relative path is eligible for indexing."""
        try:
            normalized = _safe_path(rel_path)
        except RepositoryIndexError:
            return False

        path = PurePosixPath(normalized)
        parts = path.parts
        if any(part.startswith(".") or part in cls.ignored_directories for part in parts):
            return False
        if path.name in cls.ignored_filenames:
            return False
        return path.suffix.lower() in cls.source_extensions or path.name in cls.source_filenames

    def validate_sources(self, sources: Mapping[str, str]) -> dict[str, str]:
        """Copy and validate sources before sending them to agents or Docker."""
        if not sources or len(sources) > self.max_files:
            raise RepositoryIndexError(f"Source inventory must contain 1 to {self.max_files} files")
        normalized: dict[str, str] = {}
        total_bytes = 0
        for raw_path, content in sources.items():
            path = _safe_path(raw_path)
            if not isinstance(content, str):
                raise RepositoryIndexError(f"Source {path!r} must be text")
            size = len(content.encode("utf-8"))
            if size > self.max_file_bytes:
                raise RepositoryIndexError(f"Source {path!r} exceeds the per-file size limit")
            total_bytes += size
            if total_bytes > self.max_total_bytes:
                raise RepositoryIndexError("Source inventory exceeds the total size limit")
            normalized[path] = content
        return normalized




def _safe_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value or value.startswith("/"):
        raise RepositoryIndexError(f"Unsafe repository path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RepositoryIndexError(f"Unsafe repository path: {value!r}")
    return path.as_posix()


def _source_priority(rel_path: str) -> tuple[int, int, int, str]:
    path = PurePosixPath(rel_path)
    lower = rel_path.lower()
    name = path.name
    keyword_rank = 0 if any(
        keyword in lower
        for keyword in (
            "app",
            "api",
            "auth",
            "controller",
            "database",
            "db",
            "handler",
            "main",
            "route",
            "security",
            "server",
            "service",
        )
    ) else 1
    manifest_rank = 0 if name in RepoIndexer.source_filenames else 1
    extension_rank = {
        ".py": 0,
        ".ts": 0,
        ".tsx": 0,
        ".js": 1,
        ".jsx": 1,
        ".go": 2,
        ".rs": 2,
        ".java": 3,
        ".kt": 3,
        ".php": 4,
        ".rb": 4,
    }.get(path.suffix.lower(), 5)
    category_rank = 0 if keyword_rank == 0 and manifest_rank == 1 else 1 if manifest_rank == 0 else 2
    return (category_rank, extension_rank, len(path.parts), lower)


__all__ = ["RepoIndexer", "RepositoryIndexError"]
