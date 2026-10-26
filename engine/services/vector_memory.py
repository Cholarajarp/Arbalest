"""Workspace-scoped threat memory using the Python standard library only."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from engine.services.retrieval import bm25_rank, tokenize

logger = logging.getLogger(__name__)
_WORD = re.compile(r"[a-z0-9][a-z0-9_.-]{1,63}", re.IGNORECASE)


class VectorMemory:
    """Persist bounded remediation context and retrieve it by token similarity."""

    def __init__(self, db_path: str | Path) -> None:
        base = Path(db_path)
        base.mkdir(parents=True, exist_ok=True)
        self.db_path = base / "memory.sqlite3"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5.0)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS findings ("
                "finding_id TEXT PRIMARY KEY, summary TEXT NOT NULL, context TEXT NOT NULL, updated_utc TEXT NOT NULL)"
            )

    async def ingest_finding(self, finding_id: str, summary: str, context: str) -> bool:
        safe_id = finding_id[:128]
        safe_summary = summary[:1_000]
        safe_context = context[:1_000]

        def write() -> None:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO findings(finding_id, summary, context, updated_utc) VALUES(?, ?, ?, ?) "
                    "ON CONFLICT(finding_id) DO UPDATE SET summary=excluded.summary, context=excluded.context, "
                    "updated_utc=excluded.updated_utc",
                    (safe_id, safe_summary, safe_context, datetime.now(UTC).isoformat()),
                )

        try:
            await asyncio.to_thread(write)
            return True
        except sqlite3.Error as exc:
            logger.warning("Local memory ingestion failed: %s", type(exc).__name__)
            return False

    async def query_similar(self, query_text: str, n_results: int = 3) -> list[dict[str, Any]]:
        count = min(max(int(n_results), 1), 20)
        query = query_text[:2_000]
        if not tokenize(query):
            return []

        def read() -> list[tuple[str, str, str]]:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT finding_id, summary, context FROM findings ORDER BY updated_utc DESC LIMIT 500"
                ).fetchall()
                return [(str(row[0]), str(row[1]), str(row[2])) for row in rows]

        try:
            rows = await asyncio.to_thread(read)
        except sqlite3.Error as exc:
            logger.warning("Local memory query failed: %s", type(exc).__name__)
            return []
        documents = [(finding_id, f"{summary} {context}") for finding_id, summary, context in rows]
        by_id = {finding_id: (summary, context) for finding_id, summary, context in rows}
        ranked = bm25_rank(query, documents, limit=count)
        return [
            {
                "document": f"Vulnerability: {by_id[doc_id][0]}\nContext: {by_id[doc_id][1]}",
                "metadata": {"finding_id": doc_id, "similarity": round(score, 4)},
            }
            for score, doc_id in ranked
        ]


def _tokens(value: str) -> set[str]:
    return {match.group(0).lower() for match in _WORD.finditer(value)}


_MEMORIES: dict[str, VectorMemory] = {}


def get_vector_memory(workspace: Path | None = None) -> VectorMemory:
    configured = os.environ.get("ARBALEST_MEMORY_PATH", "").strip()
    if configured:
        path = Path(configured).expanduser().resolve()
    elif workspace is not None:
        path = workspace.resolve() / ".arbalest" / "memory"
    else:
        path = Path.cwd().resolve() / ".arbalest" / "memory"
    key = str(path)
    if key not in _MEMORIES:
        _MEMORIES[key] = VectorMemory(path)
    return _MEMORIES[key]


class _LazyVectorMemory:
    async def ingest_finding(self, finding_id: str, summary: str, context: str) -> bool:
        return await get_vector_memory().ingest_finding(finding_id, summary, context)

    async def query_similar(self, query_text: str, n_results: int = 3) -> list[dict[str, Any]]:
        return await get_vector_memory().query_similar(query_text, n_results)


vector_memory = _LazyVectorMemory()

__all__ = ["VectorMemory", "get_vector_memory", "vector_memory"]
