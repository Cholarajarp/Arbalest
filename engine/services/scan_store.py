"""Lightweight scan result persistence using SQLite.

Stores completed pipeline runs so the dashboard can show scan history,
trending, and allow re-downloading SARIF/findings for any past run.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path("arbalest_scans.db")


class ScanRecord(BaseModel):
    """A completed pipeline scan stored in the database."""

    run_id: str
    target_url: str
    workspace_id: str
    started_at: str
    completed_at: str
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    agents_used: list[str] = Field(default_factory=list)
    findings_json: str = "[]"
    sarif_json: str = "{}"
    status: str = "completed"


class ScanSummary(BaseModel):
    """Lightweight scan summary for listing."""

    run_id: str
    target_url: str
    workspace_id: str
    started_at: str
    completed_at: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    status: str


class ScanStore:
    """Thread-safe SQLite-backed scan persistence."""

    def __init__(self, db_path: Path | str = _DEFAULT_DB_PATH) -> None:
        self._db_path = str(db_path)
        self._ensure_schema()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    run_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    workspace_id TEXT NOT NULL DEFAULT 'default',
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    total_findings INTEGER NOT NULL DEFAULT 0,
                    critical_count INTEGER NOT NULL DEFAULT 0,
                    high_count INTEGER NOT NULL DEFAULT 0,
                    medium_count INTEGER NOT NULL DEFAULT 0,
                    low_count INTEGER NOT NULL DEFAULT 0,
                    agents_used TEXT NOT NULL DEFAULT '[]',
                    findings_json TEXT NOT NULL DEFAULT '[]',
                    sarif_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'completed'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_completed
                ON scans(completed_at DESC)
            """)

    def save_scan(self, record: ScanRecord) -> None:
        """Insert or replace a scan record."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans
                (run_id, target_url, workspace_id, started_at, completed_at,
                 total_findings, critical_count, high_count, medium_count, low_count,
                 agents_used, findings_json, sarif_json, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.run_id,
                    record.target_url,
                    record.workspace_id,
                    record.started_at,
                    record.completed_at,
                    record.total_findings,
                    record.critical_count,
                    record.high_count,
                    record.medium_count,
                    record.low_count,
                    json.dumps(record.agents_used),
                    record.findings_json,
                    record.sarif_json,
                    record.status,
                ),
            )
        logger.info("Saved scan record", extra={"run_id": record.run_id, "findings": record.total_findings})

    def list_scans(self, *, limit: int = 50, offset: int = 0, workspace_prefix: str | None = None) -> list[ScanSummary]:
        """Return recent scans, newest first."""
        with self._connect() as conn:
            if workspace_prefix:
                rows = conn.execute(
                    """
                    SELECT run_id, target_url, workspace_id, started_at, completed_at,
                           total_findings, critical_count, high_count, medium_count, low_count, status
                    FROM scans
                    WHERE workspace_id GLOB ?
                    ORDER BY completed_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (f"{workspace_prefix}*", min(limit, 200), offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT run_id, target_url, workspace_id, started_at, completed_at,
                           total_findings, critical_count, high_count, medium_count, low_count, status
                    FROM scans
                    ORDER BY completed_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (min(limit, 200), offset),
                ).fetchall()
        return [
            ScanSummary(
                run_id=row["run_id"],
                target_url=row["target_url"],
                workspace_id=row["workspace_id"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                total_findings=row["total_findings"],
                critical_count=row["critical_count"],
                high_count=row["high_count"],
                medium_count=row["medium_count"],
                low_count=row["low_count"],
                status=row["status"],
            )
            for row in rows
        ]

    def get_scan(self, run_id: str) -> ScanRecord | None:
        """Retrieve a full scan record by run ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return ScanRecord(
            run_id=row["run_id"],
            target_url=row["target_url"],
            workspace_id=row["workspace_id"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            total_findings=row["total_findings"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            medium_count=row["medium_count"],
            low_count=row["low_count"],
            agents_used=json.loads(row["agents_used"]),
            findings_json=row["findings_json"],
            sarif_json=row["sarif_json"],
            status=row["status"],
        )

    def get_sarif(self, run_id: str) -> dict[str, Any] | None:
        """Retrieve just the SARIF JSON for a run."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT sarif_json FROM scans WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["sarif_json"])

    def get_findings(self, run_id: str) -> list[dict[str, Any]] | None:
        """Retrieve just the findings JSON for a run."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT findings_json FROM scans WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["findings_json"])

    def scan_count(self) -> int:
        """Total number of stored scans."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM scans").fetchone()
        return row["cnt"] if row else 0
