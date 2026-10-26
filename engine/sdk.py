"""Async, environment-credential-only access to Arbalest's shared scan pipeline."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self

from engine.agents.architect_agent import ThreatFinding
from engine.services.git_scope import resolve_git_diff, scope_recon_to_diff
from engine.services.runtime import build_provider
from engine.services.sbom import build_sbom
from engine.services.scan_archive import (
    ScanArchiveRef,
    compare_scan_archives,
    list_scan_archives,
    save_scan_archive,
)
from engine.services.scan_pipeline import run_agent_swarm
from engine.services.scan_workflow import ScanOptions
from engine.services.source_collector import run_recon


@dataclass(frozen=True, slots=True)
class ScanResult:
    """A scan can return findings and still be incomplete; inspect ``complete``."""

    run_id: str
    target: Path
    provider: str
    model: str
    findings: list[ThreatFinding]
    complete: bool
    status: str
    budget: dict[str, Any]
    report: dict[str, Any]
    archive: ScanArchiveRef

    @property
    def agent_errors(self) -> dict[str, str]:
        return self.report["agent_errors"]

    @property
    def severity_counts(self) -> dict[str, int]:
        return self.report["severity_counts"]


def _target(target: str | Path) -> Path:
    path = Path(target).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise ValueError(f"target is not a directory: {path}")
    return path


def _project_config(target: Path, config_path: Path | None) -> Any:
    # Lazy import keeps offline SBOM/history usable without configuration loading.
    from engine.services.project_config import load_project_config

    return load_project_config(target, config_path)


class Arbalest:
    """A reusable async client. Each run owns a fresh provider, closed in finally.

    Credentials are resolved only by runtime.build_provider from the environment;
    no credential argument or automatic dotenv loading is provided here. Explicit
    provider/model values override project configuration, then runtime defaults.
    Closing the client cancels and awaits its active runs. A closed client cannot
    be reused. Do not share a client between event loops.
    """

    def __init__(
        self,
        *,
        provider: str | None = None,
        model: str | None = None,
        config_path: str | Path | None = None,
    ) -> None:
        self.provider = provider
        self.model = model
        self.config_path = Path(config_path).expanduser().resolve() if config_path is not None else None
        self._closed = False
        self._runs: set[asyncio.Task[ScanResult]] = set()

    async def __aenter__(self) -> Self:
        self._ensure_open()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("Arbalest client is closed")

    async def aclose(self) -> None:
        self._closed = True
        tasks = tuple(self._runs)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def run(
        self,
        target: str | Path,
        options: ScanOptions | None = None,
        checkpoint_dir: str | Path | None = None,
        resume: bool = False,
        diff_base: str | None = None,
    ) -> ScanResult:
        """Scan, seal an archive, and return a JSON-serializable report plus models.

        Pipeline incompleteness is returned, not treated as a clean scan. Setup,
        checkpoint and archive errors propagate; cancellation is never converted
        into a successful or empty result. Passing options replaces config.scan.
        """
        self._ensure_open()
        task = asyncio.create_task(self._run(target, options, checkpoint_dir, resume, diff_base))
        self._runs.add(task)
        try:
            return await task
        finally:
            self._runs.discard(task)

    async def _run(
        self,
        target: str | Path,
        options: ScanOptions | None,
        checkpoint_dir: str | Path | None,
        resume: bool,
        diff_base: str | None,
    ) -> ScanResult:
        started = time.perf_counter()
        root = _target(target)
        config = _project_config(root, self.config_path)
        selected_options = options if options is not None else config.scan
        if not isinstance(selected_options, ScanOptions):
            raise TypeError("options must be ScanOptions")
        recon = await asyncio.to_thread(run_recon, root)
        if diff_base is not None:
            scope = await asyncio.to_thread(resolve_git_diff, root, diff_base)
            recon = scope_recon_to_diff(recon, scope)
        if not recon.files:
            raise ValueError("No source files found in the selected scope")
        provider, provider_name, model_name = build_provider(
            self.provider if self.provider is not None else config.provider,
            self.model if self.model is not None else config.model,
        )
        try:
            swarm = await run_agent_swarm(
                provider, recon.files, recon,
                options=selected_options, checkpoint_dir=checkpoint_dir, resume=resume,
            )
            run_id = uuid.uuid4().hex[:12]
            model = model_name or "cli-default"
            # Keep sealing synchronous: cancellation must not abandon a writer
            # running in a background thread after this method has returned.
            archive = save_scan_archive(root, run_id, swarm, provider=provider_name, model=model)
            report = {
                "run_id": run_id,
                "target": str(root),
                "provider": provider_name,
                "model": model,
                "elapsed_s": round(time.perf_counter() - started, 2),
                "total_findings": len(swarm.findings),
                "status": swarm.status,
                "complete": swarm.complete,
                "agent_errors": swarm.agent_errors,
                "coverage": recon.summary(),
                "severity_counts": swarm.severity_counts,
                "agents": {name: stat.as_dict() for name, stat in swarm.stats.items()},
                "findings": [finding.model_dump(mode="json") for finding in swarm.findings],
                "budget": swarm.budget,
                "harness": {"injection_hits": [hit.model_dump(mode="json") for hit in swarm.injection_hits]},
                "scan_archive": {
                    "directory": str(archive.directory), "seal_sha256": archive.seal_sha256,
                },
            }
            return ScanResult(
                run_id, root, provider_name, model, swarm.findings, swarm.complete,
                swarm.status, swarm.budget, report, archive,
            )
        finally:
            # Shield cleanup from a second cancellation, but await it before
            # propagating cancellation so provider transports cannot leak.
            cleanup = asyncio.create_task(provider.aclose())
            cancelled = False
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    cancelled = True
            cleanup.result()
            if cancelled:
                raise asyncio.CancelledError

    async def preflight(self, target: str | Path) -> dict[str, Any]:
        """Use shared offline project preflight without constructing a provider."""
        self._ensure_open()
        root = _target(target)
        config = _project_config(root, self.config_path)
        return await asyncio.to_thread(config.preflight, root)

    async def history(self, target: str | Path, limit: int = 20) -> list[dict[str, Any]]:
        """List verified local scan archives without provider/network access."""
        self._ensure_open()
        return await asyncio.to_thread(list_scan_archives, _target(target), limit=limit)

    async def compare(self, target: str | Path, before: str, after: str) -> dict[str, Any]:
        """Verify seals and compare deterministic finding occurrences offline."""
        self._ensure_open()
        return await asyncio.to_thread(compare_scan_archives, _target(target), before, after)

    @staticmethod
    def sbom(sources: Mapping[str, str]) -> dict[str, Any]:
        """Build an offline CycloneDX inventory of supplied manifest contents."""
        return build_sbom(sources)


__all__ = ["Arbalest", "ScanOptions", "ScanResult", "build_sbom"]
