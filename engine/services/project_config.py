"""Strict credential-free project settings and offline readiness checks."""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from engine.agents.sca_agent import collect_dependencies
from engine.services.provider_catalog import ProviderProtocol, get_provider_spec
from engine.services.runtime import resolve_api_key, sandbox_backend
from engine.services.scan_workflow import ScanOptions
from engine.services.source_collector import run_recon


@dataclass(frozen=True, slots=True)
class ProjectConfig:
    provider: str | None = None
    model: str | None = None
    scan: ScanOptions = field(default_factory=ScanOptions)

    def preflight(self, target: Path) -> dict[str, Any]:
        """No provider calls, sandbox execution, or credential values in output."""
        root = target.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("target must be a directory")
        provider = self.provider or os.environ.get("ARBALEST_PROVIDER", "nebius")
        spec = get_provider_spec(provider)
        key, variables = resolve_api_key(provider)
        local = spec.protocol is ProviderProtocol.LOCAL_CLI
        ready = bool(key) or not variables or local
        checks: list[dict[str, Any]] = [{
            "name": "provider", "ok": ready,
            "detail": "credential presence checked only; authentication/model availability not verified",
        }]
        if local:
            executable = "claude" if provider == "claude-cli" else "codex"
            ready = shutil.which(executable) is not None
            checks.append({"name": "provider_cli", "ok": ready, "detail": "authentication not verified"})
        try:
            backend = sandbox_backend()
            checks.append({"name": "sandbox_configuration", "ok": True,
                           "detail": f"{backend}; isolation not verified: run sandbox-check"})
        except RuntimeError:
            backend = "misconfigured"
            checks.append({"name": "sandbox_configuration", "ok": False, "detail": "invalid sandbox environment"})
        recon = run_recon(root)
        dependencies, coverage = collect_dependencies(recon.files)
        checks.append({"name": "source_collection", "ok": recon.collection_complete and bool(recon.files),
                       "detail": f"{len(recon.files)} source files"})
        checks.append({"name": "dependency_inventory", "ok": coverage.complete, "detail": coverage.detail})
        return {
            "ready": all(check["ok"] for check in checks), "offline": True,
            "provider": provider, "model": self.model or os.environ.get("ARBALEST_MODEL"),
            "sandbox": backend, "checks": checks, "scan": asdict(self.scan),
            "dependencies": len(dependencies), "dependency_coverage": coverage.as_dict(),
            "coverage": recon.summary(),
            "cost_note": "Reservations use operator assumptions; actual provider billing is not measured",
        }


def load_project_config(target: Path, config_path: Path | None = None) -> ProjectConfig:
    root = target.resolve(strict=True)
    path = Path(config_path) if config_path is not None else root / "arbalest.json"
    if config_path is None and not path.exists():
        return ProjectConfig()
    if path.stat().st_size > 64_000:
        raise ValueError("project configuration exceeds 64000 bytes")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate configuration field: {key}")
            result[key] = value
        return result
    data = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique)
    if not isinstance(data, dict) or set(data) - {"provider", "model", "scan"}:
        raise ValueError("project configuration accepts only provider, model, scan; credentials belong in environment")
    for name in ("provider", "model"):
        value = data.get(name)
        if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > 300):
            raise ValueError(f"{name} must be a nonempty string")
    if data.get("provider"):
        get_provider_spec(data["provider"])
    scan = data.get("scan", {})
    if not isinstance(scan, dict):
        raise ValueError("scan must be an object")
    return ProjectConfig(data.get("provider"), data.get("model"), ScanOptions.from_mapping(scan))
