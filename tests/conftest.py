"""Shared fixtures for the Arbalest test suite."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(autouse=True)
def _no_ai_keys(monkeypatch):
    """Guarantee tests exercise the real 'unarmed core' error paths."""
    real_which = shutil.which

    def isolated_which(command: str, *args, **kwargs):
        if command in {"codex", "claude"}:
            return None
        return real_which(command, *args, **kwargs)

    monkeypatch.setattr(shutil, "which", isolated_which)
    from engine.services.provider_catalog import builtin_specs

    provider_vars = {
        name
        for spec in builtin_specs().values()
        for name in (*spec.key_env, *((spec.base_url_env,) if spec.base_url_env else ()))
    }
    for var in sorted(provider_vars | {
        "AI_API_KEY", "AI_BASE_URL", "OPENAI_API_KEY", "OPENAI_BASE_URL",
        "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "NEBIUS_API_KEY", "NEBIUS_PROJECT_ID",
        "ARBALEST_PROVIDER", "ARBALEST_MODEL", "ARBALEST_SANDBOX_BACKEND", "TAVILY_API_KEY",
        "ARBALEST_PROVIDERS_FILE",
    }):
        monkeypatch.delenv(var, raising=False)
    # Never pick up an operator's real provider file from the CWD or home.
    monkeypatch.setenv("ARBALEST_PROVIDERS_FILE", str(Path(__file__).parent / "__no_providers_file__.json"))
    # MCP protocol tests use isolated temporary directories. Opt into the
    # deliberately unsafe compatibility mode there; the runtime test removes
    # this variable to prove production's default-deny behavior.
    monkeypatch.setenv("ARBALEST_MCP_UNSAFE_ALLOW_ANY_ROOT", "1")
    # Subprocess CLI tests inherit this, so a real .env in the repo is never read.
    monkeypatch.setenv("ARBALEST_SKIP_DOTENV", "1")
