"""Shared fixtures for the Arbalest test suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(autouse=True)
def _no_ai_keys(monkeypatch):
    """Guarantee tests exercise the real 'unarmed core' error paths."""
    for var in ("AI_API_KEY", "NEBIUS_API_KEY", "ARBALEST_PROVIDER", "TAVILY_API_KEY"):
        monkeypatch.delenv(var, raising=False)
