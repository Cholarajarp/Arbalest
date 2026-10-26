"""Offline project/CLI integration, without provider credits or credentials."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import arbalest_cli
from engine.sdk import Arbalest
from engine.services.project_config import load_project_config


def test_defaults_and_overrides(tmp_path):
    assert load_project_config(tmp_path).scan.concurrency == 4
    (tmp_path / "arbalest.json").write_text(json.dumps({
        "provider": "nebius", "scan": {"max_seconds": 45, "max_model_calls": 3},
    }))
    config = load_project_config(tmp_path)
    assert config.provider == "nebius"
    assert config.scan.max_seconds == 45
    assert config.scan.max_model_calls == 3


@pytest.mark.parametrize("text", [
    '{"api_key":"private"}', '{"scan":{"max_seconds":true}}',
    '{"scan":{"max_cost_usd":1}}', '{"scan":{"unknown":1}}',
    '{"provider":3}', '{"scan":{},"scan":{}}', '[]',
])
def test_invalid_configuration_fails_closed(tmp_path, text):
    (tmp_path / "arbalest.json").write_text(text)
    with pytest.raises((ValueError, TypeError)):
        load_project_config(tmp_path)


@pytest.mark.asyncio
async def test_real_sdk_preflight_no_provider_calls(tmp_path, monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "sensitive-test-value")
    monkeypatch.setenv("ARBALEST_SANDBOX_BACKEND", "docker")
    (tmp_path / "app.py").write_text("print('hello')\n")
    async with Arbalest() as client:
        result = await client.preflight(tmp_path)
    assert result["offline"] is True
    assert "sensitive-test-value" not in json.dumps(result)
    assert result["coverage"]["total_files"] == 1


def test_cli_sbom_real_inventory(tmp_path, monkeypatch, capsys):
    (tmp_path / "uv.lock").write_text('version = 1\n[[package]]\nname = "demo"\nversion = "1.2.3"\nsource = {registry = "https://pypi.org/simple"}\n')
    monkeypatch.setattr(sys, "argv", ["arbalest", "sbom", str(tmp_path), "-o", "-"])
    with pytest.raises(SystemExit) as exc:
        arbalest_cli.main()
    assert exc.value.code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["components"][0]["purl"] == "pkg:pypi/demo@1.2.3"


def test_cli_scan_options_merge(tmp_path, monkeypatch):
    (tmp_path / "arbalest.json").write_text('{"provider":"nebius","model":"test-model","scan":{"concurrency":2,"max_seconds":45}}')
    captured = {}
    async def scan(**kwargs):
        captured.update(kwargs)
        return 0
    monkeypatch.setattr(arbalest_cli, "_run_scan", scan)
    monkeypatch.setattr(sys, "argv", ["arbalest", "scan", str(tmp_path), "--concurrency", "3", "--checkpoint-dir", str(tmp_path / "checkpoint"), "--resume"])
    with pytest.raises(SystemExit) as exc:
        arbalest_cli.main()
    assert exc.value.code == 0
    assert captured["scan_options"].concurrency == 3
    assert captured["scan_options"].max_seconds == 45
    assert captured["model_name"] == "test-model"
    assert captured["checkpoint_dir"] == Path(tmp_path / "checkpoint")
    assert captured["resume"]
