"""RECON — real source collection and attack-surface statistics."""

from __future__ import annotations

from pathlib import Path

from engine.services.source_collector import collect_sources, run_recon

VULN_APP = '''
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.run(f"ping {host}", shell=True, capture_output=True)
'''

REQUIREMENTS = "pyyaml==3.13\nrequests==2.28.1\n"


def _make_repo(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir(parents=True)
    (tmp_path / "app" / "main.py").write_text(VULN_APP, encoding="utf-8")
    (tmp_path / "app" / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8")
    (tmp_path / "app" / "static").mkdir()
    (tmp_path / "app" / "static" / "ui.js").write_text("document.write(location.hash);", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config.py").write_text("eval('x')", encoding="utf-8")  # must be skipped
    return tmp_path


def test_collect_sources_skips_ignored_dirs(tmp_path):
    repo = _make_repo(tmp_path)
    sources = collect_sources(repo)
    assert "app/main.py" in sources
    assert "app/requirements.txt" in sources
    assert "app/static/ui.js" in sources
    assert not any(".git" in rel for rel in sources)


def test_recon_counts_languages_and_manifests(tmp_path):
    repo = _make_repo(tmp_path)
    report = run_recon(repo)
    assert report.total_files == 3
    assert report.language_counts.get("python") == 1
    assert report.language_counts.get("javascript") == 1
    assert report.manifests == ["app/requirements.txt"]


def test_recon_maps_entrypoints_and_sinks(tmp_path):
    repo = _make_repo(tmp_path)
    report = run_recon(repo)
    assert "app/main.py" in report.entrypoints          # @app.route detected
    assert report.sink_hits >= 1                        # subprocess.run + shell=True signature


def test_recon_summary_shape(tmp_path):
    repo = _make_repo(tmp_path)
    summary = run_recon(repo).summary()
    assert {"total_files", "languages", "manifests", "entrypoints", "sink_hits"} <= set(summary)
