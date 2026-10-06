"""Fixture organism — public API boundary of the attack chain."""
from flask import Flask, request

from handlers import run_scan

app = Flask(__name__)


@app.route("/scan")
def scan_endpoint():
    repo = request.args.get("repo", ".")
    return run_scan(repo)
