"""Billing service — intentionally vulnerable demo target for Arbalest.

Do NOT deploy. This file exists to demonstrate detection, remediation, and
adversarial verification. Every sink below is a real, reachable attack chain
from a public HTTP route down to a dangerous operation.
"""

import os
import sqlite3
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# Hardcoded credential — CWE-798 (secret scanner target)
DB_PASSWORD = "sup3r_s3cret_prod_password_2026"
API_KEY = "demo_signing_key_a1b2c3d4e5f6_not_real"


def get_db():
    conn = sqlite3.connect("billing.db")
    return conn


@app.route("/invoice")
def invoice():
    # CWE-89 SQL injection — user input concatenated straight into the query.
    invoice_id = request.args.get("id", "")
    conn = get_db()
    cur = conn.cursor()
    query = "SELECT amount, customer FROM invoices WHERE id = '" + invoice_id + "'"
    cur.execute(query)
    row = cur.fetchone()
    return jsonify({"invoice": row})


@app.route("/export")
def export_report():
    # CWE-78 OS command injection — filename flows into a shell.
    name = request.args.get("name", "report")
    cmd = "tar -czf /tmp/" + name + ".tar.gz /var/reports"
    subprocess.run(cmd, shell=True)
    return jsonify({"status": "exported", "file": name})


@app.route("/render")
def render_template_field():
    # CWE-94 code injection — eval on user-controlled expression.
    expr = request.args.get("expr", "1+1")
    result = eval(expr)  # noqa: S307
    return jsonify({"result": result})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
