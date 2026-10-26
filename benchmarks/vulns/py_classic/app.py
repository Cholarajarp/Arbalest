# Arbalest benchmark fixture — deliberately vulnerable (py_classic).
import os
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name", "")
    import sqlite3
    conn = sqlite3.connect("app.db")
    return str(conn.cursor().execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall())


@app.route("/run")
def run():
    cmd = request.args.get("cmd", "ls")
    return os.popen(cmd).read()


@app.route("/import-session")
def import_session():
    return str(pickle.loads(bytes.fromhex(request.args["session"])))


@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))


DB_PASSWORD = "Sup3rS3cretPr0dPassword!"
