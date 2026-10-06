"""Fixture fleet — billing-api: downstream repository importing the vulnerable library."""
from flask import Flask, request

from authlib.tokens import load_session

app = Flask(__name__)


@app.route("/session")
def session_endpoint():
    blob = request.args.get("blob", "")
    return load_session(blob.encode())
