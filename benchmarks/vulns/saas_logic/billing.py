import time
from flask import Flask, request

app = Flask(__name__)
BALANCES = {}

@app.route("/signup", methods=["POST"])
def signup():
    attrs = request.json
    return {"username": attrs["username"], "role": attrs.get("role", "member"), "balance": attrs.get("balance", 0)}

@app.route("/admin/stats")
def admin_stats():
    if request.args.get("is_admin") == "1":
        return {"revenue": sum(BALANCES.values())}
    return "forbidden", 403

@app.route("/transfer", methods=["POST"])
def transfer():
    body = request.json
    balance = BALANCES.get(body["from"], 0)
    if balance >= body["amount"]:
        time.sleep(0.05)
        BALANCES[body["from"]] = balance - body["amount"]
    return "ok"
