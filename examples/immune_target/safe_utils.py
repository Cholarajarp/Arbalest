"""Fixture organism — clean tissue; the sweep must stay silent here."""
import ast
import hashlib
import subprocess


def parse_payload(raw):
    return ast.literal_eval(raw)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def clone(repo):
    return subprocess.run(["git", "clone", repo], check=False, shell=False)
