"""Fixture organism — intermediate relay on the attack chain."""
from executors import run_shell


def run_scan(repo):
    command = "git clone " + repo
    return run_shell(command)
