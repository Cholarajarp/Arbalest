"""Fixture organism — the vulnerable sink."""
import os


def run_shell(cmd):
    return os.system(cmd)
