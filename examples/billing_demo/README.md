# Intentionally vulnerable billing service (scan demo)

> **Warning:** This file contains synthetic vulnerabilities for an Arbalest demonstration. Never deploy or reuse it as an application template. The credentials in it are fake.

`app.py` is a small Flask service with reachable attack chains from public routes to dangerous sinks: SQL injection, command injection, code injection and hardcoded credentials. `arbalest scan` on this directory is expected to return `VULNERABLE` (exit code `1`).
