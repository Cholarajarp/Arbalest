# Intentionally vulnerable single-repository fixture

> **Warning:** This directory contains synthetic vulnerabilities for an Arbalest demonstration. Never deploy or reuse it as an application template.

Expected behaviors include:

- `routes.py` accepts an untrusted repository value.
- `handlers.py` concatenates that value into a command.
- `executors.py` calls `os.system`, creating a CWE-78 path.
- `web.js` uses dynamic evaluation and contains a synthetic credential-like string.
- `safe_utils.py` provides nearby safe patterns for contrast.

Run scans on this fixture or on a disposable copy. Commands that verify and deploy a remediation intentionally modify their target after the exact artifact passes sandbox verification.
