# Intentionally vulnerable service (immune wargame demo)

> **Warning:** This file contains synthetic vulnerabilities for an Arbalest demonstration. Never deploy or reuse it as an application template.

`app.py` contains a command injection (`subprocess.run(..., shell=True)`) and a code injection (`eval`) reachable from public routes. `arbalest immune` patches each finding and attacks the patch in the sandbox. Proposed patches are staged in `.arbalest/proposed-heals/` and the source is left unchanged unless you pass `--deploy`. Run it on a copy if you plan to deploy.
