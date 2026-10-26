# Arbalest examples

These examples use **synthetic, intentionally vulnerable code** to demonstrate Arbalest safely. They are test fixtures, not applications or production templates. Never deploy them, connect them to real data, or copy their unsafe patterns into another project.

## Single-repository immune demo

`immune_target/` contains a small Python/JavaScript application with deliberate command injection, dynamic evaluation, and synthetic credential findings.

```powershell
python arbalest_cli.py scan .\examples\immune_target
python arbalest_cli.py immune .\examples\immune_target
```

Run against a disposable copy because verified remediation commands may update the target.

## Federated fleet demo

`hive_fleet/` models three related repositories. A deliberately unsafe deserialization sink in the shared authentication library is reachable from a downstream API, allowing Fleet mode to demonstrate cross-repository topology.

```powershell
python arbalest_cli.py fleet --target-dir .\examples\hive_fleet --no-gitops
```

Use `--no-gitops` because the fixture directories are not independent Git repositories.

## Experimental traffic-event example

`run_sentinel.py` sends one synthetic event to the standalone Sentinel agent using the same provider configuration as the CLI.

```powershell
python .\examples\run_sentinel.py
```

Sentinel is experimental and is not part of the default `arbalest scan` or MCP tool path.
