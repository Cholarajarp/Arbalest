# Intentionally vulnerable federated fleet fixture

> **Warning:** These directories model synthetic repositories with deliberate vulnerabilities. They are not deployable services.

The fixture demonstrates a cross-repository path:

```text
billing-api → authlib → unsafe session deserialization
```

`authlib/authlib/tokens.py` intentionally calls `pickle.loads`. The downstream services provide import relationships used by `FleetTopology` to construct and display an evidence-backed multi-repository blast radius.

Run the fixture without GitOps because its children are not independent Git repositories:

```powershell
python arbalest_cli.py fleet --target-dir .\examples\hive_fleet --no-gitops
```
