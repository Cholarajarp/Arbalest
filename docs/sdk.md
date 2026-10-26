# Arbalest SDKs

The Python SDK uses the same recon, diff scoping, bounded scan pipeline and
sealed archives as the CLI. The TypeScript SDK invokes an independently installed
Python CLI; it does not reimplement analysis or ship Python.

## Python (Python 3.12+)

Install Arbalest normally; the SDK adds no Python dependencies. Set provider
credentials in the process environment. The Python SDK deliberately does **not**
load `.env` files or accept API keys as arguments.

```python
import asyncio
from pathlib import Path

from engine.sdk import Arbalest, ScanOptions, build_sbom

async def main():
    async with Arbalest(config_path=Path("arbalest.toml")) as client:
        readiness = await client.preflight("./repository")  # offline
        result = await client.run(
            "./repository",
            options=ScanOptions(
                concurrency=2,
                max_seconds=120,
                max_model_calls=20,
                max_cost_usd=1.0,
                per_call_reserve_usd=0.05,
                max_retries=1,
            ),
            checkpoint_dir="./scan-checkpoint",
            resume=False,
            # diff_base="HEAD~1",  # optional Git scope
        )
        print(result.complete, result.status, result.agent_errors)
        print(result.findings)       # list[ThreatFinding], not untyped JSON
        print(result.budget)         # conservative reservation summary
        print(result.report)         # JSON-serializable report
        print(result.archive.directory, result.archive.seal_sha256)
        history = await client.history("./repository", limit=10)
        if len(history) >= 2:
            comparison = await client.compare(
                "./repository", history[1]["scan_id"], history[0]["scan_id"]
            )
            print(comparison)

    # Deterministic, offline inventory from supplied manifest contents:
    document = build_sbom({"requirements.txt": "requests==2.32.3\n"})
    print(document["bomFormat"])  # CycloneDX

asyncio.run(main())
```

### Configuration and result semantics

- `Arbalest(provider=None, model=None, config_path=None)` delegates project
  configuration to `engine.services.project_config.load_project_config`.
  Explicit provider/model arguments override the project's `.provider` and
  `.model`; runtime environment/default selection applies afterward.
- Omitting `run(options=...)` uses the project's `.scan` (`ScanOptions`). An
  explicit `ScanOptions` **replaces** that object; it is not a partial merge.
  `ScanOptions` is exported from `engine.services.scan_workflow` and rejects
  invalid values and unknown fields.
- `preflight(target)` delegates to the loaded project's `preflight(target)` and
  never constructs a provider. History, compare and SBOM are also offline.
  `client.sbom(sources)` is a synchronous convenience for `build_sbom(sources)`.
- `ScanResult` contains `run_id`, `target: Path`, `provider`, `model`, typed
  `findings`, `complete`, `status`, `budget`, JSON-serializable `report`, and
  `archive: ScanArchiveRef`. `agent_errors` and `severity_counts` are convenience
  properties. The report also includes coverage, agent receipts, injection
  detections and the archive directory/seal.
- Findings are returned even when required analysis is incomplete. Always inspect
  `complete`; an empty finding list is **not** proof that analysis succeeded.
  Setup, checkpoint, Git-scope and archive failures propagate as exceptions.
- Every completed pipeline result, including an incomplete one, is sealed with
  `save_scan_archive` under `TARGET/.arbalest/scans/<run_id>`. History and compare
  verify seals; comparison is deterministic occurrence matching, not semantic
  equivalence or proof that every resolved finding was remediated.
- Every run creates a provider through `runtime.build_provider` and closes it in
  `finally`, including pipeline/archive failures and cancellation. Context exit
  (or `await client.aclose()`) cancels and awaits active runs. A closed client
  cannot run again. Use a client in one event loop only.
- Cancellation propagates as `asyncio.CancelledError`, never as a clean result.
  Recon/Git inspection dispatched to worker threads may finish after cancellation;
  they do not write scan archives. Sealing is synchronous so no background archive
  writer is abandoned. Interruptions can leave checkpoint state for resumption.

### Budgets and resume

`max_seconds` is the workflow deadline, not an end-to-end timeout for recon,
Git inspection or archive writing. Checkpoint deadlines include time spent between
creation and resume. Resume validates source, options, provider and recon context;
use the same checkpoint directory and compatible configuration.

Cost reservations are **operator-supplied upper-bound assumptions, not vendor
billing**. `max_cost_usd` requires `per_call_reserve_usd`. Reservations are not
refunded on failure or cancellation; adapter-internal retries may require a larger
`per_call_model_calls` assumption. See `ScanOptions` for all supported Python
fields, including call timeouts and per-call attempt reservations.

## TypeScript / Node.js 22+

The package lives in `sdk/typescript`, has no runtime dependencies, and emits ESM
JavaScript plus declarations. TypeScript and Node types are pinned development
build dependencies. Build/test it with:

```sh
npm --prefix sdk/typescript ci
npm --prefix sdk/typescript test
npm --prefix sdk/typescript pack
```

Install the resulting package in a consumer project. The default executable is
`arbalest` on `PATH`. It must be a compatible installed CLI supporting project
configuration, preflight, scan budgets/checkpoints, SBOM, history and comparison.
No shell script or `.cmd` wrapper is required; on Windows use the installed
`arbalest.exe` console entry point or a Python interpreter directly.

```typescript
import { Arbalest, ArbalestError } from "@arbalest/sdk";

const client = new Arbalest({
  configPath: "./arbalest.toml",
  timeoutMs: 180_000,              // subprocess lifetime, not model budget
  maxOutputBytes: 16 * 1024 * 1024,
  // executable: "/path/to/python",
  // args: ["-m", "arbalest_cli"],
});

const controller = new AbortController();
try {
  const readiness = await client.preflight("./repository");
  const result = await client.run("./repository", {
    signal: controller.signal,
    checkpointDir: "./scan-checkpoint",
    resume: false,
    // diffBase: "HEAD~1",
    options: {
      maxSeconds: 120, maxModelCalls: 20, concurrency: 2, maxRetries: 1,
      maxCostUsd: 1.0, perCallReserveUsd: 0.05,
    },
  });
  console.log(readiness, result.exitCode, result.complete, result.findings);
  console.log(result.budget, result.archive, result.report);
  const inventory = await client.sbom("./repository");
  const history = await client.history("./repository", { limit: 10 });
  console.log(inventory, history);
  // await client.compare("./repository", beforeScanId, afterScanId);
} catch (error) {
  if (error instanceof ArbalestError) {
    console.error(error.kind, error.exitCode);
    // An exit-2 JSON error/incomplete report may be available as error.report.
  } else {
    throw error;
  }
}
```

### Process and wire contract

- `spawn` receives an executable and argument array with `shell: false`, ignored
  stdin, and inherited process environment. Credentials never become SDK
  configuration fields or CLI arguments. The SDK does not write config files.
  `configPath` names an existing shared project config, not credential material.
  The CLI's own environment/dotenv policy still applies.
- `run` invokes `scan TARGET -f json -o -`, with optional `--config`, `--provider`,
  `--model`, `--checkpoint-dir`, `--resume`, `--diff-base`, `--max-seconds`,
  `--max-model-calls`, `--max-cost-usd`, `--per-call-reserve-usd`, `--concurrency`,
  and `--max-retries`. Unspecified flags retain CLI/project defaults.
- Other commands are `preflight TARGET --format json [--config FILE]`,
  `sbom TARGET -o -`, `history TARGET --limit N`, and
  `compare TARGET --before ID --after ID`. Target paths are made absolute relative
  to the client's `cwd` (or the current working directory).
- Exit **0** returns a result. Scan exit **1** also returns a result with
  `exitCode: 1` (findings gate). Exit **2**, other exit codes and signal termination
  throw `ArbalestError` with `kind: "cli"`; exit 1 is not accepted for non-scan
  commands. Do not conflate these with an empty successful scan.
- Output must be one strict UTF-8 JSON document. Banners, fenced JSON, trailing
  logs, concatenated documents and malformed scan shapes are rejected. The full
  JSON report is retained. Optional budget/archive fields are exposed when the
  installed CLI supplies them; missing fields remain `undefined`.
- The combined stdout/stderr cap defaults to 16 MiB. stderr is counted but not
  returned or echoed, since provider diagnostics may contain sensitive material.
  Valid exit-error JSON is available to the caller: treat it as potentially
  sensitive rather than logging blindly.
- All requests accept `signal` and `timeoutMs`; defaults come from the client.
  Abort, timeout and output overflow terminate the direct child (SIGTERM followed
  by SIGKILL after a grace period). Descendant process-tree termination is not
  portable; local CLI providers may have their own child processes.
- Error kinds are `spawn`, `cli`, `json`, `output_limit`, `aborted`, and `timeout`.
  Local invalid arguments throw `TypeError` before invocation.

## Security, scope and integration limits

Scans may send collected source to the configured model provider and use advisory
or threat-intelligence services. They may incur provider charges. Neither SDK
adds telemetry; existing engine/service behavior still applies. Checkpoint and
archive directories contain security findings and should be access-controlled.
SBOM generation performs no advisory lookup and is an inventory of supplied
manifests, not a complete installed environment or transitive dependency graph.

The Python SDK relies on the shared `project_config` API; the Node adapter relies
on the CLI commands/flags above. Those integration surfaces must land with the
parent CLI/config work. SDK unit tests isolate provider calls and use a fake Node
executable; they do not establish compatibility with an older installed CLI or
exercise billable/live provider scans.
