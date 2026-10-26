# Bounded, durable project workflows

Credentials and sandbox settings remain in your process environment or private
`.env`: `NEBIUS_API_KEY`, `NEBIUS_PROJECT_ID`, `ARBALEST_SANDBOX_BACKEND`.
Do not put credentials into project JSON, SDK arguments, images, or checkpoints.
Existing `.env` files are not modified by these workflows.

Copy `configs/arbalest.json.example` to your target's `arbalest.json`, review the
limits, and select an available model. Unknown fields, duplicate keys, invalid
types, and cost caps without a per-call reservation are rejected. Explicit scan
CLI flags override project configuration; provider/model fall back to runtime
environment settings. SDK options replace the entire project scan-options object.

```sh
arbalest preflight ./repo --format json
arbalest scan ./repo -f json -o - --checkpoint-dir ./repo/.arbalest/workflow
arbalest scan ./repo -f json -o - --checkpoint-dir ./repo/.arbalest/workflow --resume
arbalest sbom ./repo -o ./repo/.arbalest/sbom.cdx.json
```

## Preflight

Offline only: validates configuration, credential presence, source collection,
dependency parser coverage, and sandbox configuration. It does not authenticate,
query a model catalog, spend provider credits, or prove sandbox network isolation.
Use `models` and `sandbox-check` for those live checks. A failed check exits 2.

## Parallel discovery and budgets

SAST dispatches source batches to a bounded parallel worker pool. Independent
secret, dependency, Semgrep (when installed/configured), and Python taint phases
run concurrently; threat correlation runs after discovery. Stable batch ordering
preserves deterministic finding IDs. SAST remains bounded by its documented
character coverage limits; parallelism is not a promise to inspect arbitrary-size
repositories completely.

Controls: `--concurrency`, `--max-seconds`, `--max-model-calls`,
`--per-call-model-calls`, `--call-timeout-seconds`, `--max-retries`,
`--max-cost-usd`, `--per-call-reserve-usd`. A deadline or required phase failure
makes the result incomplete, never secured. Wall time covers pipeline execution;
source collection/report writing are outside the pipeline budget.

Cost accounting is **conservative reservation accounting, not actual billing**.
Supply a defensible worst-case dollar reservation per attempt. Internal vendor
SDK retries are not directly observable: increase `per_call_model_calls` to
cover them. Tool loops reserve their maximum turns up front. Reservations are
not refunded after failures/cancellation. A dollar cap cannot enforce a provider
bill if your assumptions are too low; use provider-side account caps too.

## Recovery

An atomic checkpoint stores credential-redacted findings, phase coverage,
source/options/provider fingerprints, reservations, and attempt counts. It does
not store raw repository files or provider credentials. Evidence quoted directly
from sources is redacted in durable checkpoints. Treat even redacted findings
and repository paths as private data; keep checkpoints under ignored `.arbalest`.
Only one writer can hold a checkpoint directory at once.

Resume requires identical source content, options, provider identity, and scope.
Successful and partial phases are reused; partial coverage is not silently
reinterpreted as complete. Only failed/interrupted phases may retry within the
persisted attempt allowance. The original deadline includes downtime. To change
scope/budgets or restart an expired run, use a **new** checkpoint directory.
Local checkpoints are checksummed for corruption, not authenticated against a
malicious local user. Final reports remain sealed in scan archives.

## Dependency inventories

SCA and CycloneDX use the same offline parser inventory: Python, npm/pnpm/Yarn,
Go, Rust, Composer, RubyGems, NuGet, and limited Maven direct declarations. Exact
supported lock formats and unresolved-source limits are encoded in coverage.
OSV requests are batched, not capped at the first 100 dependencies. Dependency
lookup still requires network access; offline SBOM export does not.

Unsupported, malformed, ranged, non-registry, and unresolved declarations remain
incomplete. Maven parent/BOM/transitive resolution and unsupported ecosystems
still need additional resolvers. No package manager executes untrusted project
scripts. SBOM completeness concerns supplied manifests, not lock freshness or an
installed graph; source-collection incompleteness is included by the CLI.

See [SDKs](sdk.md), [taint analysis](taint-analysis.md), and
[container releases](releases.md) for additional contracts and limitations.
