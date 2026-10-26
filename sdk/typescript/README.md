# @arbalest/sdk

Dependency-free ESM SDK for **Node.js 22+**, wrapping a separately installed
Arbalest Python CLI. Credentials stay in the inherited process environment.

```typescript
import { Arbalest } from "@arbalest/sdk";

const client = new Arbalest({ timeoutMs: 180_000 });
const result = await client.run("./repository", {
  options: { maxSeconds: 120, maxModelCalls: 20, concurrency: 2 },
});
console.log(result.exitCode, result.complete, result.findings);
```

APIs: `run`, `preflight`, `sbom`, `history`, `compare`. Every operation accepts an
`AbortSignal` and subprocess timeout. Scan exit 1 returns findings; exit 2 throws
`ArbalestError`. Never treat an incomplete report as a clean scan.

By default `arbalest` must be on PATH. To select an interpreter:

```typescript
const client = new Arbalest({
  executable: "/path/to/python",
  args: ["-m", "arbalest_cli"],
  configPath: "./arbalest.toml",
});
```

Requires a compatible CLI supporting `preflight TARGET --format json`,
`scan TARGET -f json -o -` with project configuration/budget/checkpoint flags,
`sbom TARGET -o -`, `history TARGET --limit N`, and
`compare TARGET --before ID --after ID`.

Processes use literal argument arrays and `shell: false`; output is bounded
(default 16 MiB combined stdout/stderr) and strictly parsed as JSON. Timeouts and
abort terminate the direct child, not a portable descendant process tree.
Analysis may share source with configured providers and incur charges. Offline
SBOM/history/comparison do not construct model providers.

Build: `npm ci && npm run build`. Test: `npm test` (Node test runner, fake CLI,
no provider credentials or network needed). No runtime npm dependencies.

Full documentation: [docs/sdk.md](../../docs/sdk.md) in the Arbalest repository.
