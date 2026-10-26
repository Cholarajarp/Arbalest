import assert from "node:assert/strict";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { Arbalest, ArbalestError } from "../dist/index.js";

const fixture = fileURLToPath(new URL("./fixture-cli.mjs", import.meta.url));
const target = "a target ; echo shell-not-used & $(not-expanded)";
const client = (mode = "normal", options = {}) => new Arbalest({
  executable: process.execPath, args: [fixture, mode], timeoutMs: 5000, ...options,
});
const kind = (name, code) => (error) => {
  assert.ok(error instanceof ArbalestError);
  assert.equal(error.kind, name);
  if (code !== undefined) assert.equal(error.exitCode, code);
  return true;
};

test("run uses literal argv, JSON stdout, shared options and findings exit 1", async () => {
  const result = await client("findings", { configPath: "project config.toml" }).run(target, {
    provider: "test", model: "model with spaces", checkpointDir: "checkpoint dir",
    resume: true, diffBase: "HEAD~1",
    options: { maxSeconds: 12, maxModelCalls: 3, maxCostUsd: 0.5,
      perCallReserveUsd: 0.1, concurrency: 2, maxRetries: 0 },
  });
  assert.equal(result.exitCode, 1);
  assert.equal(result.complete, true);
  assert.equal(result.findings[0].finding_id, "SDK-1");
  assert.deepEqual(result.budget, { reserved_model_calls: 1 });
  assert.equal(result.archive.seal_sha256.length, 64);
  assert.deepEqual(result.report.argv, [
    "scan", resolve(target), "-f", "json", "-o", "-", "--config", "project config.toml",
    "--provider", "test", "--model", "model with spaces", "--checkpoint-dir", "checkpoint dir",
    "--diff-base", "HEAD~1", "--resume", "--max-seconds", "12", "--max-model-calls", "3",
    "--max-cost-usd", "0.5", "--per-call-reserve-usd", "0.1", "--concurrency", "2", "--max-retries", "0",
  ]);
});

test("exit 0 returns results", async () => {
  assert.equal((await client().run(target)).exitCode, 0);
});

test("exit 2 remains an error even with valid findings JSON", async () => {
  await assert.rejects(client("error").run(target), (error) => {
    kind("cli", 2)(error);
    assert.equal(error.report.complete, false);
    return true;
  });
  await assert.rejects(client("error-text").run(target), kind("cli", 2));
  await assert.rejects(client("other-exit").run(target), kind("cli", 3));
});

for (const mode of ["invalid", "trailing", "utf8", "shape", "bad-finding"]) {
  test(`rejects malformed JSON or scan shape: ${mode}`, async () => {
    await assert.rejects(client(mode).run(target), kind("json"));
  });
}

test("only scans accept the findings exit code", async () => {
  await assert.rejects(client("findings").preflight(target), kind("cli", 1));
});

test("preflight, SBOM, history and compare use CLI syntax", async () => {
  const sdk = client();
  const preflight = await sdk.preflight(target, { configPath: "explicit.toml" });
  assert.deepEqual(preflight.argv, ["preflight", resolve(target), "--format", "json", "--config", "explicit.toml"]);
  const sbom = await sdk.sbom(target);
  assert.deepEqual(sbom.argv, ["sbom", resolve(target), "-o", "-"]);
  const history = await sdk.history(target, { limit: 7 });
  assert.deepEqual(history[0].argv, ["history", resolve(target), "--limit", "7"]);
  const before = "0123456789ab", after = "fedcba987654";
  const comparison = await sdk.compare(target, before, after);
  assert.deepEqual(comparison.argv, ["compare", resolve(target), "--before", before, "--after", after]);
});

test("credentials inherit environment and never enter argv", async () => {
  process.env.ARBALEST_SDK_TEST_CREDENTIAL = "test-only-env-value";
  try {
    const result = await client("env").preflight(target);
    assert.equal(result.inherited, "test-only-env-value");
    assert.ok(!result.argv.includes("test-only-env-value"));
  } finally {
    delete process.env.ARBALEST_SDK_TEST_CREDENTIAL;
  }
});

for (const mode of ["large", "large-stderr"]) {
  test(`bounds combined output: ${mode}`, async () => {
    await assert.rejects(client(mode, { maxOutputBytes: 1024 }).run(target), kind("output_limit"));
  });
}

test("already-aborted signals do not spawn", async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(client("hang").run(target, { signal: controller.signal }), kind("aborted"));
});

test("abort terminates an active process", async () => {
  const controller = new AbortController();
  const running = client("hang").run(target, { signal: controller.signal });
  setTimeout(() => controller.abort(), 100);
  await assert.rejects(running, kind("aborted"));
});

test("timeouts terminate children, including a SIGTERM-resistant child", async () => {
  for (const mode of ["hang", "ignore-term"]) {
    await assert.rejects(client(mode).run(target, { timeoutMs: 300 }), kind("timeout"));
  }
});

test("spawn errors are distinct", async () => {
  const sdk = new Arbalest({ executable: "__no_arbalest_sdk_executable__" });
  await assert.rejects(sdk.history(target), kind("spawn"));
});

test("validates bounds and identifiers before spawning", async () => {
  assert.throws(() => client("normal", { maxOutputBytes: 0 }), TypeError);
  assert.throws(() => client("normal", { timeoutMs: Infinity }), TypeError);
  assert.throws(() => client("normal", { timeoutMs: 2_147_483_648 }), TypeError);
  await assert.rejects(client().run(target, { options: { maxSeconds: NaN } }), TypeError);
  await assert.rejects(client().history(target, { limit: 101 }), TypeError);
  await assert.rejects(client().compare(target, "../bad", "fedcba987654"), TypeError);
  await assert.rejects(client().run(""), TypeError);
});
