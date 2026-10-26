// Fake executable: tests never invoke Python, providers, network or a shell.
const argv = process.argv.slice(2);
const mode = argv.shift();
const command = argv[0];
const report = {
  run_id: "0123456789ab", complete: true, status: "complete",
  findings: [{
    finding_id: "SDK-1", cwe: "CWE-89", severity: "high", summary: "Unsafe query",
    affected_nodes: ["app.py"], evidence: ["line 1"],
  }],
  budget: { reserved_model_calls: 1 },
  scan_archive: { directory: "/target/.arbalest/scans/0123456789ab", seal_sha256: "a".repeat(64) },
};
if (mode === "hang") {
  setInterval(() => {}, 1000);
} else if (mode === "ignore-term") {
  process.on("SIGTERM", () => {});
  setInterval(() => {}, 1000);
} else if (mode === "large" || mode === "large-stderr") {
  (mode === "large" ? process.stdout : process.stderr).write("x".repeat(100_000));
  setInterval(() => {}, 1000);
} else if (mode === "invalid") {
  console.log("banner\n{}");
} else if (mode === "trailing") {
  console.log(JSON.stringify(report) + "\nlog");
} else if (mode === "utf8") {
  process.stdout.write(Buffer.from([0xff]));
} else if (mode === "shape") {
  console.log(JSON.stringify({ findings: [] }));
} else if (mode === "bad-finding") {
  console.log(JSON.stringify({ ...report, findings: [{}] }));
} else if (mode === "error") {
  console.log(JSON.stringify({ error: "incomplete", ...report, complete: false, status: "incomplete" }));
  process.exitCode = 2;
} else if (mode === "error-text") {
  console.error("could not configure provider");
  process.exitCode = 2;
} else if (mode === "other-exit") {
  console.log("{}");
  process.exitCode = 3;
} else {
  let value;
  if (command === "scan") value = report;
  else if (command === "preflight") value = { ready: true };
  else if (command === "sbom") value = { bomFormat: "CycloneDX", components: [] };
  else if (command === "history") value = [{ scan_id: "0123456789ab" }];
  else if (command === "compare") value = { new: [], persistent: [], resolved: [], uncertain: [] };
  else throw new Error("Unexpected command");
  value.argv = argv;
  if (Array.isArray(value)) value[0].argv = argv;
  if (mode === "env") value.inherited = process.env.ARBALEST_SDK_TEST_CREDENTIAL;
  console.log(JSON.stringify(value));
  if (mode === "findings") process.exitCode = 1;
}
