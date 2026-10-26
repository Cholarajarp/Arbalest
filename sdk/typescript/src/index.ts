import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { TextDecoder } from "node:util";

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };

export interface Finding extends JsonObject {
  finding_id: string;
  cwe: string;
  severity: string;
  summary: string;
  affected_nodes: string[];
  evidence: string[];
}

export interface ScanReport extends JsonObject {
  run_id: string;
  complete: boolean;
  status: string;
  findings: Finding[];
}

export interface ScanResult {
  /** 1 is a findings gate, not a transport/CLI failure. */
  exitCode: 0 | 1;
  report: ScanReport;
  findings: Finding[];
  complete: boolean;
  budget: JsonObject | undefined;
  archive: JsonObject | undefined;
}

export interface RequestOptions {
  signal?: AbortSignal;
  /** SDK process timeout, separate from the engine's scan budget. */
  timeoutMs?: number;
}

export interface ConfigOptions extends RequestOptions {
  configPath?: string;
}

export interface ScanOptions {
  maxSeconds?: number;
  maxModelCalls?: number;
  maxCostUsd?: number;
  perCallReserveUsd?: number;
  concurrency?: number;
  maxRetries?: number;
}

export interface RunOptions extends ConfigOptions {
  provider?: string;
  model?: string;
  options?: ScanOptions;
  checkpointDir?: string;
  resume?: boolean;
  diffBase?: string;
}

export interface ClientOptions {
  /** Executable on PATH (default arbalest), never a shell command string. */
  executable?: string;
  /** E.g. ["-m", "arbalest_cli"] when executable is a Python interpreter. */
  args?: readonly string[];
  cwd?: string;
  configPath?: string;
  timeoutMs?: number;
  /** Combined stdout/stderr byte limit (default 16 MiB). */
  maxOutputBytes?: number;
}

export type ErrorKind = "spawn" | "cli" | "json" | "output_limit" | "aborted" | "timeout";

export class ArbalestError extends Error {
  override readonly name = "ArbalestError";
  constructor(
    message: string,
    readonly kind: ErrorKind,
    readonly exitCode: number | null = null,
    /** CLI error stdout, when it was a valid JSON value. */
    readonly report: Json | undefined = undefined,
  ) {
    super(message);
  }
}

function object(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function positiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive integer`);
}

function timeout(value: number): void {
  positiveInteger(value, "timeoutMs");
  if (value > 2_147_483_647) throw new TypeError("timeoutMs exceeds the Node timer limit");
}

function nonempty(value: string, name: string): string {
  if (typeof value !== "string" || !value.length || value.includes("\0")) {
    throw new TypeError(`${name} must be a nonempty string without NUL`);
  }
  return value;
}

function scanReport(value: Json): ScanReport {
  if (!object(value) || typeof value.run_id !== "string" || typeof value.complete !== "boolean"
      || value.status !== (value.complete ? "complete" : "incomplete") || !Array.isArray(value.findings)
      || !value.findings.every((f) => object(f)
        && ["finding_id", "cwe", "severity", "summary"].every((key) => typeof f[key] === "string")
        && Array.isArray(f.affected_nodes) && f.affected_nodes.every((n) => typeof n === "string")
        && Array.isArray(f.evidence) && f.evidence.every((n) => typeof n === "string"))) {
    throw new ArbalestError("CLI returned an invalid scan report", "json");
  }
  for (const key of ["budget", "scan_archive"]) {
    if (value[key] !== undefined && !object(value[key])) {
      throw new ArbalestError(`CLI returned invalid ${key}`, "json");
    }
  }
  return value as ScanReport;
}

/** Node 22+ adapter for an independently installed Arbalest Python CLI.
 * Credentials are inherited from process.env; no API key/config object is accepted.
 */
export class Arbalest {
  private readonly executable: string;
  private readonly prefix: readonly string[];
  private readonly cwd: string | undefined;
  private readonly configPath: string | undefined;
  private readonly timeoutMs: number;
  private readonly maxOutputBytes: number;

  constructor(options: ClientOptions = {}) {
    this.executable = nonempty(options.executable ?? "arbalest", "executable");
    this.prefix = [...(options.args ?? [])].map((arg) => nonempty(arg, "argument"));
    this.cwd = options.cwd;
    this.configPath = options.configPath;
    this.timeoutMs = options.timeoutMs ?? 330_000;
    this.maxOutputBytes = options.maxOutputBytes ?? 16 * 1024 * 1024;
    timeout(this.timeoutMs);
    positiveInteger(this.maxOutputBytes, "maxOutputBytes");
  }

  private target(target: string): string {
    // Absolute paths prevent a target beginning with '-' becoming a CLI option.
    return resolve(this.cwd ?? process.cwd(), nonempty(target, "target"));
  }

  private config(argv: string[], options: ConfigOptions): void {
    const path = options.configPath ?? this.configPath;
    if (path !== undefined) argv.push("--config", nonempty(path, "configPath"));
  }

  private execute(argv: string[], options: RequestOptions, findingsExit = false): Promise<{ value: Json; code: 0 | 1 }> {
    const timeoutMs = options.timeoutMs ?? this.timeoutMs;
    timeout(timeoutMs);
    if (options.signal?.aborted) return Promise.reject(new ArbalestError("Request aborted", "aborted"));
    return new Promise((accept, reject) => {
      const stdout: Buffer[] = [];
      let bytes = 0;
      let failure: ArbalestError | undefined;
      // No shell, no credential argv, no environment overrides. stderr counts
      // toward the cap but is never echoed (a provider may have logged secrets).
      const child = spawn(this.executable, [...this.prefix, ...argv], {
        cwd: this.cwd, shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
      });
      let killTimer: ReturnType<typeof setTimeout> | undefined;
      const stop = (error: ArbalestError): void => {
        if (failure) return;
        failure = error;
        child.kill("SIGTERM");
        killTimer = setTimeout(() => {
          child.kill("SIGKILL");
          // Descendants can inherit stdio and keep 'close' pending even after
          // the direct child dies. Do not let those pipes defeat our deadline.
          child.stdout.destroy();
          child.stderr.destroy();
          cleanup();
          reject(failure);
        }, 1_000);
        killTimer.unref();
      };
      const abort = (): void => stop(new ArbalestError("Request aborted", "aborted"));
      options.signal?.addEventListener("abort", abort, { once: true });
      const timer = setTimeout(() => stop(new ArbalestError("CLI process timed out", "timeout")), timeoutMs);
      timer.unref();
      const cleanup = (): void => {
        clearTimeout(timer);
        if (killTimer) clearTimeout(killTimer);
        options.signal?.removeEventListener("abort", abort);
      };
      const consume = (chunk: Buffer, save: boolean): void => {
        if (failure) return;
        bytes += chunk.length;
        if (bytes > this.maxOutputBytes) {
          stop(new ArbalestError("CLI output exceeded maxOutputBytes", "output_limit"));
        } else if (save) stdout.push(chunk);
      };
      child.stdout.on("data", (chunk: Buffer) => consume(chunk, true));
      child.stderr.on("data", (chunk: Buffer) => consume(chunk, false));
      child.on("error", () => {
        cleanup();
        reject(failure ?? new ArbalestError("Unable to start CLI executable", "spawn"));
      });
      child.on("close", (code) => {
        cleanup();
        if (failure) return reject(failure);
        let value: Json;
        try {
          // Fatal UTF-8 decoding and JSON.parse reject replacement bytes,
          // banners, fenced JSON, trailing logs and concatenated documents.
          const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.concat(stdout));
          value = JSON.parse(text) as Json;
        } catch {
          return reject(new ArbalestError(
            code === 0 || (findingsExit && code === 1) ? "CLI did not return strict JSON" : "CLI failed",
            code === 0 || (findingsExit && code === 1) ? "json" : "cli", code,
          ));
        }
        if (code !== 0 && !(findingsExit && code === 1)) {
          return reject(new ArbalestError("CLI failed", "cli", code, value));
        }
        accept({ value, code: code as 0 | 1 });
      });
      // Close the race between the initial aborted check and listener setup.
      if (options.signal?.aborted) abort();
    });
  }

  async run(target: string, options: RunOptions = {}): Promise<ScanResult> {
    const argv = ["scan", this.target(target), "-f", "json", "-o", "-"];
    this.config(argv, options);
    for (const [flag, value] of [
      ["--provider", options.provider], ["--model", options.model],
      ["--checkpoint-dir", options.checkpointDir], ["--diff-base", options.diffBase],
    ] as const) {
      if (value !== undefined) argv.push(flag, nonempty(value, flag));
    }
    if (options.resume) argv.push("--resume");
    const flags = {
      maxSeconds: "--max-seconds", maxModelCalls: "--max-model-calls",
      maxCostUsd: "--max-cost-usd", perCallReserveUsd: "--per-call-reserve-usd",
      concurrency: "--concurrency", maxRetries: "--max-retries",
    } as const;
    for (const key of Object.keys(flags) as (keyof ScanOptions)[]) {
      const value = options.options?.[key];
      if (value !== undefined) {
        if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
          throw new TypeError(`${key} must be finite and nonnegative`);
        }
        argv.push(flags[key], String(value));
      }
    }
    const { value, code } = await this.execute(argv, options, true);
    const report = scanReport(value);
    return {
      exitCode: code, report, findings: report.findings, complete: report.complete,
      budget: report.budget as JsonObject | undefined,
      archive: report.scan_archive as JsonObject | undefined,
    };
  }

  async preflight(target: string, options: ConfigOptions = {}): Promise<JsonObject> {
    const argv = ["preflight", this.target(target), "--format", "json"];
    this.config(argv, options);
    const { value } = await this.execute(argv, options);
    if (!object(value)) throw new ArbalestError("Invalid preflight report", "json");
    return value;
  }

  async sbom(target: string, options: RequestOptions = {}): Promise<JsonObject> {
    const { value } = await this.execute(["sbom", this.target(target), "-o", "-"], options);
    if (!object(value) || value.bomFormat !== "CycloneDX" || !Array.isArray(value.components)) {
      throw new ArbalestError("Invalid CycloneDX report", "json");
    }
    return value;
  }

  async history(target: string, options: RequestOptions & { limit?: number } = {}): Promise<JsonObject[]> {
    const limit = options.limit ?? 20;
    positiveInteger(limit, "limit");
    if (limit > 100) throw new TypeError("limit must be at most 100");
    const { value } = await this.execute(["history", this.target(target), "--limit", String(limit)], options);
    if (!Array.isArray(value) || !value.every(object)) throw new ArbalestError("Invalid history report", "json");
    return value;
  }

  async compare(target: string, before: string, after: string, options: RequestOptions = {}): Promise<JsonObject> {
    for (const id of [before, after]) {
      if (!/^[a-f0-9]{12}$/.test(id)) throw new TypeError("scan IDs must be 12 lowercase hexadecimal characters");
    }
    const { value } = await this.execute([
      "compare", this.target(target), "--before", before, "--after", after,
    ], options);
    if (!object(value) || ![value.new, value.persistent, value.resolved, value.uncertain].every(Array.isArray)) {
      throw new ArbalestError("Invalid comparison report", "json");
    }
    return value;
  }
}
