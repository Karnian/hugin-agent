#!/usr/bin/env node
import { execFileSync, spawn } from "node:child_process";
import { closeSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import type { Stats } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export interface RuntimePaths {
  dir: string;
  pidfile: string;
  logfile: string;
}

export interface DaemonCommand {
  command: string;
  args: string[];
}

export interface PidRecord {
  pid: number;
  startedAt: number;
  cmd: string;
}

interface ClaimRecord {
  claiming: true;
  startedAt: number;
  ownerPid?: number;
}

interface LifecycleResult {
  code: number;
  message: string;
}

export type ProcessMatch = "yes" | "no" | "unknown";
export type PidfileState = "running" | "starting" | "stale" | "none";
export type StopDecision = "kill" | "refuse-unverified" | "stale" | "not-running" | "starting";

const ACTIVE_CLAIM_GRACE_MS = 2000;
const DEFAULT_READY_TIMEOUT_MS = 4000;
const DEFAULT_READY_STABLE_MS = 500;
/** Hard cap on the readiness windows so a large HUGIND_READY_* value can't hang `start`. */
const MAX_READY_MS = 30_000;
const READY_POLL_MS = 150;
const DEFAULT_READY_MARKER = "hugind starting";

function ensureDir(dir: string): string {
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function runtimeDir(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  home = homedir(),
): string {
  const override = env.HUGIND_STATE_DIR?.trim();
  if (override) return ensureDir(resolve(override));

  if (platform === "darwin") {
    return ensureDir(join(home, "Library", "Application Support", "hugin-agent"));
  }

  if (platform === "win32") {
    const localAppData = env.LOCALAPPDATA?.trim() || join(home, "AppData", "Local");
    return ensureDir(join(localAppData, "hugin-agent"));
  }

  const stateHome = env.XDG_STATE_HOME?.trim() || join(home, ".local", "state");
  return ensureDir(join(stateHome, "hugin-agent"));
}

export function runtimePaths(env: NodeJS.ProcessEnv = process.env): RuntimePaths {
  const dir = runtimeDir(env);
  return {
    dir,
    pidfile: join(dir, "hugind.pid"),
    logfile: join(dir, "hugind.log"),
  };
}

export function daemonEntryPath(): string {
  const self = fileURLToPath(import.meta.url);
  const extension = self.endsWith(".js") ? ".js" : ".ts";
  return join(dirname(self), `index${extension}`);
}

function parseDaemonArgs(raw: string | undefined): string[] {
  const trimmed = raw?.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith("[")) {
    const parsed = JSON.parse(trimmed) as unknown;
    if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === "string")) {
      throw new Error("HUGIND_DAEMON_ARGS must be a JSON array of strings");
    }
    return parsed;
  }
  return trimmed.split(/\s+/);
}

export function daemonCommand(env: NodeJS.ProcessEnv = process.env): DaemonCommand {
  const override = env.HUGIND_DAEMON_CMD?.trim();
  if (override) return { command: override, args: parseDaemonArgs(env.HUGIND_DAEMON_ARGS) };
  const entry = daemonEntryPath();
  if (entry.endsWith(".js")) return { command: process.execPath, args: [entry] };
  return { command: process.execPath, args: ["--import", "tsx", entry] };
}

function daemonCommandLine(cmd: DaemonCommand): string {
  return [cmd.command, ...cmd.args].join(" ");
}

function isPidRecord(value: unknown): value is PidRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Partial<PidRecord>;
  return (
    Number.isInteger(record.pid) &&
    (record.pid ?? 0) > 0 &&
    typeof record.startedAt === "number" &&
    Number.isFinite(record.startedAt) &&
    typeof record.cmd === "string"
  );
}

function isClaimRecord(value: unknown): value is ClaimRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Partial<ClaimRecord>;
  return (
    record.claiming === true &&
    typeof record.startedAt === "number" &&
    Number.isFinite(record.startedAt) &&
    (record.ownerPid === undefined || (Number.isInteger(record.ownerPid) && record.ownerPid > 0))
  );
}

interface PidfileFingerprint {
  dev: number;
  ino: number;
  mtimeMs: number;
  size: number;
}

type PidfileSnapshot =
  | { kind: "none"; fingerprint?: undefined }
  | { kind: "record"; record: PidRecord; fingerprint: PidfileFingerprint }
  | { kind: "claim"; claim: ClaimRecord; fingerprint: PidfileFingerprint }
  | { kind: "invalid"; fingerprint: PidfileFingerprint };

interface PidfileInspection {
  state: PidfileState;
  snapshot: PidfileSnapshot;
  record?: PidRecord;
  match?: ProcessMatch;
  legacy: boolean;
}

function fingerprintFromStat(stat: Stats): PidfileFingerprint {
  return { dev: stat.dev, ino: stat.ino, mtimeMs: stat.mtimeMs, size: stat.size };
}

function isFreshFingerprint(fingerprint: PidfileFingerprint): boolean {
  return Date.now() - fingerprint.mtimeMs < ACTIVE_CLAIM_GRACE_MS;
}

function isActiveClaim(claim: ClaimRecord, fingerprint: PidfileFingerprint): boolean {
  if (claim.ownerPid !== undefined) return isPidAlive(claim.ownerPid);
  return isFreshFingerprint(fingerprint);
}

function readPidfileSnapshot(pidfile: string): PidfileSnapshot {
  let fingerprint: PidfileFingerprint;
  try {
    fingerprint = fingerprintFromStat(statSync(pidfile));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { kind: "none" };
    throw e;
  }

  let raw: string;
  try {
    raw = readFileSync(pidfile, "utf8").trim();
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { kind: "none" };
    throw e;
  }

  if (!raw) return { kind: "invalid", fingerprint };

  const legacyPid = Number(raw);
  if (Number.isInteger(legacyPid) && legacyPid > 0) {
    return { kind: "record", record: { pid: legacyPid, startedAt: 0, cmd: "" }, fingerprint };
  }

  try {
    const parsed = JSON.parse(raw) as unknown;
    if (isPidRecord(parsed)) return { kind: "record", record: parsed, fingerprint };
    if (isClaimRecord(parsed)) return { kind: "claim", claim: parsed, fingerprint };
    return { kind: "invalid", fingerprint };
  } catch (e) {
    if (e instanceof SyntaxError) return { kind: "invalid", fingerprint };
    throw e;
  }
}

export function readRecord(pidfile: string): PidRecord | null {
  const snapshot = readPidfileSnapshot(pidfile);
  return snapshot.kind === "record" ? snapshot.record : null;
}

export function readPid(pidfile: string): number | null {
  return readRecord(pidfile)?.pid ?? null;
}

export function removePidfile(pidfile: string): void {
  rmSync(pidfile, { force: true });
}

export function isPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

function tokenBasename(token: string): string {
  return token.split(/[\\/]/).pop() ?? token;
}

function isAbsolutePathLike(token: string): boolean {
  return token.startsWith("/") || /^[A-Za-z]:[\\/]/.test(token) || token.startsWith("\\\\");
}

function distinctiveTokens(cmd: string): string[] {
  const common = new Set(["node", "node.exe", "tsx", "--import", "-e", "env"]);
  const parts = cmd
    .split(/\s+/)
    .map((part) => part.trim().replace(/^["']|["']$/g, ""))
    .filter((part) => part.length > 0);
  const absoluteTokens = parts
    .filter((part) => isAbsolutePathLike(part))
    .filter((part) => {
      const base = tokenBasename(part).toLowerCase();
      return part.length >= 4 && !common.has(base) && !/^\d+$/.test(base);
    })
    .sort((a, b) => b.length - a.length);
  if (absoluteTokens.length > 0) return [absoluteTokens[0] as string];

  const trimmed = cmd.trim();
  return trimmed ? [trimmed] : [];
}

export function processMatches(pid: number, cmd: string): ProcessMatch {
  // Test-only deterministic override (mirrors HUGIND_DAEMON_CMD): forcing the
  // ownership result is more reliable than trying to make `ps` fail via PATH,
  // since macOS falls back to /bin/ps even with an empty PATH.
  const forced = process.env.HUGIND_FORCE_MATCH;
  if (forced === "yes" || forced === "no" || forced === "unknown") return forced;

  if (process.platform === "win32" || cmd.trim() === "") return "unknown";

  let actual: string;
  try {
    actual = execFileSync("ps", ["-p", String(pid), "-o", "command="], { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }

  if (!actual) return "unknown";

  const tokens = distinctiveTokens(cmd);
  if (tokens.length === 0) return "unknown";
  return tokens.some((token) => actual.includes(token)) ? "yes" : "no";
}

export function isOurDaemonRunning(record: PidRecord | null): boolean {
  return record !== null && isPidAlive(record.pid) && processMatches(record.pid, record.cmd) !== "no";
}

function isLegacyRecord(record: PidRecord): boolean {
  return record.cmd.trim() === "";
}

function inspectPidfile(paths: RuntimePaths): PidfileInspection {
  const snapshot = readPidfileSnapshot(paths.pidfile);
  if (snapshot.kind === "none") return { state: "none", snapshot, legacy: false };
  if (snapshot.kind === "claim") {
    return { state: isActiveClaim(snapshot.claim, snapshot.fingerprint) ? "starting" : "stale", snapshot, legacy: false };
  }
  if (snapshot.kind === "invalid") {
    return { state: isFreshFingerprint(snapshot.fingerprint) ? "starting" : "stale", snapshot, legacy: false };
  }

  const { record } = snapshot;
  if (!isPidAlive(record.pid)) return { state: "stale", snapshot, record, legacy: isLegacyRecord(record) };

  const legacy = isLegacyRecord(record);
  const match = legacy ? "unknown" : processMatches(record.pid, record.cmd);
  return { state: match === "no" ? "stale" : "running", snapshot, record, match, legacy };
}

export function pidfileState(paths: RuntimePaths): PidfileState {
  return inspectPidfile(paths).state;
}

export function stopDecision(
  inspection: { state: PidfileState; record?: PidRecord; match?: ProcessMatch; legacy?: boolean },
  force = false,
): StopDecision {
  if (inspection.state === "none") return "not-running";
  if (inspection.state === "starting") return "starting";
  if (inspection.state === "stale" || inspection.record === undefined || inspection.match === "no") return "stale";

  const ownershipUnverified = inspection.legacy === true || inspection.match !== "yes";
  if (ownershipUnverified && !force) return "refuse-unverified";
  return "kill";
}

function sameFingerprint(a: PidfileFingerprint, b: PidfileFingerprint): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.mtimeMs === b.mtimeMs && a.size === b.size;
}

function removePidfileIfUnchanged(pidfile: string, snapshot: PidfileSnapshot): boolean {
  if (snapshot.kind === "none") return false;
  let current: PidfileFingerprint;
  try {
    current = fingerprintFromStat(statSync(pidfile));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw e;
  }
  if (!sameFingerprint(current, snapshot.fingerprint)) return false;
  removePidfile(pidfile);
  return true;
}

export function removePidfileIfHoldsPid(pidfile: string, pid: number): boolean {
  const snapshot = readPidfileSnapshot(pidfile);
  if (snapshot.kind !== "record" || snapshot.record.pid !== pid) return false;
  let current: PidfileFingerprint;
  try {
    current = fingerprintFromStat(statSync(pidfile));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw e;
  }
  if (!sameFingerprint(current, snapshot.fingerprint)) return false;
  removePidfile(pidfile);
  return true;
}

function writeClaimFd(fd: number): void {
  const claim: ClaimRecord = { claiming: true, startedAt: Date.now(), ownerPid: process.pid };
  writeFileSync(fd, `${JSON.stringify(claim)}\n`, "utf8");
}

function writeRecordAtomic(pidfile: string, record: PidRecord): void {
  const tmp = `${pidfile}.${process.pid}.${Date.now()}.tmp`;
  try {
    writeFileSync(tmp, `${JSON.stringify(record)}\n`, { encoding: "utf8", flag: "wx" });
    renameSync(tmp, pidfile);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
}

function pidfileHoldsPid(pidfile: string, pid: number): boolean {
  return readRecord(pidfile)?.pid === pid;
}

function readLogTail(logfile: string, maxLines = 8): string {
  try {
    const raw = readFileSync(logfile, "utf8").trim();
    if (!raw) return "";
    return raw.split(/\r?\n/).slice(-maxLines).join("\n");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw e;
  }
}

function startFailureMessage(paths: RuntimePaths, detail: string): string {
  const tail = readLogTail(paths.logfile);
  return tail ? `${detail}; logs: ${paths.logfile}\n${tail}` : `${detail}; logs: ${paths.logfile}`;
}

function fileSize(path: string): number {
  try {
    return statSync(path).size;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw e;
  }
}

function logContainsMarkerSince(logfile: string, marker: string, offset: number): boolean {
  if (marker === "") return true;
  try {
    const raw = readFileSync(logfile, "utf8");
    return raw.slice(Math.min(offset, raw.length)).includes(marker);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw e;
  }
}

export function envMs(env: NodeJS.ProcessEnv, name: string, fallback: number, max = Number.POSITIVE_INFINITY): number {
  const raw = env[name]?.trim();
  if (!raw) return Math.min(fallback, max);
  const parsed = Number(raw);
  if (!(Number.isFinite(parsed) && parsed >= 0)) return Math.min(fallback, max);
  // Cap the readiness windows so a large/hostile env value can never make
  // `start` hang; the residual "marker-then-crash after the window" edge is an
  // inherent limit of log-based readiness (see service/README.md).
  return Math.min(parsed, max);
}

interface ChildState {
  spawnError?: Error;
  exit?: { code: number | null; signal: NodeJS.Signals | null };
}

function childExitDetail(childState: ChildState): string {
  const childExit = childState.exit;
  return childExit !== undefined
    ? `failed to start hugind; child exited immediately/before readiness (code ${childExit.code ?? "null"}, signal ${childExit.signal ?? "null"})`
    : "failed to start hugind; child did not remain alive";
}

function cleanupStartedPidfile(paths: RuntimePaths, pid: number): void {
  removePidfileIfHoldsPid(paths.pidfile, pid);
}

function killStartedChild(pid: number): void {
  if (!isPidAlive(pid)) return;
  try {
    process.kill(pid);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ESRCH") throw e;
  }
}

async function waitForDaemonReadiness(
  env: NodeJS.ProcessEnv,
  paths: RuntimePaths,
  pid: number,
  childState: ChildState,
  logOffset: number,
): Promise<LifecycleResult> {
  const marker = env.HUGIND_READY_MARKER ?? DEFAULT_READY_MARKER;
  const timeoutMs = envMs(env, "HUGIND_READY_TIMEOUT_MS", DEFAULT_READY_TIMEOUT_MS, MAX_READY_MS);
  const stableMs = envMs(env, "HUGIND_READY_STABLE_MS", DEFAULT_READY_STABLE_MS, MAX_READY_MS);
  const deadline = Date.now() + timeoutMs;

  while (true) {
    const stillOwnsPidfile = pidfileHoldsPid(paths.pidfile, pid);
    if (childState.exit !== undefined || !isPidAlive(pid) || !stillOwnsPidfile) {
      if (stillOwnsPidfile) cleanupStartedPidfile(paths, pid);
      killStartedChild(pid);
      return { code: 1, message: startFailureMessage(paths, childExitDetail(childState)) };
    }

    if (logContainsMarkerSince(paths.logfile, marker, logOffset)) {
      const stableDeadline = Date.now() + stableMs;
      while (Date.now() < stableDeadline) {
        const ownsDuringStability = pidfileHoldsPid(paths.pidfile, pid);
        if (childState.exit !== undefined || !isPidAlive(pid) || !ownsDuringStability) {
          if (ownsDuringStability) cleanupStartedPidfile(paths, pid);
          killStartedChild(pid);
          return { code: 1, message: startFailureMessage(paths, childExitDetail(childState)) };
        }
        await sleep(Math.min(READY_POLL_MS, stableDeadline - Date.now()));
      }

      const ownsAfterStability = pidfileHoldsPid(paths.pidfile, pid);
      if (childState.exit !== undefined || !isPidAlive(pid) || !ownsAfterStability) {
        if (ownsAfterStability) cleanupStartedPidfile(paths, pid);
        killStartedChild(pid);
        return { code: 1, message: startFailureMessage(paths, childExitDetail(childState)) };
      }
      return { code: 0, message: `hugind started (pid ${pid}) — logs: ${paths.logfile}` };
    }

    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await sleep(Math.min(READY_POLL_MS, remaining));
  }

  const stillOwnsPidfile = pidfileHoldsPid(paths.pidfile, pid);
  if (childState.exit !== undefined || !isPidAlive(pid) || !stillOwnsPidfile) {
    if (stillOwnsPidfile) cleanupStartedPidfile(paths, pid);
    killStartedChild(pid);
    return { code: 1, message: startFailureMessage(paths, childExitDetail(childState)) };
  }

  return {
    code: 0,
    message: `hugind started (pid ${pid}) — not yet confirmed healthy; check logs: ${paths.logfile}`,
  };
}

function claimPidfile(paths: RuntimePaths): { claimed: true } | { result: LifecycleResult } {
  for (let attempt = 0; attempt < 2; attempt++) {
    let fd: number | null = null;
    try {
      fd = openSync(paths.pidfile, "wx");
      writeClaimFd(fd);
      return { claimed: true };
    } catch (e) {
      if (fd !== null) {
        closeSync(fd);
        fd = null;
        removePidfile(paths.pidfile);
      }
      const err = e as NodeJS.ErrnoException;
      if (err.code !== "EEXIST") throw e;

      const inspection = inspectPidfile(paths);
      if (inspection.state === "running" && inspection.record !== undefined) {
        const suffix = inspection.legacy || inspection.match === "unknown" ? ", ownership unverified" : "";
        return { result: { code: 1, message: `already running (pid ${inspection.record.pid}${suffix})` } };
      }

      if (inspection.state === "starting") {
        return { result: { code: 1, message: "already running / start in progress; try again" } };
      }

      if (attempt === 0 && (inspection.state === "stale" || inspection.state === "none")) {
        removePidfileIfUnchanged(paths.pidfile, inspection.snapshot);
        continue;
      }

      return { result: { code: 1, message: "already running / try again" } };
    } finally {
      if (fd !== null) closeSync(fd);
    }
  }

  return { result: { code: 1, message: "already running / try again" } };
}

export async function startDaemon(env: NodeJS.ProcessEnv = process.env, paths = runtimePaths(env)): Promise<LifecycleResult> {
  const claim = claimPidfile(paths);
  if ("result" in claim) return claim.result;

  let claimActive = true;
  let logfd: number | null = null;
  let childPid: number | null = null;
  let recordWritten = false;
  try {
    logfd = openSync(paths.logfile, "a");
    const logOffset = fileSize(paths.logfile);
    const cmd = daemonCommand(env);
    const cmdLine = daemonCommandLine(cmd);
    const childState: ChildState = {};
    const child = spawn(cmd.command, cmd.args, {
      detached: true,
      stdio: ["ignore", logfd, logfd],
      env,
      windowsHide: true,
    });
    child.on("error", (e) => {
      childState.spawnError = e;
    });
    child.on("exit", (code, signal) => {
      childState.exit = { code, signal };
    });
    if (child.pid === undefined) {
      removePidfile(paths.pidfile);
      claimActive = false;
      await sleep(50);
      const reason = childState.spawnError ? `failed to start hugind: ${childState.spawnError.message}` : "failed to start hugind";
      return { code: 1, message: startFailureMessage(paths, reason) };
    }

    childPid = child.pid;
    child.unref();
    writeRecordAtomic(paths.pidfile, { pid: child.pid, startedAt: Date.now(), cmd: cmdLine });
    claimActive = false;
    recordWritten = true;

    return await waitForDaemonReadiness(env, paths, child.pid, childState, logOffset);
  } finally {
    if (!recordWritten && childPid !== null) killStartedChild(childPid);
    if (claimActive) {
      removePidfile(paths.pidfile);
    }
    if (logfd !== null) closeSync(logfd);
  }
}

async function sleep(ms: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, ms));
}

async function waitForExit(pid: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!isPidAlive(pid)) return true;
    await sleep(100);
  }
  return !isPidAlive(pid);
}

export async function stopDaemon(
  env: NodeJS.ProcessEnv = process.env,
  paths = runtimePaths(env),
  opts: { force?: boolean; timeoutMs?: number } = {},
): Promise<LifecycleResult> {
  const inspection = inspectPidfile(paths);
  const decision = stopDecision(inspection, opts.force === true);
  if (decision === "not-running") {
    return { code: 1, message: "not running" };
  }

  if (decision === "starting") {
    return { code: 1, message: "a start is in progress; retry" };
  }

  if (decision === "stale" || inspection.record === undefined) {
    if (inspection.record !== undefined) {
      removePidfileIfHoldsPid(paths.pidfile, inspection.record.pid);
    } else {
      removePidfileIfUnchanged(paths.pidfile, inspection.snapshot);
    }
    return { code: 1, message: "not running (stale pidfile removed)" };
  }

  const record = inspection.record;
  const pid = record.pid;
  const ownershipUnverified = inspection.legacy || inspection.match === "unknown";
  if (decision === "refuse-unverified") {
    return {
      code: 1,
      message: `cannot verify this pidfile belongs to hugind; rerun with --force to terminate pid ${pid}, or remove the stale pidfile`,
    };
  }

  try {
    process.kill(pid);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ESRCH") throw e;
  }

  if (await waitForExit(pid, opts.timeoutMs ?? 5000)) {
    removePidfileIfHoldsPid(paths.pidfile, pid);
    const suffix = ownershipUnverified ? "; ownership could not be re-verified" : "";
    return { code: 0, message: `stopped (pid ${pid}${suffix})` };
  }

  if (opts.force) {
    try {
      process.kill(pid, "SIGKILL");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ESRCH") throw e;
    }
    if (await waitForExit(pid, 2000)) {
      removePidfileIfHoldsPid(paths.pidfile, pid);
      const suffix = ownershipUnverified ? "; ownership could not be re-verified" : "";
      return { code: 0, message: `stopped (pid ${pid}${suffix})` };
    }
  }

  return { code: 1, message: `pid ${pid} did not stop within 5s; retry with --force to terminate it` };
}

export function statusDaemon(env: NodeJS.ProcessEnv = process.env, paths = runtimePaths(env)): LifecycleResult {
  const inspection = inspectPidfile(paths);
  if (inspection.state === "starting") {
    return { code: 1, message: "starting (in progress)" };
  }

  if (inspection.state === "running" && inspection.record !== undefined) {
    const unverified = inspection.legacy || inspection.match === "unknown";
    const suffix = unverified ? ", ownership unverified" : "";
    return { code: 0, message: `running (pid ${inspection.record.pid}${suffix}, logs: ${paths.logfile})` };
  }

  if (inspection.state === "stale") removePidfileIfUnchanged(paths.pidfile, inspection.snapshot);
  return { code: 1, message: "stopped" };
}

function usage(): LifecycleResult {
  return {
    code: 1,
    message: [
      "usage: hugind <start|stop|status|restart> [--force]",
      "",
      "Environment:",
      "  HUGIND_STATE_DIR      override runtime dir for hugind.pid and hugind.log",
      "  HUGIND_DAEMON_CMD     test override for daemon command",
      "  HUGIND_DAEMON_ARGS    test override args, preferably a JSON string array",
    ].join("\n"),
  };
}

export async function runCli(argv = process.argv.slice(2), env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const [command, ...args] = argv;
  const paths = runtimePaths(env);
  let result: LifecycleResult;

  if (command === "start") {
    result = await startDaemon(env, paths);
  } else if (command === "stop") {
    result = await stopDaemon(env, paths, { force: args.includes("--force") });
  } else if (command === "status") {
    result = statusDaemon(env, paths);
  } else if (command === "restart") {
    const stopped = await stopDaemon(env, paths, { force: args.includes("--force") });
    console.log(stopped.message);
    if (stopped.code !== 0 && !stopped.message.startsWith("not running")) return stopped.code;
    result = await startDaemon(env, paths);
  } else {
    result = usage();
  }

  console.log(result.message);
  return result.code;
}

/** True when this module is the process entrypoint. Compares REAL paths so an
 *  npm `bin` symlink (dist/cli.js reached via a symlinked `hugind`) still counts
 *  as main — `process.argv[1]` is the symlink while `import.meta.url` is the
 *  resolved file, so a plain URL compare would miss it and the CLI would no-op. */
function invokedAsMain(): boolean {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  try {
    return realpathSync(argv1) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return import.meta.url === pathToFileURL(argv1).href;
  }
}

if (invokedAsMain()) {
  runCli().then(
    (code) => process.exit(code),
    (e) => {
      console.error(String(e));
      process.exit(1);
    },
  );
}
