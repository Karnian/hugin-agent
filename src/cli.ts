import { execFileSync, spawn } from "node:child_process";
import { closeSync, ftruncateSync, mkdirSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
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

interface LifecycleResult {
  code: number;
  message: string;
}

type ProcessMatch = "yes" | "no" | "unknown";

const START_GRACE_MS = 500;
const ACTIVE_CLAIM_GRACE_MS = 2000;

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
  return join(dirname(fileURLToPath(import.meta.url)), "index.ts");
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
  return { command: process.execPath, args: ["--import", "tsx", daemonEntryPath()] };
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

export function readRecord(pidfile: string): PidRecord | null {
  try {
    const raw = readFileSync(pidfile, "utf8").trim();
    if (!raw) return null;

    const legacyPid = Number(raw);
    if (Number.isInteger(legacyPid) && legacyPid > 0) {
      return { pid: legacyPid, startedAt: 0, cmd: "" };
    }

    const parsed = JSON.parse(raw) as unknown;
    return isPidRecord(parsed) ? parsed : null;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    if (e instanceof SyntaxError) return null;
    throw e;
  }
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

function distinctiveTokens(cmd: string): string[] {
  const common = new Set(["node", "node.exe", "tsx", "--import", "-e", "env"]);
  const tokens = new Set<string>();
  for (const part of cmd.split(/\s+/)) {
    const cleaned = part.trim().replace(/^["']|["']$/g, "");
    if (!cleaned) continue;
    const base = basename(cleaned);
    const candidates = common.has(base.toLowerCase()) ? [base] : [cleaned, base];
    for (const candidate of candidates) {
      if (
        candidate.length >= 4 &&
        !candidate.startsWith("-") &&
        !common.has(candidate.toLowerCase()) &&
        !/^\d+$/.test(candidate)
      ) {
        tokens.add(candidate);
      }
    }
  }
  return [...tokens];
}

export function processMatches(pid: number, cmd: string): ProcessMatch {
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

function writeRecordFd(fd: number, record: PidRecord): void {
  ftruncateSync(fd, 0);
  writeFileSync(fd, `${JSON.stringify(record)}\n`, "utf8");
}

function pidfileHoldsPid(pidfile: string, pid: number): boolean {
  return readRecord(pidfile)?.pid === pid;
}

function isFreshPidfileClaim(pidfile: string): boolean {
  try {
    return Date.now() - statSync(pidfile).mtimeMs < ACTIVE_CLAIM_GRACE_MS;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw e;
  }
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

function claimPidfile(paths: RuntimePaths): { fd: number } | { result: LifecycleResult } {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      return { fd: openSync(paths.pidfile, "wx") };
    } catch (e) {
      const err = e as NodeJS.ErrnoException;
      if (err.code !== "EEXIST") throw e;

      const existing = readRecord(paths.pidfile);
      if (existing !== null && isOurDaemonRunning(existing)) {
        return { result: { code: 1, message: `already running (pid ${existing.pid})` } };
      }

      if (attempt === 0 && (existing !== null || !isFreshPidfileClaim(paths.pidfile))) {
        removePidfile(paths.pidfile);
        continue;
      }

      return { result: { code: 1, message: "already running / try again" } };
    }
  }

  return { result: { code: 1, message: "already running / try again" } };
}

export async function startDaemon(env: NodeJS.ProcessEnv = process.env, paths = runtimePaths(env)): Promise<LifecycleResult> {
  const claim = claimPidfile(paths);
  if ("result" in claim) return claim.result;

  let pidfd: number | null = claim.fd;
  let logfd: number | null = null;
  try {
    logfd = openSync(paths.logfile, "a");
    const cmd = daemonCommand(env);
    const cmdLine = daemonCommandLine(cmd);
    const childState: {
      spawnError?: Error;
      exit?: { code: number | null; signal: NodeJS.Signals | null };
    } = {};
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
      closeSync(pidfd);
      pidfd = null;
      removePidfile(paths.pidfile);
      await sleep(50);
      const reason = childState.spawnError ? `failed to start hugind: ${childState.spawnError.message}` : "failed to start hugind";
      return { code: 1, message: startFailureMessage(paths, reason) };
    }

    child.unref();
    writeRecordFd(pidfd, { pid: child.pid, startedAt: Date.now(), cmd: cmdLine });
    closeSync(pidfd);
    pidfd = null;

    await sleep(START_GRACE_MS);
    const stillOwnsPidfile = pidfileHoldsPid(paths.pidfile, child.pid);
    const childExit = childState.exit;
    if (childExit !== undefined || !isPidAlive(child.pid) || !stillOwnsPidfile) {
      if (stillOwnsPidfile) removePidfile(paths.pidfile);
      const exitDetail =
        childExit !== undefined
          ? `failed to start hugind; child exited immediately (code ${childExit.code ?? "null"}, signal ${childExit.signal ?? "null"})`
          : "failed to start hugind; child did not remain alive";
      return { code: 1, message: startFailureMessage(paths, exitDetail) };
    }

    return { code: 0, message: `hugind started (pid ${child.pid}) — logs: ${paths.logfile}` };
  } finally {
    if (pidfd !== null) {
      closeSync(pidfd);
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
  const record = readRecord(paths.pidfile);
  if (record === null || !isPidAlive(record.pid)) {
    removePidfile(paths.pidfile);
    return { code: 1, message: "not running" };
  }

  if (processMatches(record.pid, record.cmd) === "no") {
    removePidfile(paths.pidfile);
    return { code: 1, message: "not running (stale pidfile removed)" };
  }

  const pid = record.pid;
  try {
    process.kill(pid);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ESRCH") throw e;
  }

  if (await waitForExit(pid, opts.timeoutMs ?? 5000)) {
    removePidfile(paths.pidfile);
    return { code: 0, message: `stopped (pid ${pid})` };
  }

  if (opts.force) {
    try {
      process.kill(pid, "SIGKILL");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ESRCH") throw e;
    }
    if (await waitForExit(pid, 2000)) {
      removePidfile(paths.pidfile);
      return { code: 0, message: `stopped (pid ${pid})` };
    }
  }

  return { code: 1, message: `pid ${pid} did not stop within 5s; retry with --force to terminate it` };
}

export function statusDaemon(env: NodeJS.ProcessEnv = process.env, paths = runtimePaths(env)): LifecycleResult {
  const record = readRecord(paths.pidfile);
  if (record !== null && isOurDaemonRunning(record)) {
    return { code: 0, message: `running (pid ${record.pid}, logs: ${paths.logfile})` };
  }
  removePidfile(paths.pidfile);
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli().then(
    (code) => process.exit(code),
    (e) => {
      console.error(String(e));
      process.exit(1);
    },
  );
}
