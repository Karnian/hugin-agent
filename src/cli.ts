import { spawn } from "node:child_process";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

interface LifecycleResult {
  code: number;
  message: string;
}

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

export function readPid(pidfile: string): number | null {
  try {
    const raw = readFileSync(pidfile, "utf8").trim();
    if (!raw) return null;
    const pid = Number(raw);
    return Number.isInteger(pid) && pid > 0 ? pid : null;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw e;
  }
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

function cleanStalePidfile(paths: RuntimePaths): void {
  const pid = readPid(paths.pidfile);
  if (pid !== null && !isPidAlive(pid)) removePidfile(paths.pidfile);
  if (pid === null && existsSync(paths.pidfile)) removePidfile(paths.pidfile);
}

export function startDaemon(env: NodeJS.ProcessEnv = process.env, paths = runtimePaths(env)): LifecycleResult {
  const existingPid = readPid(paths.pidfile);
  if (existingPid !== null && isPidAlive(existingPid)) {
    return { code: 1, message: `already running (pid ${existingPid})` };
  }
  cleanStalePidfile(paths);

  const logfd = openSync(paths.logfile, "a");
  try {
    const cmd = daemonCommand(env);
    const child = spawn(cmd.command, cmd.args, {
      detached: true,
      stdio: ["ignore", logfd, logfd],
      env,
      windowsHide: true,
    });
    child.on("error", () => {});
    if (child.pid === undefined) {
      return { code: 1, message: `failed to start hugind; logs: ${paths.logfile}` };
    }
    child.unref();
    writeFileSync(paths.pidfile, `${child.pid}\n`);
    return { code: 0, message: `hugind started (pid ${child.pid}) — logs: ${paths.logfile}` };
  } finally {
    closeSync(logfd);
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
  const pid = readPid(paths.pidfile);
  if (pid === null || !isPidAlive(pid)) {
    removePidfile(paths.pidfile);
    return { code: 1, message: "not running" };
  }

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
  const pid = readPid(paths.pidfile);
  if (pid !== null && isPidAlive(pid)) {
    return { code: 0, message: `running (pid ${pid}, logs: ${paths.logfile})` };
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
    result = startDaemon(env, paths);
  } else if (command === "stop") {
    result = await stopDaemon(env, paths, { force: args.includes("--force") });
  } else if (command === "status") {
    result = statusDaemon(env, paths);
  } else if (command === "restart") {
    const stopped = await stopDaemon(env, paths, { force: args.includes("--force") });
    console.log(stopped.message);
    if (stopped.code !== 0 && stopped.message !== "not running") return stopped.code;
    result = startDaemon(env, paths);
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
