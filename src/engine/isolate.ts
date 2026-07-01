/**
 * Permission-config isolation for the spawned engine (plan §5.6).
 *
 * IMPORTANT — spike v2/v3 + this repo's probes (docs/hugind-mvp-plan.md §5.6):
 * on a macOS host whose Claude login is keychain-backed against the DEFAULT
 * config path, BOTH `config-dir` and `home-swap` isolation drop the login
 * ("Not logged in"). `none` runs under the host config so the login is preserved,
 * but then the host allow-list (`allow:["Bash(*)",…]` + `dontAsk`) DISABLES the
 * approval gate — so the daemon MUST fail closed on gated (write/exec) jobs.
 * `selfCheckLogin` lets the daemon detect the drop at startup and decide.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export type IsolationMode = "config-dir" | "home-swap" | "none";

export interface Isolation {
  mode: IsolationMode;
  /** Env overlay applied to the engine child process. */
  env: NodeJS.ProcessEnv;
  cleanup: () => void;
}

const EMPTY_ALLOW = JSON.stringify({ permissions: { allow: [], defaultMode: "default" } }, null, 2);

export function buildIsolation(mode: IsolationMode, stateDir: string): Isolation {
  if (mode === "none") return { mode, env: {}, cleanup: () => {} };

  const dir = join(stateDir, "isolation", mode);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });

  if (mode === "config-dir") {
    // Provide .claude.json (account/onboarding) + an empty-allow settings.json so
    // the gate fires. (Auth still comes from the keychain — see the header note.)
    const src = join(homedir(), ".claude.json");
    if (existsSync(src)) cpSync(src, join(dir, ".claude.json"));
    writeFileSync(join(dir, "settings.json"), EMPTY_ALLOW);
    return { mode, env: { CLAUDE_CONFIG_DIR: dir }, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
  }

  // home-swap
  mkdirSync(join(dir, ".claude"), { recursive: true });
  writeFileSync(join(dir, ".claude", "settings.json"), EMPTY_ALLOW);
  return { mode, env: { HOME: dir }, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

export interface LoginCheck {
  loggedIn: boolean;
  detail: string;
}

/** Startup self-check: does a minimal `claude -p` under `env` stay logged in? A
 *  gate that never fires because the login was lost is worse than useless. */
export function selfCheckLogin(env: NodeJS.ProcessEnv, command = "claude", timeoutMs = 60_000): Promise<LoginCheck> {
  return new Promise((resolve) => {
    let out = "";
    let child: ChildProcess;
    try {
      child = spawn(command, ["-p", "Reply with exactly: OK", "--output-format", "stream-json", "--verbose"], {
        env: { ...process.env, ...env },
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (e) {
      resolve({ loggedIn: false, detail: `spawn failed: ${(e as Error).message}` });
      return;
    }
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.stdout?.on("data", (d: Buffer) => (out += d.toString()));
    child.stderr?.on("data", (d: Buffer) => (out += d.toString()));
    child.on("error", (e) => {
      clearTimeout(timer);
      resolve({ loggedIn: false, detail: `spawn error: ${e.message}` });
    });
    child.on("close", () => {
      clearTimeout(timer);
      const loginErr = /not logged in|please run \/login|unauthorized|invalid api key/i.test(out);
      resolve({ loggedIn: !loginErr, detail: loginErr ? "login lost under isolation" : "logged in" });
    });
  });
}
