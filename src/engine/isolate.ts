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
 *
 * FUTURE (unblocks the real deny→blocked gate under isolation): Claude Code also
 * honors env-based auth — `ANTHROPIC_API_KEY` (always used in non-interactive `-p`
 * mode when set) and `CLAUDE_CODE_OAUTH_TOKEN`. Injecting one into the isolated
 * child env should survive both `config-dir` and `home-swap` (it isn't
 * keychain/default-path bound), giving {isolated gate + logged in} on this host.
 * Left for P3 (approval bridge) where the gate is actually exercised.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { ApprovalBridge, PERMISSION_PROMPT_TOOL, approvalRunDir, permissionMcpServers } from "./permission";

export type IsolationMode = "config-dir" | "home-swap" | "none";

export interface Isolation {
  mode: IsolationMode;
  /** Env overlay applied to the engine child process. */
  env: NodeJS.ProcessEnv;
  cleanup: () => void;
}

const EMPTY_ALLOW = JSON.stringify({ permissions: { allow: [], defaultMode: "default" } }, null, 2);

/** Provider env-auth honored by claude in non-interactive `-p` mode (auth-spec §9,
 *  out of band). Injecting whatever the DAEMON was given into the isolated child
 *  keeps it logged in even though the keychain-backed default-path login is dropped
 *  by config-dir/home-swap (the isolation finding — see the header). Nothing is
 *  injected when neither is set: the child then relies on the host keychain login,
 *  which only survives `none`. */
function envAuthOverlay(): NodeJS.ProcessEnv {
  const overlay: NodeJS.ProcessEnv = {};
  if (process.env.ANTHROPIC_API_KEY) overlay.ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
  if (process.env.CLAUDE_CODE_OAUTH_TOKEN) overlay.CLAUDE_CODE_OAUTH_TOKEN = process.env.CLAUDE_CODE_OAUTH_TOKEN;
  return overlay;
}

/** Fields a spawned CLI may inherit. The child must NOT get the daemon's FULL env
 *  (auth-pairing-spec §9): that leaks unrelated secrets to model-controlled code
 *  and lets a stray `CLAUDE_CONFIG_DIR` override the isolation. Everything else
 *  (isolation config + provider auth) arrives via the explicit `overlay`. */
const ENV_ALLOWLIST = ["PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TERM", "SHELL", "USER", "LOGNAME"];

/** Build a scrubbed child env: the allowlist above (from the daemon's env) plus
 *  `overlay`, which WINS (so home-swap `HOME` / config-dir `CLAUDE_CONFIG_DIR` +
 *  injected provider auth take effect and nothing else leaks in). */
export function scrubbedChildEnv(overlay: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const base: NodeJS.ProcessEnv = {};
  for (const k of ENV_ALLOWLIST) {
    const v = process.env[k];
    if (v !== undefined) base[k] = v;
  }
  return { ...base, ...overlay };
}

export function buildIsolation(mode: IsolationMode, stateDir: string): Isolation {
  if (mode === "none") return { mode, env: {}, cleanup: () => {} };

  const dir = join(stateDir, "isolation", mode);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });

  if (mode === "config-dir") {
    // Provide .claude.json (account/onboarding) + an empty-allow settings.json so
    // the gate fires. Auth comes from the keychain OR the injected env-auth.
    const src = join(homedir(), ".claude.json");
    if (existsSync(src)) cpSync(src, join(dir, ".claude.json"));
    writeFileSync(join(dir, "settings.json"), EMPTY_ALLOW);
    return { mode, env: { CLAUDE_CONFIG_DIR: dir, ...envAuthOverlay() }, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
  }

  // home-swap
  mkdirSync(join(dir, ".claude"), { recursive: true });
  writeFileSync(join(dir, ".claude", "settings.json"), EMPTY_ALLOW);
  return { mode, env: { HOME: dir, ...envAuthOverlay() }, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
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
        env: scrubbedChildEnv(env),
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

export interface GateCheck {
  gateFires: boolean;
  detail: string;
}

/**
 * Startup gate self-check (Track B; Codex P3 note). A LIVE gate must satisfy BOTH:
 * a dangerous tool actually ROUTES THROUGH the permission prompt (a surviving login
 * is necessary but not sufficient — a host allow-list can pre-approve tools so the
 * prompt never fires), AND a `deny` actually BLOCKS execution. This spawns claude
 * with the SAME permission-prompt wiring ClaudeEngine uses, asks it to WRITE a
 * sentinel file, DENIES the prompt, waits for claude to finish, and returns
 * `gateFires` only if the prompt fired AND the sentinel was never written. Probing
 * the Write tool (not Bash) catches the host-fallback case where writes are
 * pre-approved while another tool still prompts. Fail-closed: any error / login
 * loss / no-prompt / deny-not-honored => gateFires:false.
 */
export async function selfCheckGate(env: NodeJS.ProcessEnv, command = "claude", timeoutMs = 90_000): Promise<GateCheck> {
  let runDir: string | undefined;
  let bridge: ApprovalBridge | undefined;
  try {
    runDir = approvalRunDir(); // 0700, owner-only
    const dir = runDir;
    const sentinel = join(dir, "sentinel.txt");
    const socketPath = join(dir, "s.sock");
    const mcpConfig = join(dir, "mcp.json");
    bridge = new ApprovalBridge(socketPath);
    await bridge.start();
    writeFileSync(mcpConfig, JSON.stringify({ mcpServers: permissionMcpServers(socketPath) }), { mode: 0o600 });
    const activeBridge = bridge;

    return await new Promise<GateCheck>((resolve) => {
      let fired = false;
      let done = false;
      let out = "";
      let child: ChildProcess | undefined;
      const finish = (detail: string, exited: boolean) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try {
          child?.kill("SIGKILL");
        } catch {
          /* already gone */
        }
        const blocked = !existsSync(sentinel); // deny must have prevented the write
        void activeBridge.close();
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          /* best effort */
        }
        // LIVE only if ALL hold: the WRITE-of-the-sentinel prompt fired, the deny
        // actually BLOCKED the write, AND claude EXITED (a timeout can't confirm
        // the full deny→blocked→exit cycle — a late write could still land).
        resolve({
          gateFires: fired && blocked && exited,
          detail: `${detail}; write-prompt ${fired ? "fired" : "not fired"}; write ${blocked ? "blocked" : "NOT blocked"}`,
        });
      };
      // DENY every prompt; only a Write targeting OUR sentinel counts as the probe
      // firing — a different tool (e.g. Bash) prompting must not satisfy the check
      // while Write stays pre-approved.
      activeBridge.onRequest((req) => {
        activeBridge.resolve(req.requestId, "deny", "gate self-check probe");
        if (req.toolName === "Write" && JSON.stringify(req.input ?? "").includes(sentinel)) fired = true;
      });
      const timer = setTimeout(() => finish("timeout", false), timeoutMs);
      try {
        child = spawn(
          command,
          [
            "-p", `Use the Write tool to create the file ${sentinel} with the exact content GATE-PROBE. Do nothing else.`,
            "--output-format", "stream-json", "--verbose",
            "--permission-mode", "default",
            "--mcp-config", mcpConfig, "--strict-mcp-config",
            "--permission-prompt-tool", PERMISSION_PROMPT_TOOL,
          ],
          { env: { ...scrubbedChildEnv(env), HUGIN_GATE_SENTINEL: sentinel }, stdio: ["ignore", "pipe", "pipe"] },
        );
      } catch (e) {
        finish(`spawn failed: ${(e as Error).message}`, false);
        return;
      }
      child.stdout?.on("data", (d: Buffer) => (out += d.toString()));
      child.stderr?.on("data", (d: Buffer) => (out += d.toString()));
      child.on("error", (e) => finish(`spawn error: ${e.message}`, false));
      child.on("close", () => {
        const loginErr = /not logged in|please run \/login|unauthorized|invalid api key/i.test(out);
        finish(loginErr ? "login lost under isolation" : "claude exited", true);
      });
    });
  } catch (e) {
    if (bridge) {
      try {
        await bridge.close(); // close the live server the setup left running (Codex r2 #6)
      } catch {
        /* best effort */
      }
    }
    if (runDir) {
      try {
        rmSync(runDir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    }
    return { gateFires: false, detail: `gate self-check setup failed: ${(e as Error).message}` };
  }
}
