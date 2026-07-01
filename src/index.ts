/**
 * hugind entrypoint. Config comes from the environment:
 *   HUGIND_SERVER_URL   (required)  wss://relay.example.com   (ws:// only loopback)
 *   HUGIND_AGENT_ID     (required)  per-device agent id
 *   HUGIND_KEY_ID       dev-key
 *   HUGIND_TENANT_ID    dev-tenant
 *   HUGIND_AGENT_VERSION 0.0.0
 *   HUGIND_PROJECT_ROOTS comma-separated absolute paths
 *   HUGIND_STATE_DIR    .hugind
 *   HUGIND_ENGINE_CMD   (test override)
 */

import { type Config, loadConfig } from "./config";
import { Daemon } from "./daemon";
import { devSigner } from "./conn/handshake";
import { ClaudeEngine } from "./engine/claude";
import { buildIsolation, selfCheckLogin } from "./engine/isolate";
import { log } from "./log";

function loadConfigOrExit(): Config {
  const roots =
    process.env.HUGIND_PROJECT_ROOTS?.split(",")
      .map((s) => s.trim())
      .filter(Boolean) ?? [];
  try {
    return loadConfig({
      serverUrl: process.env.HUGIND_SERVER_URL,
      agentId: process.env.HUGIND_AGENT_ID,
      keyId: process.env.HUGIND_KEY_ID,
      tenantId: process.env.HUGIND_TENANT_ID,
      agentVersion: process.env.HUGIND_AGENT_VERSION,
      projectRoots: roots,
      stateDir: process.env.HUGIND_STATE_DIR,
      engineCommand: process.env.HUGIND_ENGINE_CMD,
    });
  } catch (e) {
    log.error("invalid config (set HUGIND_SERVER_URL + HUGIND_AGENT_ID at minimum)", {
      err: String(e),
    });
    process.exit(1);
  }
}

async function main(): Promise<void> {
  const config = loadConfigOrExit();

  // Permission isolation + startup login self-check (plan §5.6). If isolation
  // drops the login (macOS keychain hosts — see isolate.ts), fall back to the
  // host config; the approval gate is then UNAVAILABLE and gated write/exec jobs
  // must fail closed (P3 wires the enforcement + the prompt bridge).
  const iso = buildIsolation(config.isolation, config.stateDir);
  let engineEnv = iso.env;
  if (iso.mode !== "none") {
    const login = await selfCheckLogin(iso.env, config.engineCommand);
    if (login.loggedIn) {
      log.info("permission isolation active + login preserved", { mode: iso.mode });
    } else {
      log.warn("isolation dropped the login — falling back to host config; approval gate UNAVAILABLE (gated jobs must fail closed, P3)", { mode: iso.mode, detail: login.detail });
      iso.cleanup();
      engineEnv = {};
    }
  } else {
    log.warn("isolation=none — under host config; approval gate disabled if the host allow-list is permissive (P3 fail-closed)");
  }

  const engine = new ClaudeEngine({
    command: config.engineCommand,
    env: engineEnv,
    allowlist: config.projectRoots,
    stateDir: config.stateDir,
    timeoutMs: 3_600_000,
  });
  const daemon = new Daemon(config, devSigner(config.keyId), engine);
  const shutdown = () => {
    log.info("signal received — shutting down");
    daemon.stop();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  log.info("hugind starting", { serverUrl: config.serverUrl, agentId: config.agentId });
  await daemon.start();
}

main().catch((e) => {
  log.error("fatal", { err: String(e) });
  process.exit(1);
});
