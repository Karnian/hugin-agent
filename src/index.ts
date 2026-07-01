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
import type { Signer } from "./conn/handshake";
import { keychainSigner } from "./auth/keystore";
import { readPairingConfig } from "./auth/config-file";
import { configFilePath } from "./auth/paths";
import { ClaudeEngine } from "./engine/claude";
import { buildIsolation, selfCheckLogin } from "./engine/isolate";
import { log } from "./log";

function loadConfigOrExit(): Config {
  const roots =
    process.env.HUGIND_PROJECT_ROOTS?.split(",")
      .map((s) => s.trim())
      .filter(Boolean) ?? [];
  try {
    // Persisted pairing identity (`hugin-agent connect`) is the baseline; each
    // HUGIND_* env var overrides its field (tests / custom installs). A malformed
    // config file throws here → fail closed rather than run half-paired.
    const paired = readPairingConfig(configFilePath());
    return loadConfig({
      serverUrl: process.env.HUGIND_SERVER_URL ?? paired?.serverUrl,
      agentId: process.env.HUGIND_AGENT_ID ?? paired?.agentId,
      keyId: process.env.HUGIND_KEY_ID ?? paired?.keyId,
      tenantId: process.env.HUGIND_TENANT_ID ?? paired?.tenantId,
      agentVersion: process.env.HUGIND_AGENT_VERSION,
      projectRoots: roots,
      stateDir: process.env.HUGIND_STATE_DIR,
      engineCommand: process.env.HUGIND_ENGINE_CMD,
    });
  } catch (e) {
    log.error("invalid config — pair with `hugin-agent connect`, or set HUGIND_SERVER_URL + HUGIND_AGENT_ID", {
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
  // Isolation-readiness diagnostic: does isolation preserve the login? (A login
  // probe is necessary-but-not-sufficient — it does NOT prove the permission
  // prompt fires; that needs the real MCP bridge, deferred.)
  if (iso.mode !== "none") {
    const login = await selfCheckLogin(iso.env, config.engineCommand);
    if (login.loggedIn) {
      log.info("isolation preserves login", { mode: iso.mode });
    } else {
      log.warn("isolation dropped the login — using host config", { mode: iso.mode, detail: login.detail });
      iso.cleanup();
      engineEnv = {};
    }
  }
  // The real approval-prompt bridge (claude --permission-prompt-tool ->
  // onApprovalRequest) is NOT wired to ClaudeEngine yet (deferred with the
  // isolation solve), so there is no LIVE gate for the real engine. Fail closed:
  // gated jobs (write/exec or approval_policy != never) are rejected until the
  // bridge lands. A login probe passing is not proof the gate fires.
  const gateAvailable = false;
  log.warn("approval gate not yet wired (real MCP bridge deferred) — gated jobs are rejected (fail closed); read_only+never jobs run");

  const engine = new ClaudeEngine({
    command: config.engineCommand,
    env: engineEnv,
    allowlist: config.projectRoots,
    stateDir: config.stateDir,
    timeoutMs: 3_600_000,
  });
  // Production device-key signer (auth-pairing-spec §2): loads the keychain seed
  // for key_id and signs the handshake transcript — the transcript bytes +
  // performHandshake caller are unchanged (only the key source is). No paired key
  // → fail closed: an unpaired daemon cannot connect (run `hugin-agent connect`).
  let signer: Signer;
  try {
    signer = await keychainSigner(config.keyId);
  } catch (e) {
    log.error("no device key in the OS keychain — run `hugin-agent connect` to pair this device", { err: String(e) });
    process.exit(1);
  }

  const daemon = new Daemon(config, signer, engine, gateAvailable);
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
