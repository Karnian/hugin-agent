/**
 * hugind entrypoint. Config comes from the environment:
 *   HUGIND_SERVER_URL   (required)  wss://relay.example.com   (ws:// only loopback)
 *   HUGIND_AGENT_ID     (required)  per-device agent id
 *   HUGIND_KEY_ID       dev-key
 *   HUGIND_TENANT_ID    dev-tenant
 *   HUGIND_AGENT_VERSION 0.0.0
 *   HUGIND_PROTOCOL_VERSION 2.0.0 default (set 1.0.0 only for a v1-only relay)
 *   HUGIND_PROJECT_ROOTS comma-separated absolute paths
 *   HUGIND_STATE_DIR    .hugind
 *   HUGIND_ENGINE_CMD   (test override)
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { type Config, loadConfig } from "./config";
import { Daemon } from "./daemon";
import type { Signer } from "./conn/handshake";
import { keychainSigner } from "./auth/keystore";
import { readPairingConfig } from "./auth/config-file";
import { configFilePath } from "./auth/paths";
import { ClaudeEngine } from "./engine/claude";
import { buildIsolation, selfCheckGate, selfCheckLogin } from "./engine/isolate";
import { detectEngineCapabilities } from "./engine/detect";
import { invokedAsMain } from "./entrypoint";
import { log } from "./log";
import { simplePairingGateEnabled } from "./simple-pairing-dev";
import { SessionEnumerator } from "./sessions/enumerator";
import { ClaudeResumeRunner, CodexResumeRunner } from "./sessions/resume";

export function loadConfigFromEnv(env: NodeJS.ProcessEnv = process.env): Config {
  const roots =
    env.HUGIND_PROJECT_ROOTS?.split(",")
      .map((s) => s.trim())
      .filter(Boolean) ?? [];
  // Persisted pairing identity (`hugin-agent connect`) is the baseline; each
  // HUGIND_* env var overrides its field (tests / custom installs). A malformed
  // config file throws here → fail closed rather than run half-paired.
  const paired = readPairingConfig(configFilePath());
  return loadConfig({
    serverUrl: env.HUGIND_SERVER_URL ?? paired?.serverUrl,
    agentId: env.HUGIND_AGENT_ID ?? paired?.agentId,
    keyId: env.HUGIND_KEY_ID ?? paired?.keyId,
    tenantId: env.HUGIND_TENANT_ID ?? paired?.tenantId,
    agentVersion: env.HUGIND_AGENT_VERSION,
    protocolVersion: env.HUGIND_PROTOCOL_VERSION,
    allowDevOrigin: simplePairingGateEnabled(env.HUGIN_SIMPLE_PAIRING),
    projectRoots: roots,
    stateDir: env.HUGIND_STATE_DIR,
    engineCommand: env.HUGIND_ENGINE_CMD,
  });
}

function loadConfigOrExit(): Config {
  try {
    return loadConfigFromEnv();
  } catch (e) {
    log.error("invalid config — pair with `hugin-agent connect`, or set HUGIND_SERVER_URL + HUGIND_AGENT_ID", {
      err: String(e),
    });
    process.exit(1);
  }
}

export async function runDaemon(): Promise<void> {
  const config = loadConfigOrExit();
  const engineCapabilities = await detectEngineCapabilities({ claudeCommand: config.engineCommand });

  // Permission isolation + startup login self-check (plan §5.6). If isolation
  // drops the login (macOS keychain hosts — see isolate.ts) and no env-auth was
  // injected, fall back to the host config so read_only jobs can still run.
  const iso = buildIsolation(config.isolation, config.stateDir);
  let engineEnv = iso.env;
  let isolatedConfig = false; // running under the ISOLATED empty-allow config?
  if (iso.mode !== "none") {
    const login = await selfCheckLogin(iso.env, config.engineCommand);
    if (login.loggedIn) {
      log.info("isolation preserves login", { mode: iso.mode });
      isolatedConfig = true;
    } else {
      log.warn("isolation dropped the login — using host config", { mode: iso.mode, detail: login.detail });
      iso.cleanup();
      engineEnv = {};
    }
  }
  // Track B: the approval gate is LIVE only when BOTH hold — (1) we run under the
  // ISOLATED empty-allow config, where EVERY tool uniformly prompts (a host
  // allow-list or `none` could pre-approve some tool like Bash and let it bypass
  // the bridge — so gated jobs must NOT run there), and (2) a forced Write is
  // actually gated AND a deny BLOCKS it. Under empty-allow, the Write probe
  // passing implies all dangerous tools are gated the same way. Anywhere else →
  // fail closed: gated (write/exec or approval_policy != never) jobs are rejected;
  // read_only jobs still run with their write/exec tools disallowed at the engine.
  let gateAvailable = false;
  if (isolatedConfig) {
    const gate = await selfCheckGate(engineEnv, config.engineCommand);
    gateAvailable = gate.gateFires;
    if (gateAvailable) log.info("approval gate LIVE — gated jobs run with remote approval", { detail: gate.detail });
    else log.warn("approval gate unavailable — gated jobs rejected (fail closed); read_only runs", { detail: gate.detail });
  } else {
    log.warn("no isolated permission config (host-fallback or none) — approval gate unavailable; gated jobs rejected (fail closed), read_only runs");
  }

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

  const sessionEnumerator = new SessionEnumerator({
    claudeProjectsDir: join(homedir(), ".claude/projects"),
    codexSessionsDir: join(homedir(), ".codex/sessions"),
    allowlist: config.projectRoots,
  });
  const resumeRunners = {
    claude: new ClaudeResumeRunner({ command: config.engineCommand, env: engineEnv }),
    codex: new CodexResumeRunner({ env: engineEnv }),
  };
  const daemon = new Daemon(config, signer, engine, gateAvailable, sessionEnumerator, resumeRunners, engineCapabilities);
  const shutdown = () => {
    log.info("signal received — shutting down");
    daemon.stop();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  log.info("hugind starting", { serverUrl: config.serverUrl, agentId: config.agentId });
  await daemon.start();
}

if (invokedAsMain(import.meta.url, "index")) {
  runDaemon().catch((e) => {
    log.error("fatal", { err: String(e) });
    process.exit(1);
  });
}
