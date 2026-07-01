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
import { FakeEngine } from "./engine/fake-engine";
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
  // P2a: the real Claude adapter lands in P2b; until then jobs run a placeholder
  // fake engine. The transport/handshake/reconnect path above is production-real.
  log.warn("P2a build: using the FAKE engine — the real Claude adapter lands in P2b");
  const engine = new FakeEngine({ events: [{ kind: "system_status", note: "fake engine (P2a)" }] });
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
