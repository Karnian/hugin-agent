/**
 * Local paths for the daemon's NON-SECRET pairing config (auth-pairing-spec §3
 * step 4). The device private key never lives here — it stays in the OS keychain
 * (`keystore.ts`). Only `agent_id`/`key_id`/`tenant_id`/serverUrl are persisted.
 *
 * Resolution order (first wins):
 *   1. `HUGIND_CONFIG`      — explicit config-file path (tests, custom installs).
 *   2. `HUGIND_CONFIG_DIR`  — a config directory (file is `<dir>/config.json`).
 *   3. `XDG_CONFIG_HOME`    — `<xdg>/hugin-agent/config.json`.
 *   4. default              — `~/.config/hugin-agent/config.json`.
 */

import { homedir } from "node:os";
import { join } from "node:path";

/** The directory the pairing config lives in (honors the env overrides above). */
export function configDir(): string {
  const dirOverride = process.env.HUGIND_CONFIG_DIR;
  if (dirOverride) return dirOverride;
  const xdg = process.env.XDG_CONFIG_HOME;
  if (xdg) return join(xdg, "hugin-agent");
  return join(homedir(), ".config", "hugin-agent");
}

/** Absolute path to the pairing config JSON. */
export function configFilePath(): string {
  return process.env.HUGIND_CONFIG ?? join(configDir(), "config.json");
}
