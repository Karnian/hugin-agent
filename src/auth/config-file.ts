/**
 * The daemon's persisted pairing identity (auth-pairing-spec §3 step 4) — a
 * NON-SECRET JSON file written by `hugin-agent connect` and read by the daemon at
 * startup. It carries only what the handshake needs to build the signed
 * transcript: the server URL to dial, the per-device `agent_id`, the `key_id`
 * selecting the keychain-resident device key, and the `tenant_id` bound into the
 * transcript. `user_id` is off-wire (pairing-record only) and NOT stored here;
 * the private key stays in the OS keychain, never in this file.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";

/** Same charsets as the wire `AuthId` / tenant grammar (auth-pairing-spec §2). */
const AuthId = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/);
const TenantId = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/);

export const PairingConfigFile = z.strictObject({
  /** Schema version for forward-compat (bump on a breaking config change). */
  version: z.literal(1).default(1),
  /** Canonical ws(s):// relay origin the daemon dials (auth-pairing-spec §5). */
  serverUrl: z.string().refine((u) => u.startsWith("wss://") || u.startsWith("ws://"), "serverUrl must be ws(s)://"),
  agentId: AuthId,
  keyId: AuthId,
  tenantId: TenantId,
});

export type PairingConfigFile = z.infer<typeof PairingConfigFile>;

/** Read + validate the pairing config; returns null if the file does not exist.
 *  A malformed file THROWS (fail closed — never silently run half-paired). */
export function readPairingConfig(path: string): PairingConfigFile | null {
  if (!existsSync(path)) return null;
  return PairingConfigFile.parse(JSON.parse(readFileSync(path, "utf8")));
}

/** Atomically-ish write the pairing config (0600 — device identity, non-secret
 *  but not world-readable). Creates the parent directory as needed. */
export function writePairingConfig(path: string, cfg: Omit<PairingConfigFile, "version">): void {
  const validated = PairingConfigFile.parse({ version: 1, ...cfg });
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(validated, null, 2)}\n`, { mode: 0o600 });
}
