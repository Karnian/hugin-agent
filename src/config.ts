/**
 * hugind daemon configuration (non-secret). The device private key and provider
 * tokens never live here — they stay in the OS keychain / the engine's own auth.
 */

import { z } from "zod";
import { LIMITS } from "../protocol/v1/index";

/** Matches the wire `AuthId` charset (messages.ts) so a configured `agentId`
 *  can be put on the wire without re-validation. */
const AuthId = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/);

export const Config = z.strictObject({
  /** Relay origin the daemon dials out to. This is a coarse user-facing guard;
   *  the HARD gate is `canonicalizeServerOrigin` at handshake time, which rejects
   *  non-canonical origins and limits `ws://` to loopback (auth-spec §5). */
  serverUrl: z
    .string()
    .refine((u) => u.startsWith("wss://") || u.startsWith("ws://"), "serverUrl must be ws(s)://"),
  /** Per-device agent id (server-minted at pairing). */
  agentId: AuthId,
  /** Device key id selecting the signing key (a stub key in the non-auth MVP). */
  keyId: AuthId.default("dev-key"),
  /** Daemon version reported in `hello.agent_version`. */
  agentVersion: z.string().regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/).max(64).default("0.0.0"),
  /** Tenant the device is paired to (off-wire; used only to build the signed
   *  transcript). Grammar 1*128(ALPHA/DIGIT/-/_/.). */
  tenantId: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/).default("dev-tenant"),
  /** Absolute repo roots jobs may run under (allowlist; realpath-checked at use). */
  projectRoots: z.array(z.string()).default([]),
  /** Daemon-owned dir for per-attempt worktrees + the SQLite event log. */
  stateDir: z.string().default(".hugind"),
  /** Engine permission-isolation strategy (spike finding). Default is the
   *  spike-proven HOME swap; `config-dir` is promoted only after a startup probe. */
  isolation: z.enum(["home-swap", "config-dir"]).default("home-swap"),
  /** Max concurrent attempts (static cap; credit window is Phase 2). */
  maxConcurrent: z.number().int().positive().max(64).default(2),
  /** Engine command override for tests (the fake engine); defaults to `claude`. */
  engineCommand: z.string().optional(),
  /** SQLite event-log path; `:memory:` for tests. Defaults to
   *  `<stateDir>/eventlog.db` (computed by the daemon when unset). */
  dbPath: z.string().optional(),
  /** Backpressure caps (default: protocol `LIMITS`; overridable for tests). */
  maxUnackedEventsPerAttempt: z.number().int().positive().default(LIMITS.MAX_UNACKED_EVENTS_PER_ATTEMPT),
  maxUnackedBytesPerAttempt: z.number().int().positive().default(LIMITS.MAX_UNACKED_BYTES_PER_ATTEMPT),
  maxUnackedBytesPerConn: z.number().int().positive().default(LIMITS.MAX_UNACKED_BYTES_PER_CONN),
});

export type Config = z.infer<typeof Config>;

export function loadConfig(raw: unknown): Config {
  return Config.parse(raw);
}
