/**
 * Device pairing flow (auth-pairing-spec §3) — the client side of `hugin-agent
 * connect --server <url>`.
 *
 *   1. Mint an Ed25519 device keypair in memory (nothing persisted yet).
 *   2. Start a device-code flow, sending ONLY the PUBLIC key; show the user code.
 *   3. Poll until the server approves: it mints `agent_id`, registers the public
 *      key, and returns `agent_id`/`key_id`/`tenant_id`(/`user_id`) + the relay
 *      URL to dial.
 *   4. Persist the seed to the OS keychain under the server-assigned `key_id`,
 *      and write the non-secret pairing config.
 *
 * The private key (seed) NEVER leaves the host — the wire carries only the public
 * key at start and, later, signatures at handshake. The in-memory seed is
 * scrubbed on every exit path.
 */

import { z } from "zod";
import { canonicalizeServerOrigin } from "../../protocol/v1/origin";
import { log } from "../log";
import { configFilePath } from "./paths";
import { writePairingConfig } from "./config-file";
import { keychainSeedStore, newDeviceKey, type SeedStore } from "./keystore";

const AuthId = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/);

/** `POST /v1/pair/start` response (RFC 8628-style device authorization). */
const StartResponse = z.object({
  device_code: z.string().min(1).max(512),
  user_code: z.string().min(1).max(64),
  verification_uri: z.string().min(1).max(512),
  interval_ms: z.number().int().positive().max(60_000),
  expires_in_ms: z.number().int().positive().max(3_600_000),
});

/** `POST /v1/pair/poll` response. `approved` carries the minted pairing record. */
const PollResponse = z.discriminatedUnion("status", [
  z.object({ status: z.literal("pending") }),
  z.object({ status: z.literal("denied") }),
  z.object({ status: z.literal("expired") }),
  z.object({
    status: z.literal("approved"),
    agent_id: AuthId,
    key_id: AuthId,
    tenant_id: AuthId,
    user_id: z.string().max(256).optional(),
    /** ws(s):// relay origin to dial (validated canonical before persist). */
    relay_url: z.string().min(1).max(512),
  }),
]);

export interface ConnectOptions {
  /** Pairing server base URL (http/https). */
  serverUrl: string;
  agentVersion?: string;
  /** Where to store the device seed (default: the OS keychain). */
  seedStore?: SeedStore;
  /** Config-file path (default: resolved from env / XDG / ~/.config). */
  configPath?: string;
  /** Injected for tests; defaults to the global fetch. */
  fetchImpl?: typeof fetch;
  /** Called with the user code + URL to display (default: log to stderr). */
  onUserCode?: (info: { userCode: string; verificationUri: string }) => void;
  /** Test hooks. */
  sleepImpl?: (ms: number) => Promise<void>;
  nowImpl?: () => number;
}

export interface PairingResult {
  agentId: string;
  keyId: string;
  tenantId: string;
  userId?: string;
  /** Canonical relay origin persisted as the daemon's serverUrl. */
  serverUrl: string;
  configPath: string;
}

async function postJson(fetchImpl: typeof fetch, url: string, body: unknown): Promise<unknown> {
  const res = await fetchImpl(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${url} → HTTP ${res.status}`);
  return res.json();
}

/**
 * Run the pairing flow to completion. Resolves with the minted identity (already
 * persisted); rejects on denial / expiry / timeout / malformed server response.
 */
export async function connect(opts: ConnectOptions): Promise<PairingResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const sleep = opts.sleepImpl ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = opts.nowImpl ?? (() => Date.now());
  const seedStore = opts.seedStore ?? keychainSeedStore();
  const configPath = opts.configPath ?? configFilePath();
  const base = opts.serverUrl.replace(/\/+$/, ""); // trim trailing slashes
  const onUserCode =
    opts.onUserCode ??
    ((i) => log.info("approve this device to finish pairing", { url: i.verificationUri, code: i.userCode }));

  const dk = newDeviceKey();
  try {
    // 1. start — send ONLY the public key.
    const start = StartResponse.parse(
      await postJson(fetchImpl, `${base}/v1/pair/start`, {
        public_key: dk.publicRaw.toString("base64url"),
        agent_version: opts.agentVersion ?? "0.0.0",
        os: { platform: process.platform, arch: process.arch },
      }),
    );
    onUserCode({ userCode: start.user_code, verificationUri: start.verification_uri });

    // 2. poll until approved / terminal.
    const deadline = now() + start.expires_in_ms;
    while (now() < deadline) {
      await sleep(start.interval_ms);
      const poll = PollResponse.parse(await postJson(fetchImpl, `${base}/v1/pair/poll`, { device_code: start.device_code }));
      if (poll.status === "pending") continue;
      if (poll.status === "denied") throw new Error("pairing was denied");
      if (poll.status === "expired") throw new Error("pairing code expired before approval");

      // 3. approved — validate the relay URL, persist the seed + config.
      const serverUrl = canonicalizeServerOrigin(poll.relay_url);
      if (serverUrl === null) throw new Error(`server returned a non-canonical relay_url: ${poll.relay_url}`);
      await seedStore.set(poll.key_id, dk.seed);
      writePairingConfig(configPath, {
        serverUrl,
        agentId: poll.agent_id,
        keyId: poll.key_id,
        tenantId: poll.tenant_id,
      });
      return {
        agentId: poll.agent_id,
        keyId: poll.key_id,
        tenantId: poll.tenant_id,
        userId: poll.user_id,
        serverUrl,
        configPath,
      };
    }
    throw new Error("pairing timed out waiting for approval");
  } finally {
    dk.seed.fill(0); // scrub the in-memory seed on every path (the store has its own copy)
  }
}
