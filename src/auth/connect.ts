/**
 * Browser-initiated rev2 pairing (auth-pairing-spec §3): paste hpk1 token,
 * prove possession of a fresh Ed25519 device key, wait for browser fingerprint
 * activation, then persist the paired identity.
 *
 * The private key seed never leaves the host. Pairing sends only the public key
 * plus a PoP signature, and the in-memory seed is scrubbed on every exit path.
 */

import { z } from "zod";
import { b64u, deriveKeypairFromSeed, signTranscript } from "../../protocol/v1/ed25519";
import { PROTOCOL_VERSION } from "../../protocol/v1/messages";
import { canonicalizeServerOrigin } from "../../protocol/v1/origin";
import { buildPairingTranscript, keyFingerprint, PAIRING_SECRET_RE } from "../../protocol/v1/pairing";
import { configFilePath } from "./paths";
import { writePairingConfig } from "./config-file";
import { keychainSeedStore, newDeviceKey, type SeedStore } from "./keystore";
import { parsePairingToken } from "./pairing-token";

const AuthId = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/);

const CompleteResponse = z.strictObject({
  status: z.literal("pending"),
  fingerprint: z.string().regex(PAIRING_SECRET_RE),
  poll_token: z.string().min(1).max(1024),
});

const StatusResponse = z.discriminatedUnion("status", [
  z.strictObject({ status: z.literal("pending") }),
  z.strictObject({ status: z.literal("rejected") }),
  z.strictObject({
    status: z.literal("active"),
    agent_id: AuthId,
    key_id: AuthId,
    tenant_id: AuthId,
  }),
]);

export interface ConnectOptions {
  /** The pasted hpk1 token. */
  token: string;
  agentVersion?: string;
  seedStore?: SeedStore;
  configPath?: string;
  fetchImpl?: typeof fetch;
  sleepImpl?: (ms: number) => Promise<void>;
  nowImpl?: () => number;
  onFingerprint?: (fp: string) => void;
  pollIntervalMs?: number;
  pollDeadlineMs?: number;
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

interface PairingEndpoints {
  complete: string;
  status: string;
}

function pairingEndpoints(canonicalOrigin: string): PairingEndpoints {
  const url = new URL(canonicalOrigin);
  const scheme = url.protocol === "wss:" ? "https" : "http";
  const base = `${scheme}://${url.host}/api/v1/hugin-agents/pair`;
  return {
    complete: `${base}/complete`,
    status: `${base}/status`,
  };
}

function validatePollingOptions(pollIntervalMs: number, pollDeadlineMs: number): void {
  if (!Number.isFinite(pollIntervalMs) || pollIntervalMs <= 0) {
    throw new Error("invalid pairing poll interval");
  }
  if (!Number.isFinite(pollDeadlineMs) || pollDeadlineMs <= 0) {
    throw new Error("invalid pairing poll deadline");
  }
}

async function postJson(fetchImpl: typeof fetch, url: string, body: unknown): Promise<Response> {
  return fetchImpl(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      "cache-control": "no-store",
    },
    body: JSON.stringify(body),
  });
}

async function readJson(res: Response, message: string): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    throw new Error(message);
  }
}

function parseCompleteResponse(value: unknown): z.infer<typeof CompleteResponse> {
  try {
    return CompleteResponse.parse(value);
  } catch {
    throw new Error("pairing server returned an invalid completion response; re-pair this device");
  }
}

function parseStatusResponse(value: unknown): z.infer<typeof StatusResponse> {
  try {
    return StatusResponse.parse(value);
  } catch {
    throw new Error("pairing server returned an invalid status response; re-pair this device");
  }
}

export async function connect(opts: ConnectOptions): Promise<PairingResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const sleep = opts.sleepImpl ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = opts.nowImpl ?? (() => Date.now());
  const seedStore = opts.seedStore ?? keychainSeedStore();
  const configPath = opts.configPath ?? configFilePath();
  const onFingerprint = opts.onFingerprint ?? (() => undefined);
  const pollIntervalMs = opts.pollIntervalMs ?? 2000;
  const pollDeadlineMs = opts.pollDeadlineMs ?? 600_000;
  validatePollingOptions(pollIntervalMs, pollDeadlineMs);

  const parsedToken = parsePairingToken(opts.token, now());
  const canonicalOrigin = canonicalizeServerOrigin(parsedToken.origin);
  if (canonicalOrigin === null) {
    throw new Error("pairing token origin is invalid; re-copy the token");
  }
  const endpoints = pairingEndpoints(canonicalOrigin);

  const dk = newDeviceKey();
  try {
    const localFingerprint = keyFingerprint(dk.publicRaw);

    const completePairing = async (): Promise<string> => {
      const transcript = buildPairingTranscript({
        secret: parsedToken.secret,
        publicRaw: dk.publicRaw,
        server_origin: canonicalOrigin,
        protocol_version: PROTOCOL_VERSION,
      });
      const { privateKey } = deriveKeypairFromSeed(dk.seed);
      const popSignature = signTranscript(privateKey, transcript);

      const res = await postJson(fetchImpl, endpoints.complete, {
        secret: parsedToken.secret,
        public_key: b64u(dk.publicRaw),
        pop_signature: popSignature,
      });
      if (res.status !== 202) {
        throw new Error("pairing completion failed; re-copy the token or re-pair this device");
      }
      const complete = parseCompleteResponse(
        await readJson(res, "pairing server returned an invalid completion response; re-pair this device"),
      );
      if (complete.fingerprint !== localFingerprint) {
        throw new Error("pairing server fingerprint mismatch; re-copy the token");
      }
      return complete.poll_token;
    };

    let pollToken = await completePairing();
    onFingerprint(localFingerprint);

    const deadline = now() + pollDeadlineMs;
    let recoveredFromMissingPollToken = false;
    while (now() < deadline) {
      const res = await postJson(fetchImpl, endpoints.status, { poll_token: pollToken });
      if (res.status === 404) {
        if (recoveredFromMissingPollToken) {
          throw new Error("pairing status expired; re-pair this device");
        }
        pollToken = await completePairing();
        recoveredFromMissingPollToken = true;
        continue;
      }
      if (res.status !== 200) {
        throw new Error("pairing status request failed; re-pair this device");
      }

      const poll = parseStatusResponse(
        await readJson(res, "pairing server returned an invalid status response; re-pair this device"),
      );
      if (poll.status === "pending") {
        await sleep(pollIntervalMs);
        continue;
      }
      if (poll.status === "rejected") {
        throw new Error("pairing was rejected; re-pair this device");
      }

      await seedStore.set(poll.key_id, dk.seed);
      writePairingConfig(configPath, {
        serverUrl: canonicalOrigin,
        agentId: poll.agent_id,
        keyId: poll.key_id,
        tenantId: poll.tenant_id,
      });
      return {
        agentId: poll.agent_id,
        keyId: poll.key_id,
        tenantId: poll.tenant_id,
        serverUrl: canonicalOrigin,
        configPath,
      };
    }
    throw new Error("pairing timed out; re-pair this device");
  } finally {
    dk.seed.fill(0); // scrub the in-memory seed on every path (the store has its own copy)
  }
}
