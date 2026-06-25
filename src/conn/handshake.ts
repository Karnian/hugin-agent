/**
 * Authenticated handshake: `auth.challenge` → signed `hello` → `hello.accepted`.
 *
 * MVP is NON-AUTH: the `Signer` is a DEV ephemeral Ed25519 key and the mock relay
 * accepts any signature. The signing path is real, though — it builds the
 * canonical transcript (`protocol/v1/transcript`) and a 64-byte Ed25519 signature
 * — so swapping `devSigner` for the OS-keychain device key is the only change for
 * production (no caller change).
 */

import { generateKeyPairSync, sign } from "node:crypto";
import { type Message, PROTOCOL_VERSION } from "../../protocol/v1/index";
import { buildTranscript } from "../../protocol/v1/transcript";
import { canonicalizeServerOrigin } from "../../protocol/v1/origin";
import type { Config } from "../config";
import { envelope } from "./outbound";
import type { RelayClient } from "./client";

export interface Signer {
  keyId: string;
  /** Sign the canonical transcript; return the base64url (unpadded) signature. */
  sign(transcript: Buffer): string;
}

/** DEV-ONLY non-auth signer: an ephemeral Ed25519 key. Production replaces this
 *  with a keychain-backed device-key signer. */
export function devSigner(keyId = "dev-key"): Signer {
  const { privateKey } = generateKeyPairSync("ed25519");
  return {
    keyId,
    sign: (transcript: Buffer) => sign(null, transcript, privateKey).toString("base64url"),
  };
}

export interface HandshakeResult {
  negotiatedVersion: string;
  connectionEpoch: number;
  heartbeatIntervalMs: number;
}

function nodePlatform(): "darwin" | "linux" | "win32" {
  const p = process.platform;
  if (p === "darwin" || p === "linux" || p === "win32") return p;
  throw new Error(`unsupported platform "${p}"`);
}

export async function performHandshake(
  client: RelayClient,
  config: Config,
  signer: Signer,
  timeoutMs = 10_000,
): Promise<HandshakeResult> {
  const challenge = (await client.waitFor((m) => m.type === "auth.challenge", timeoutMs)) as Extract<
    Message,
    { type: "auth.challenge" }
  >;

  const origin = canonicalizeServerOrigin(config.serverUrl);
  if (origin === null) throw new Error(`non-canonical serverUrl: ${config.serverUrl}`);

  const transcript = buildTranscript({
    challenge_id: challenge.challenge_id,
    nonce_raw: Buffer.from(challenge.nonce, "base64url"),
    agent_id: config.agentId,
    key_id: signer.keyId,
    protocol_version: PROTOCOL_VERSION,
    tenant_id: config.tenantId,
    server_origin: origin,
  });

  const hello: Message = {
    ...envelope(),
    type: "hello",
    protocol_version: PROTOCOL_VERSION,
    agent_id: config.agentId,
    agent_version: config.agentVersion,
    auth: {
      challenge_id: challenge.challenge_id,
      key_id: signer.keyId,
      signature: signer.sign(transcript),
      alg: "ed25519",
    },
    os: { platform: nodePlatform(), arch: process.arch },
    // P1 stub capabilities; real engine detection lands in P2b.
    capabilities: {
      engines: { claude: { installed: true }, codex: { installed: false } },
      project_roots: config.projectRoots,
    },
    active_jobs: [],
    pending_results: [],
  };
  client.send(hello);

  const reply = await client.waitFor(
    (m) => m.type === "hello.accepted" || m.type === "hello.rejected",
    timeoutMs,
  );
  if (reply.type === "hello.rejected") {
    const r = reply as Extract<Message, { type: "hello.rejected" }>;
    throw new Error(`hello.rejected: ${r.code} — ${r.message}`);
  }
  const accepted = reply as Extract<Message, { type: "hello.accepted" }>;
  client.setAuthed(true);
  return {
    negotiatedVersion: accepted.negotiated_version,
    connectionEpoch: accepted.connection_epoch,
    heartbeatIntervalMs: accepted.heartbeat_interval_ms,
  };
}
