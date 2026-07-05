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
import { type Message, negotiateVersion } from "../../protocol/v1/index";
import { buildTranscript } from "../../protocol/v1/transcript";
import { canonicalizeServerOrigin } from "../../protocol/v1/origin";
import { canonicalizeDevOrigin } from "../simple-pairing-dev";
import type { Config } from "../config";
import { envelope } from "./outbound";
import type { RelayClient } from "./client";
import type { EngineCapabilities } from "../engine/detect";

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
  /** Resume directives the server returned for our reported durable state. */
  resume: Extract<Message, { type: "hello.accepted" }>["resume"];
}

type HelloMsg = Extract<Message, { type: "hello" }>;

/** Durable state reported in `hello` so the server can issue resume directives. */
export interface ResumeState {
  activeJobs: HelloMsg["active_jobs"];
  pendingResults: HelloMsg["pending_results"];
}

export interface HandshakeOpts {
  timeoutMs?: number;
  engines: EngineCapabilities;
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
  resume: ResumeState,
  opts: HandshakeOpts,
): Promise<HandshakeResult> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const challenge = (await client.waitFor((m) => m.type === "auth.challenge", timeoutMs)) as Extract<
    Message,
    { type: "auth.challenge" }
  >;

  const canonicalizeOrigin = config.allowDevOrigin ? canonicalizeDevOrigin : canonicalizeServerOrigin;
  const origin = canonicalizeOrigin(config.serverUrl);
  if (origin === null) throw new Error(`non-canonical serverUrl: ${config.serverUrl}`);
  const protocolVersion = config.protocolVersion;

  const transcript = buildTranscript({
    challenge_id: challenge.challenge_id,
    nonce_raw: Buffer.from(challenge.nonce, "base64url"),
    agent_id: config.agentId,
    key_id: signer.keyId,
    protocol_version: protocolVersion,
    tenant_id: config.tenantId,
    server_origin: origin,
  });

  const hello: Message = {
    ...envelope(),
    type: "hello",
    protocol_version: protocolVersion,
    agent_id: config.agentId,
    agent_version: config.agentVersion,
    auth: {
      challenge_id: challenge.challenge_id,
      key_id: signer.keyId,
      signature: signer.sign(transcript),
      alg: "ed25519",
    },
    os: { platform: nodePlatform(), arch: process.arch },
    // Stay inside the frozen v1 Capabilities schema. capabilities.sessions is
    // deferred until a v2 Hello/Capabilities schema exists; C2 infers session.*
    // support from negotiated_version >= 2.x.
    capabilities: {
      engines: opts.engines,
      project_roots: config.projectRoots,
    },
    active_jobs: resume.activeJobs,
    pending_results: resume.pendingResults,
  };
  client.send(hello);
  // Only now is a hello.accepted valid — it must follow our signed hello. Arming
  // AFTER the send makes the client discard any accept the relay sent BEFORE the
  // possession proof, so the waitFor below can only resolve on a post-hello accept.
  client.armForAccept();

  const reply = await client.waitFor(
    (m) => m.type === "hello.accepted" || m.type === "hello.rejected",
    timeoutMs,
  );
  if (reply.type === "hello.rejected") {
    const r = reply as Extract<Message, { type: "hello.rejected" }>;
    throw new Error(`hello.rejected: ${r.code} — ${r.message}`);
  }
  const accepted = reply as Extract<Message, { type: "hello.accepted" }>;
  const negotiated = negotiateVersion(config.protocolVersion, [accepted.negotiated_version]);
  if (!negotiated.ok || negotiated.version !== accepted.negotiated_version) {
    throw new Error(
      `relay negotiated an unsupported version "${accepted.negotiated_version}" (agent advertised "${config.protocolVersion}")`,
    );
  }
  client.setNegotiatedVersion(accepted.negotiated_version);
  client.setAuthed(true);
  return {
    negotiatedVersion: accepted.negotiated_version,
    connectionEpoch: accepted.connection_epoch,
    heartbeatIntervalMs: accepted.heartbeat_interval_ms,
    resume: accepted.resume,
  };
}
