/**
 * Minimal mock relay for hugind development/e2e (P1 scope): issues an
 * `auth.challenge`, accepts ANY `hello` (non-auth), assigns a monotonic
 * `connection_epoch`, and exposes an `onAccept` hook so tests can script drops.
 * Job assignment lands in later phases.
 */

import { randomBytes } from "node:crypto";
import { WebSocketServer, type WebSocket, type RawData } from "ws";
import { LIMITS, type Message, type MessageV2, negotiateVersion, PROTOCOL_VERSION, PROTOCOL_VERSION_V2 } from "../protocol/v1/index";
import { resultDigest } from "../protocol/v1/digest";
import { buildTranscript } from "../protocol/v1/transcript";
import { verifyTranscript } from "../protocol/v1/ed25519";
import { canonicalizeServerOrigin, validateTenantId } from "../protocol/v1/origin";
import { decodeInbound } from "../src/conn/framing";
import { messageId } from "../src/util/ids";
import { log } from "../src/log";

/**
 * A pairing record the relay resolves `(agent_id, key_id)` → registered public
 * key against (auth-pairing-spec §2/§3). `tenant_id` and `server_origin` are the
 * OFF-WIRE values the verifier reconstructs from the record + trusted connection
 * metadata — never from `hello` — and binds into the transcript (§5). The mock
 * holds a single record; a real relay looks it up per connection.
 */
export interface PairingRecord {
  agentId: string;
  keyId: string;
  /** Registered raw 32-byte Ed25519 public key, hex-encoded. */
  publicKeyHex: string;
  tenantId: string;
  /** Canonical server_origin the verifier binds (see canonicalizeServerOrigin). */
  serverOrigin: string;
}

export type HandshakeRejectCode = "expired_challenge" | "agent_unknown" | "bad_signature";
export type VerifyResult = { ok: true } | { ok: false; code: HandshakeRejectCode; message: string };

/**
 * Verify a `hello` possession proof (auth-pairing-spec §4 server steps + §5).
 * Pure + exported so an e2e can drive it against the committed F4 vectors.
 *
 * The verifier reconstructs the transcript from TRUSTED values only: the nonce +
 * challenge_id IT issued, the pairing record's `tenant_id`/`server_origin`, and
 * the agent-supplied `agent_id`/`key_id`/`protocol_version` (each pinned to the
 * record / the exact hello value). `tenant_id` and `server_origin` are NEVER read
 * from `hello`. Any field mismatch ⇒ the signature fails ⇒ `bad_signature`.
 */
export function verifyHello(
  hello: Extract<Message, { type: "hello" }>,
  issued: { challengeId: string; nonce: string },
  record: PairingRecord,
): VerifyResult {
  // 0. The pairing record is trusted config, but the verifier NEVER binds a
  //    non-canonical origin or an invalid tenant into the transcript (auth-spec §5
  //    "rejects non-canonical input — never silently normalizes"). A malformed
  //    record is a relay misconfiguration → reject, don't sign off on ambiguous
  //    bytes a differently-canonicalizing client might reproduce.
  if (!validateTenantId(record.tenantId) || canonicalizeServerOrigin(record.serverOrigin) !== record.serverOrigin) {
    return { ok: false, code: "agent_unknown", message: "pairing record has an invalid tenant_id or non-canonical server_origin" };
  }
  // 1. Resolve the nonce by the echoed challenge_id — a mismatch means we never
  //    issued it (or it is stale): treat as an expired/unknown challenge. Replay
  //    is additionally defeated structurally: each connection issues a FRESH
  //    nonce and we reconstruct with the nonce WE issued (not one from `hello`),
  //    so a captured `hello` replayed on a new connection fails the signature.
  //    Cross-connection single-use + TTL is the cloud's linearizable store
  //    (auth-spec §6), out of this mock's scope.
  if (hello.auth.challenge_id !== issued.challengeId) {
    return { ok: false, code: "expired_challenge", message: "unknown or expired challenge_id" };
  }
  // 2. Resolve (agent_id, key_id) → registered public key. The key_id in the
  //    transcript MUST equal hello.auth.key_id and be registered to this agent.
  if (hello.agent_id !== record.agentId || hello.auth.key_id !== record.keyId) {
    return { ok: false, code: "agent_unknown", message: "no registered key for (agent_id, key_id)" };
  }
  const publicRaw = Buffer.from(record.publicKeyHex, "hex");
  if (publicRaw.length !== 32) {
    return { ok: false, code: "agent_unknown", message: "registered public key is not 32 bytes" };
  }
  // 3. Recompute the canonical transcript and verify the Ed25519 signature. The
  //    protocol_version bound is the EXACT hello value (never a negotiated one);
  //    tenant_id + server_origin come from the record, not the wire.
  const transcript = buildTranscript({
    challenge_id: issued.challengeId,
    nonce_raw: Buffer.from(issued.nonce, "base64url"),
    agent_id: hello.agent_id,
    key_id: hello.auth.key_id,
    protocol_version: hello.protocol_version,
    tenant_id: record.tenantId,
    server_origin: record.serverOrigin,
  });
  if (!verifyTranscript(publicRaw, transcript, hello.auth.signature)) {
    return { ok: false, code: "bad_signature", message: "Ed25519 signature does not verify over the transcript" };
  }
  return { ok: true };
}

export interface AcceptCtx {
  ws: WebSocket;
  epoch: number;
  hello: Extract<Message, { type: "hello" }>;
}

export interface MockRelayOpts {
  /** Called right after `hello.accepted` is sent. Tests can `ctx.ws.close()` here. */
  onAccept?: (ctx: AcceptCtx) => void;
  /** Called on every inbound `heartbeat`. */
  onHeartbeat?: () => void;
  /** Heartbeat interval advertised in `hello.accepted` (default: LIMITS value). */
  heartbeatIntervalMs?: number;
  /** Protocol versions this mock relay can negotiate (default: ["1.0.0", "2.0.0"]). */
  supportedVersions?: readonly string[];
  /** Test hook: force the exact accepted negotiated_version after normal negotiation succeeds. */
  forceNegotiatedVersion?: string;
  /** Force a fixed `connection_epoch` instead of the monotonic `++epoch` — used to
   *  exercise the daemon's non-monotonic-epoch rejection. */
  forceEpoch?: number;
  /** Override the challenge nonce (default: a fresh canonical 43-char base64url). */
  nonce?: string;
  /** Auto-send a cumulative `stream.ack` per `stream.event` (default true). Set
   *  false to drive acks manually via `sendAck` (backpressure tests). */
  autoAckStream?: boolean;
  onJobAccept?: (m: Extract<Message, { type: "job.accept" }>) => void;
  onJobReject?: (m: Extract<Message, { type: "job.reject" }>) => void;
  onStreamEvent?: (m: Extract<Message, { type: "stream.event" }>) => void;
  onResult?: (m: Extract<Message, { type: "job.result" }>) => void;
  onApprovalRequest?: (m: Extract<Message, { type: "approval.request" }>) => void;
  onJobStatus?: (m: Extract<Message, { type: "job.status" }>) => void;
  onDraining?: (m: Extract<Message, { type: "agent.draining" }>) => void;
  /** Auto-respond to `approval.request` (default true). Set false to test the
   *  daemon's approval timeout / auto-deny. */
  autoApprove?: boolean;
  /** Decision for the auto-response (default "allow"). */
  approvalDecision?: "allow" | "deny";
  /** Resume directives for a reconnecting daemon's `hello` (default: none). */
  resumeFor?: (hello: Extract<Message, { type: "hello" }>) => Extract<Message, { type: "hello.accepted" }>["resume"];
  /** Auto-send `job.result.ack` (default true). Set false to keep a result
   *  pending across a reconnect (resend_result tests). */
  autoAckResult?: boolean;
  /** Send the challenge but never `hello.accepted` — stalls the handshake (tests
   *  stop() during the pre-auth window). */
  stallHandshake?: boolean;
  /** When set, the relay VERIFIES the `hello` Ed25519 possession proof against
   *  this pairing record (auth-pairing-spec §4/§5) and replies `hello.rejected`
   *  with the failure code on mismatch. Unset ⇒ accept any signature (the
   *  non-auth default the pre-Track-A scenarios rely on). */
  verifyAuth?: PairingRecord;
  /** Called with the reject code when a VERIFIED handshake is refused. */
  onHandshakeReject?: (code: HandshakeRejectCode) => void;
  /** When set, send a `hello.accepted` carrying THIS epoch immediately after the
   *  challenge — BEFORE any `hello` — to exercise the daemon discarding a premature
   *  accept (it must complete only on a post-`hello` accept). */
  prematureAcceptEpoch?: number;
  /** Test hook: send a v2 session.list.request immediately after hello.accepted. */
  sendSessionListAfterAccept?: boolean;
  /** Called when the daemon replies to the test session.list.request. */
  onSessionListResponse?: (m: Extract<MessageV2, { type: "session.list.response" }>) => void;
  /** Test hook: send a v2 session.history.request immediately after hello.accepted. */
  sendSessionHistoryAfterAccept?: { request_id: string; handle: string; cursor?: string; limit?: number };
  /** Called when the daemon replies to the test session.history.request. */
  onSessionHistoryResponse?: (m: Extract<MessageV2, { type: "session.history.response" }>) => void;
  /** Called when the daemon reports a v2 session-layer error. */
  onSessionError?: (m: Extract<MessageV2, { type: "session.error" }>) => void;
  onSessionResumeAccept?: (m: Extract<MessageV2, { type: "session.resume.accept" }>) => void;
  onSessionResumeReject?: (m: Extract<MessageV2, { type: "session.resume.reject" }>) => void;
  onSessionEvent?: (m: Extract<MessageV2, { type: "session.event" }>) => void;
  onSessionTurnResult?: (m: Extract<MessageV2, { type: "session.turn.result" }>) => void;
}

export interface AssignSpec {
  job_id: string;
  attempt_id: string;
  lease_id: string;
  engine?: "claude" | "codex";
  prompt?: string;
  repo_root?: string;
  sandbox?: "read_only" | "workspace_write" | "full";
  approval_policy?: "never" | "on_request" | "on_write" | "always";
}

export interface ResumeSessionSpec {
  request_id: string;
  handle: string;
  message: string;
}

function toBuffer(data: RawData): Buffer {
  if (Array.isArray(data)) return Buffer.concat(data);
  if (Buffer.isBuffer(data)) return data;
  return Buffer.from(data as ArrayBuffer);
}

function isProtocolV2(version: string): boolean {
  const major = Number(version.split(".")[0]);
  return Number.isInteger(major) && major >= 2;
}

export class MockRelay {
  private wss: WebSocketServer | null = null;
  private epoch = 0;
  port = 0;
  private verifyRecord: PairingRecord | null;

  constructor(private readonly opts: MockRelayOpts = {}) {
    this.verifyRecord = opts.verifyAuth ?? null;
  }

  /** Register/replace the pairing record the relay verifies `hello` against.
   *  Used by e2e once the listen port (→ canonical server_origin) is known. */
  setVerifyAuth(record: PairingRecord): void {
    this.verifyRecord = record;
  }

  start(port = 0): Promise<number> {
    return new Promise((resolve, reject) => {
      const wss = new WebSocketServer({ port, host: "127.0.0.1", maxPayload: LIMITS.MAX_FRAME_BYTES });
      this.wss = wss;
      wss.on("listening", () => {
        const addr = wss.address();
        this.port = typeof addr === "object" && addr ? addr.port : port;
        resolve(this.port);
      });
      wss.on("error", reject);
      wss.on("connection", (ws) => this.handleConnection(ws));
    });
  }

  private send(ws: WebSocket, msg: MessageV2): void {
    ws.send(JSON.stringify(msg));
  }

  private handleConnection(ws: WebSocket): void {
    let authed = false;
    let v2 = false;
    const now = new Date().toISOString();
    const nonce = this.opts.nonce ?? randomBytes(32).toString("base64url");
    const challengeId = `ch-${messageId()}`;
    this.send(ws, {
      id: messageId(),
      ts: now,
      type: "auth.challenge",
      challenge_id: challengeId,
      nonce,
      server_time: now,
      challenge_ttl_ms: LIMITS.CHALLENGE_TTL_MS,
    });

    // Optional attack probe: a hello.accepted BEFORE the daemon sends its hello.
    // A hardened client discards it (armForAccept), completing only on the real
    // post-hello accept below.
    if (this.opts.prematureAcceptEpoch !== undefined) {
      this.send(ws, {
        id: messageId(),
        ts: new Date().toISOString(),
        type: "hello.accepted",
        negotiated_version: PROTOCOL_VERSION,
        connection_epoch: this.opts.prematureAcceptEpoch,
        heartbeat_interval_ms: this.opts.heartbeatIntervalMs ?? LIMITS.HEARTBEAT_INTERVAL_MS,
        resume: [],
      });
    }

    ws.on("message", (data: RawData) => {
      // Same single framing choke point as the daemon (plan §5.1): size → schema
      // → direction/phase. `receiver: "server"` flips the allowed directions.
      const res = decodeInbound(toBuffer(data), { receiver: "server", authed, v2 });
      if (!res.ok) {
        log.warn("[mock] inbound rejected", { code: res.code, reason: res.reason });
        return;
      }
      const m = res.msg;
      if (m.type === "hello" && this.opts.stallHandshake) {
        return; // never send hello.accepted → handshake stalls
      }
      if (m.type === "hello") {
        // A second `hello` on an already-authenticated connection is a protocol
        // violation — ignore it (no re-verify, no second hello.accepted, no epoch
        // bump). `validateInbound` permits handshake types post-auth (it only
        // gates NON-handshake types pre-auth), so this phase guard lives here.
        // Cross-connection replay is separately defeated by the per-connection
        // fresh nonce (see verifyHello).
        if (authed) {
          log.warn("[mock] ignoring duplicate hello on an already-authenticated connection");
          return;
        }
        const negotiated = negotiateVersion(m.protocol_version, this.opts.supportedVersions ?? [PROTOCOL_VERSION, PROTOCOL_VERSION_V2]);
        if (!negotiated.ok) {
          log.warn("[mock] hello rejected", { code: "unsupported_version", reason: negotiated.reason });
          this.send(ws, {
            id: messageId(),
            ts: new Date().toISOString(),
            type: "hello.rejected",
            code: "unsupported_version",
            message: negotiated.reason,
          });
          return; // fail closed: no epoch, no accept
        }
        // Track A: verify the Ed25519 possession proof before accepting. No
        // record preserves the non-auth default (accept any signature).
        const record = this.verifyRecord;
        if (record) {
          const res = verifyHello(m, { challengeId, nonce }, record);
          if (!res.ok) {
            log.warn("[mock] hello rejected", { code: res.code, reason: res.message });
            this.send(ws, {
              id: messageId(),
              ts: new Date().toISOString(),
              type: "hello.rejected",
              code: res.code,
              message: res.message,
            });
            this.opts.onHandshakeReject?.(res.code);
            return; // fail closed: no epoch, no accept
          }
        } else {
          // No pairing record → NON-AUTH test mode: accept any signature (the
          // pre-Track-A transport/job scenarios rely on this). Emitted LOUDLY so a
          // test that meant to exercise auth but forgot setVerifyAuth() is visible
          // — not a silent fail-open. The production verifier is the cloud relay,
          // which always verifies; this mock is not a security boundary.
          log.warn("[mock] accepting hello WITHOUT signature verification (non-auth test mode — set verifyAuth to verify)");
        }
        const epoch = this.opts.forceEpoch ?? ++this.epoch;
        const acceptedVersion = this.opts.forceNegotiatedVersion ?? negotiated.version;
        this.send(ws, {
          id: messageId(),
          ts: new Date().toISOString(),
          type: "hello.accepted",
          negotiated_version: acceptedVersion,
          connection_epoch: epoch,
          heartbeat_interval_ms: this.opts.heartbeatIntervalMs ?? LIMITS.HEARTBEAT_INTERVAL_MS,
          resume: this.opts.resumeFor?.(m) ?? [],
        });
        v2 = isProtocolV2(acceptedVersion);
        authed = true;
        this.opts.onAccept?.({ ws, epoch, hello: m });
        if (this.opts.sendSessionListAfterAccept) {
          this.send(ws, {
            id: messageId(),
            ts: new Date().toISOString(),
            type: "session.list.request",
            request_id: "session-list-e2e",
          });
        }
        if (this.opts.sendSessionHistoryAfterAccept) {
          const req = this.opts.sendSessionHistoryAfterAccept;
          this.send(ws, {
            id: messageId(),
            ts: new Date().toISOString(),
            type: "session.history.request",
            request_id: req.request_id,
            handle: req.handle,
            ...(req.cursor === undefined ? {} : { cursor: req.cursor }),
            ...(req.limit === undefined ? {} : { limit: req.limit }),
          });
        }
      } else if (m.type === "heartbeat") {
        this.opts.onHeartbeat?.();
      } else if (m.type === "session.list.response") {
        this.opts.onSessionListResponse?.(m);
      } else if (m.type === "session.history.response") {
        this.opts.onSessionHistoryResponse?.(m);
      } else if (m.type === "session.error") {
        this.opts.onSessionError?.(m);
      } else if (m.type === "session.resume.accept") {
        this.opts.onSessionResumeAccept?.(m);
      } else if (m.type === "session.resume.reject") {
        this.opts.onSessionResumeReject?.(m);
      } else if (m.type === "session.event") {
        this.opts.onSessionEvent?.(m);
      } else if (m.type === "session.turn.result") {
        this.opts.onSessionTurnResult?.(m);
      } else if (m.type === "job.accept") {
        this.opts.onJobAccept?.(m);
      } else if (m.type === "job.reject") {
        this.opts.onJobReject?.(m);
      } else if (m.type === "job.status") {
        this.opts.onJobStatus?.(m);
      } else if (m.type === "agent.draining") {
        this.opts.onDraining?.(m);
      } else if (m.type === "stream.event") {
        this.opts.onStreamEvent?.(m);
        if (this.opts.autoAckStream !== false) {
          this.sendAck(ws, { job_id: m.job_id, attempt_id: m.attempt_id, lease_id: m.lease_id }, m.seq);
        }
      } else if (m.type === "job.result") {
        this.opts.onResult?.(m);
        if (this.opts.autoAckResult !== false) {
          this.send(ws, {
            id: messageId(),
            ts: new Date().toISOString(),
            type: "job.result.ack",
            job_id: m.job_id,
            attempt_id: m.attempt_id,
            lease_id: m.lease_id,
            result_digest: resultDigest(m as unknown as Record<string, unknown>),
          });
        }
      } else if (m.type === "approval.request") {
        this.opts.onApprovalRequest?.(m);
        if (this.opts.autoApprove !== false) {
          this.send(ws, {
            id: messageId(),
            ts: new Date().toISOString(),
            type: "approval.response",
            job_id: m.job_id,
            attempt_id: m.attempt_id,
            lease_id: m.lease_id,
            request_id: m.request_id,
            decision: this.opts.approvalDecision ?? "allow",
            decided_by: "remote_user",
          });
        }
      }
    });

    ws.on("error", () => {});
  }

  /** Send a `job.assign` (all required fields defaulted for tests). */
  assign(ws: WebSocket, spec: AssignSpec): void {
    const now = new Date().toISOString();
    this.send(ws, {
      id: messageId(),
      ts: now,
      type: "job.assign",
      job_id: spec.job_id,
      attempt_id: spec.attempt_id,
      lease_id: spec.lease_id,
      lease_ttl_ms: LIMITS.LEASE_TTL_MS_DEFAULT,
      engine: spec.engine ?? "claude",
      workspace: { repo_root: spec.repo_root ?? "/tmp/repo" },
      prompt: spec.prompt ?? "do the thing",
      sandbox: spec.sandbox ?? "read_only",
      approval_policy: spec.approval_policy ?? "on_write",
      env_policy: { mode: "whitelist", allow: [] },
      network_policy: { mode: "off" },
      limits: { timeout_ms: 600_000, max_output_bytes: 5_000_000 },
      created_at: now,
      assignment_start_timeout_ms: 30_000,
    });
  }

  resumeSession(ws: WebSocket, spec: ResumeSessionSpec): void {
    this.send(ws, {
      id: messageId(),
      ts: new Date().toISOString(),
      type: "session.resume.request",
      request_id: spec.request_id,
      handle: spec.handle,
      message: spec.message,
    });
  }

  sendSessionMessage(ws: WebSocket, spec: ResumeSessionSpec): void {
    this.send(ws, {
      id: messageId(),
      ts: new Date().toISOString(),
      type: "session.message",
      request_id: spec.request_id,
      handle: spec.handle,
      message: spec.message,
    });
  }

  sendSessionCancel(ws: WebSocket, turnId: string): void {
    this.send(ws, {
      id: messageId(),
      ts: new Date().toISOString(),
      type: "session.cancel",
      turn_id: turnId,
    });
  }

  sendSessionAck(ws: WebSocket, turnId: string, ackSeq: number): void {
    this.send(ws, {
      id: messageId(),
      ts: new Date().toISOString(),
      type: "session.ack",
      turn_id: turnId,
      ack_seq: ackSeq,
    });
  }

  /** Send a cumulative `stream.ack` (manual backpressure control). */
  sendAck(ws: WebSocket, ctx: { job_id: string; attempt_id: string; lease_id: string }, ackSeq: number): void {
    this.send(ws, {
      id: messageId(),
      ts: new Date().toISOString(),
      type: "stream.ack",
      job_id: ctx.job_id,
      attempt_id: ctx.attempt_id,
      lease_id: ctx.lease_id,
      ack_seq: ackSeq,
    });
  }

  /** Revoke the lease for an attempt (fences the daemon). */
  revoke(ws: WebSocket, ctx: { job_id: string; attempt_id: string; lease_id: string }, reason = "revoked"): void {
    this.send(ws, {
      id: messageId(),
      ts: new Date().toISOString(),
      type: "lease.revoke",
      job_id: ctx.job_id,
      attempt_id: ctx.attempt_id,
      lease_id: ctx.lease_id,
      reason,
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      const wss = this.wss;
      if (!wss) return resolve();
      for (const c of wss.clients) c.terminate();
      wss.close(() => resolve());
    });
  }
}
