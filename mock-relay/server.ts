/**
 * Minimal mock relay for hugind development/e2e (P1 scope): issues an
 * `auth.challenge`, accepts ANY `hello` (non-auth), assigns a monotonic
 * `connection_epoch`, and exposes an `onAccept` hook so tests can script drops.
 * Job assignment lands in later phases.
 */

import { randomBytes } from "node:crypto";
import { WebSocketServer, type WebSocket, type RawData } from "ws";
import { LIMITS, type Message, PROTOCOL_VERSION } from "../protocol/v1/index";
import { resultDigest } from "../protocol/v1/digest";
import { decodeInbound } from "../src/conn/framing";
import { messageId } from "../src/util/ids";
import { log } from "../src/log";

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
  /** Auto-respond to `approval.request` (default true). Set false to test the
   *  daemon's approval timeout / auto-deny. */
  autoApprove?: boolean;
  /** Decision for the auto-response (default "allow"). */
  approvalDecision?: "allow" | "deny";
}

export interface AssignSpec {
  job_id: string;
  attempt_id: string;
  lease_id: string;
  engine?: "claude" | "codex";
  prompt?: string;
  repo_root?: string;
  sandbox?: "read_only" | "workspace_write" | "full";
}

function toBuffer(data: RawData): Buffer {
  if (Array.isArray(data)) return Buffer.concat(data);
  if (Buffer.isBuffer(data)) return data;
  return Buffer.from(data as ArrayBuffer);
}

export class MockRelay {
  private wss: WebSocketServer | null = null;
  private epoch = 0;
  port = 0;

  constructor(private readonly opts: MockRelayOpts = {}) {}

  start(port = 0): Promise<number> {
    return new Promise((resolve, reject) => {
      const wss = new WebSocketServer({ port, maxPayload: LIMITS.MAX_FRAME_BYTES });
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

  private send(ws: WebSocket, msg: Message): void {
    ws.send(JSON.stringify(msg));
  }

  private handleConnection(ws: WebSocket): void {
    let authed = false;
    const now = new Date().toISOString();
    const nonce = this.opts.nonce ?? randomBytes(32).toString("base64url");
    this.send(ws, {
      id: messageId(),
      ts: now,
      type: "auth.challenge",
      challenge_id: `ch-${messageId()}`,
      nonce,
      server_time: now,
      challenge_ttl_ms: LIMITS.CHALLENGE_TTL_MS,
    });

    ws.on("message", (data: RawData) => {
      // Same single framing choke point as the daemon (plan §5.1): size → schema
      // → direction/phase. `receiver: "server"` flips the allowed directions.
      const res = decodeInbound(toBuffer(data), { receiver: "server", authed });
      if (!res.ok) {
        log.warn("[mock] inbound rejected", { code: res.code, reason: res.reason });
        return;
      }
      const m = res.msg;
      if (m.type === "hello") {
        const epoch = this.opts.forceEpoch ?? ++this.epoch;
        this.send(ws, {
          id: messageId(),
          ts: new Date().toISOString(),
          type: "hello.accepted",
          negotiated_version: PROTOCOL_VERSION,
          connection_epoch: epoch,
          heartbeat_interval_ms: this.opts.heartbeatIntervalMs ?? LIMITS.HEARTBEAT_INTERVAL_MS,
          resume: [],
        });
        authed = true;
        this.opts.onAccept?.({ ws, epoch, hello: m });
      } else if (m.type === "heartbeat") {
        this.opts.onHeartbeat?.();
      } else if (m.type === "job.accept") {
        this.opts.onJobAccept?.(m);
      } else if (m.type === "job.reject") {
        this.opts.onJobReject?.(m);
      } else if (m.type === "stream.event") {
        this.opts.onStreamEvent?.(m);
        if (this.opts.autoAckStream !== false) {
          this.sendAck(ws, { job_id: m.job_id, attempt_id: m.attempt_id, lease_id: m.lease_id }, m.seq);
        }
      } else if (m.type === "job.result") {
        this.opts.onResult?.(m);
        this.send(ws, {
          id: messageId(),
          ts: new Date().toISOString(),
          type: "job.result.ack",
          job_id: m.job_id,
          attempt_id: m.attempt_id,
          lease_id: m.lease_id,
          result_digest: resultDigest(m as unknown as Record<string, unknown>),
        });
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
      approval_policy: "on_write",
      env_policy: { mode: "whitelist", allow: [] },
      network_policy: { mode: "off" },
      limits: { timeout_ms: 600_000, max_output_bytes: 5_000_000 },
      created_at: now,
      assignment_start_timeout_ms: 30_000,
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
