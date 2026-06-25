/**
 * Minimal mock relay for hugind development/e2e (P1 scope): issues an
 * `auth.challenge`, accepts ANY `hello` (non-auth), assigns a monotonic
 * `connection_epoch`, and exposes an `onAccept` hook so tests can script drops.
 * Job assignment lands in later phases.
 */

import { randomBytes } from "node:crypto";
import { WebSocketServer, type WebSocket, type RawData } from "ws";
import { LIMITS, type Message, PROTOCOL_VERSION } from "../protocol/v1/index";
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
      }
    });

    ws.on("error", () => {});
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
