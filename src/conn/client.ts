/**
 * WSS client: dial out, decode every inbound frame through the single `framing`
 * choke point, and expose a message pump + `waitFor` (used by the handshake).
 *
 * Inbound messages are BUFFERED until consumed: the relay sends `auth.challenge`
 * immediately on connect, which can arrive before the handshake registers its
 * `waitFor`. `deliver()` queues anything no waiter/handler wants; `waitFor` scans
 * the queue first. This removes the connect→first-message race.
 */

import { WebSocket, type RawData } from "ws";
import { LIMITS, type MessageV2 } from "../../protocol/v1/index";
import { decodeInbound, encodeOutbound } from "./framing";
import { log } from "../log";

function toBuffer(data: RawData): Buffer {
  if (Array.isArray(data)) return Buffer.concat(data);
  if (Buffer.isBuffer(data)) return data;
  return Buffer.from(data as ArrayBuffer);
}

interface Waiter {
  pred: (m: MessageV2) => boolean;
  resolve: (m: MessageV2) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

function isProtocolV2(version: string): boolean {
  const major = Number(version.split(".")[0]);
  return Number.isInteger(major) && major >= 2;
}

export class RelayClient {
  private ws: WebSocket | null = null;
  private authed = false;
  private v2 = false;
  /** Set once the signed `hello` has been sent. A `hello.accepted` that arrives
   *  BEFORE this is a protocol violation (an accept can't precede the possession
   *  proof it accepts) and is discarded — so a premature/replayed accept can't be
   *  consumed by the post-hello `waitFor`. Defense-in-depth atop TLS relay auth. */
  private armedForAccept = false;
  private pending: MessageV2[] = [];
  private waiters: Waiter[] = [];
  private messageHandlers = new Set<(m: MessageV2) => void>();
  private closeHandlers = new Set<(info: { code: number; reason: string }) => void>();

  connect(url: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url, { maxPayload: LIMITS.MAX_FRAME_BYTES });
      this.ws = ws;
      let opened = false;
      ws.on("open", () => {
        opened = true;
        resolve();
      });
      ws.on("message", (data: RawData) => {
        const res = decodeInbound(toBuffer(data), { receiver: "agent", authed: this.authed, v2: this.v2 });
        if (!res.ok) {
          log.warn("inbound rejected", { code: res.code, reason: res.reason });
          return;
        }
        if (res.msg.type === "hello.accepted") {
          // Only valid once we've sent our signed hello (armForAccept). An accept
          // received before that is discarded — it can't accept a possession proof
          // we hadn't sent, and must not be consumable by the post-hello waitFor.
          if (!this.armedForAccept) {
            log.warn("discarding premature hello.accepted (arrived before hello sent)");
            return;
          }
          // The phase flip MUST be synchronous: the relay may send hello.accepted
          // and job.assign in one read, and ws emits both 'message' events in the
          // same tick — the job.assign is decoded before any handshake microtask
          // could set the flag, so flip it here before decoding the next.
          this.setNegotiatedVersion(res.msg.negotiated_version);
          this.authed = true;
        }
        this.deliver(res.msg);
      });
      ws.on("error", (err) => {
        log.error("ws error", { err: String(err) });
        if (!opened) reject(err);
      });
      ws.on("close", (code, reasonBuf) => {
        const reason = reasonBuf?.toString() ?? "";
        log.info("ws closed", { code, reason });
        const err = new Error("socket closed");
        for (const w of this.waiters.splice(0)) {
          clearTimeout(w.timer);
          w.reject(err);
        }
        for (const h of this.closeHandlers) h({ code, reason });
      });
    });
  }

  /** Route a decoded message: one-shot waiters → persistent handlers → buffer. */
  private deliver(m: MessageV2): void {
    for (let i = 0; i < this.waiters.length; i++) {
      const w = this.waiters[i]!;
      if (w.pred(m)) {
        this.waiters.splice(i, 1);
        clearTimeout(w.timer);
        w.resolve(m);
        return;
      }
    }
    if (this.messageHandlers.size > 0) {
      for (const h of this.messageHandlers) h(m);
      return;
    }
    this.pending.push(m);
  }

  setAuthed(b: boolean): void {
    this.authed = b;
  }

  setNegotiatedVersion(version: string): void {
    this.v2 = isProtocolV2(version);
  }

  /** Arm the client to accept a `hello.accepted`. The handshake calls this right
   *  after sending the signed `hello`: any accept received earlier is discarded. */
  armForAccept(): void {
    this.armedForAccept = true;
  }

  send(msg: MessageV2): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) throw new Error("send on a non-open socket");
    this.ws.send(encodeOutbound(msg));
  }

  /** Register a persistent handler; drains any buffered messages to it in order. */
  onMessage(h: (m: MessageV2) => void): () => void {
    this.messageHandlers.add(h);
    if (this.pending.length > 0) {
      const buf = this.pending;
      this.pending = [];
      for (const m of buf) h(m);
    }
    return () => this.messageHandlers.delete(h);
  }

  onClose(h: (info: { code: number; reason: string }) => void): () => void {
    this.closeHandlers.add(h);
    return () => this.closeHandlers.delete(h);
  }

  /** Resolve with the next message matching `pred` (checking the buffer first);
   *  reject on timeout or socket close. Drives the handshake steps. */
  waitFor(pred: (m: MessageV2) => boolean, timeoutMs: number): Promise<MessageV2> {
    const idx = this.pending.findIndex(pred);
    if (idx >= 0) {
      const [m] = this.pending.splice(idx, 1);
      return Promise.resolve(m as MessageV2);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const i = this.waiters.findIndex((w) => w.timer === timer);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(new Error("waitFor timeout"));
      }, timeoutMs);
      timer.unref?.();
      this.waiters.push({ pred, resolve, reject, timer });
    });
  }

  close(code = 1000): void {
    this.ws?.close(code);
  }
}
