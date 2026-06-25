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
import { LIMITS, type Message } from "../../protocol/v1/index";
import { decodeInbound, encodeOutbound } from "./framing";
import { log } from "../log";

function toBuffer(data: RawData): Buffer {
  if (Array.isArray(data)) return Buffer.concat(data);
  if (Buffer.isBuffer(data)) return data;
  return Buffer.from(data as ArrayBuffer);
}

interface Waiter {
  pred: (m: Message) => boolean;
  resolve: (m: Message) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class RelayClient {
  private ws: WebSocket | null = null;
  private authed = false;
  private pending: Message[] = [];
  private waiters: Waiter[] = [];
  private messageHandlers = new Set<(m: Message) => void>();
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
        const res = decodeInbound(toBuffer(data), { receiver: "agent", authed: this.authed });
        if (!res.ok) {
          log.warn("inbound rejected", { code: res.code, reason: res.reason });
          return;
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
  private deliver(m: Message): void {
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

  send(msg: Message): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) throw new Error("send on a non-open socket");
    this.ws.send(encodeOutbound(msg));
  }

  /** Register a persistent handler; drains any buffered messages to it in order. */
  onMessage(h: (m: Message) => void): () => void {
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
  waitFor(pred: (m: Message) => boolean, timeoutMs: number): Promise<Message> {
    const idx = this.pending.findIndex(pred);
    if (idx >= 0) {
      const [m] = this.pending.splice(idx, 1);
      return Promise.resolve(m as Message);
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
