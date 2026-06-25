/**
 * hugind lifecycle: dial out → handshake → heartbeat → (on close) reconnect with
 * backoff. P1 is transport + non-auth handshake; job execution is P2.
 */

import type { Config } from "./config";
import { RelayClient } from "./conn/client";
import { performHandshake, type Signer } from "./conn/handshake";
import { startHeartbeat } from "./conn/heartbeat";
import { backoffDelay, sleep } from "./conn/reconnect";
import { log } from "./log";

export class Daemon {
  private running = false;
  private lastEpoch = -1;
  private activeClient: RelayClient | null = null;
  private readonly abort = new AbortController();

  constructor(
    private readonly config: Config,
    private readonly signer: Signer,
  ) {}

  /** Monotonic `connection_epoch` gate (plan §5.1): accept only a strictly
   *  increasing epoch; an older/equal one is a stale session and is rejected. */
  acceptEpoch(epoch: number): boolean {
    if (epoch <= this.lastEpoch) return false;
    this.lastEpoch = epoch;
    return true;
  }

  async start(): Promise<void> {
    this.running = true;
    let attempt = 0;
    while (this.running) {
      let established = false;
      try {
        established = await this.runSession();
      } catch (e) {
        log.warn("session error", { err: String(e) });
      }
      if (established) attempt = 0; // a real session resets backoff
      if (!this.running) break;
      const delay = backoffDelay(attempt, 500, 10_000);
      attempt++;
      log.info("reconnecting", { delayMs: delay, attempt });
      await sleep(delay, this.abort.signal);
    }
    log.info("daemon stopped");
  }

  /** One connection lifecycle; resolves when the connection closes. Returns
   *  whether the handshake established (used to reset reconnect backoff). */
  private async runSession(): Promise<boolean> {
    const client = new RelayClient();
    this.activeClient = client;
    let established = false;
    const closed = new Promise<void>((resolve) => {
      client.onClose(() => resolve());
    });
    try {
      await client.connect(this.config.serverUrl);
      const hs = await performHandshake(client, this.config, this.signer);
      if (!this.acceptEpoch(hs.connectionEpoch)) {
        log.warn("non-monotonic connection_epoch — closing", {
          epoch: hs.connectionEpoch,
          lastEpoch: this.lastEpoch,
        });
        client.close(1008);
        return false;
      }
      established = true;
      log.info("handshake ok", {
        negotiatedVersion: hs.negotiatedVersion,
        connectionEpoch: hs.connectionEpoch,
      });
      const stopHeartbeat = startHeartbeat(client, hs.heartbeatIntervalMs);
      try {
        await closed; // run until the connection drops
      } finally {
        stopHeartbeat();
      }
    } finally {
      client.close();
      if (this.activeClient === client) this.activeClient = null;
    }
    return established;
  }

  stop(): void {
    this.running = false;
    this.abort.abort();
    this.activeClient?.close();
  }
}
