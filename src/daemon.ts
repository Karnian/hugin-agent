/**
 * hugind lifecycle: dial out → handshake → heartbeat + job dispatch → (on close)
 * reconnect with backoff. P2a adds the job path (registry/eventlog/engine) behind
 * the post-handshake message pump.
 */

import { join } from "node:path";
import type { Config } from "./config";
import type { Message } from "../protocol/v1/index";
import type { Engine } from "./engine/types";
import { RelayClient } from "./conn/client";
import { performHandshake, type Signer } from "./conn/handshake";
import { startHeartbeat } from "./conn/heartbeat";
import { backoffDelay, sleep } from "./conn/reconnect";
import { EventLog } from "./store/eventlog";
import { JobRegistry } from "./jobs/registry";
import { JobManager } from "./jobs/manager";
import { log } from "./log";

export class Daemon {
  private running = false;
  private lastEpoch = -1;
  private activeClient: RelayClient | null = null;
  private readonly abort = new AbortController();
  private readonly store: EventLog;

  constructor(
    private readonly config: Config,
    private readonly signer: Signer,
    private readonly engine: Engine,
  ) {
    this.store = new EventLog(config.dbPath ?? join(config.stateDir, "eventlog.db"));
  }

  /** Monotonic `connection_epoch` gate (plan §5.1). */
  acceptEpoch(epoch: number): boolean {
    if (epoch <= this.lastEpoch) return false;
    this.lastEpoch = epoch;
    return true;
  }

  /** e2e/introspection: durable pending results + tracked attempts. */
  pendingResultCount(): number {
    return this.store.pendingResults().length;
  }
  activeAttemptCount(): number {
    return this.store.activeAttempts().length;
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
      if (established) attempt = 0;
      if (!this.running) break;
      const delay = backoffDelay(attempt, 500, 10_000);
      attempt++;
      log.info("reconnecting", { delayMs: delay, attempt });
      await sleep(delay, this.abort.signal);
    }
    this.store.close();
    log.info("daemon stopped");
  }

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
      log.info("handshake ok", { negotiatedVersion: hs.negotiatedVersion, connectionEpoch: hs.connectionEpoch });

      // Post-handshake job pump. Registry is per-session (P4 adds cross-session
      // resume from the durable store); the event log is daemon-durable.
      const registry = new JobRegistry(this.config.maxConcurrent);
      const safeSend = (m: Message) => {
        try {
          client.send(m);
        } catch (e) {
          log.warn("send failed", { err: String(e) });
        }
      };
      const manager = new JobManager(registry, this.store, this.engine, safeSend, {
        events: this.config.maxUnackedEventsPerAttempt,
        bytes: this.config.maxUnackedBytesPerAttempt,
        conn: this.config.maxUnackedBytesPerConn,
      });
      client.onMessage((m) => {
        switch (m.type) {
          case "job.assign":
            manager.handleAssign(m);
            break;
          case "stream.ack":
            manager.handleStreamAck(m);
            break;
          case "job.result.ack":
            manager.handleResultAck(m);
            break;
          case "job.cancel":
            manager.handleCancel(m);
            break;
          case "lease.revoke":
            manager.handleRevoke(m);
            break;
          default:
            break; // lease.granted → P4 (rotation); others ignored
        }
      });

      const stopHeartbeat = startHeartbeat(client, hs.heartbeatIntervalMs);
      try {
        await closed;
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
