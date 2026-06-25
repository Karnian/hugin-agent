/**
 * Periodic liveness heartbeat. The daemon never self-reassigns on missed
 * heartbeats — reassignment is the server's call via lease expiry (plan §4).
 */

import type { RelayClient } from "./client";
import { heartbeatMsg } from "./outbound";
import { log } from "../log";

/** Start sending heartbeats every `intervalMs`; returns a stop function. */
export function startHeartbeat(client: RelayClient, intervalMs: number): () => void {
  const timer = setInterval(() => {
    try {
      client.send(heartbeatMsg());
    } catch (e) {
      log.warn("heartbeat send failed", { err: String(e) });
    }
  }, intervalMs);
  timer.unref?.();
  return () => clearInterval(timer);
}
