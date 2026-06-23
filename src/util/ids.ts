/**
 * Wire id generation. All are bounded `Id` values (≤256 chars) per the protocol.
 */

import { randomUUID } from "node:crypto";

/** Envelope message id (`{ id }` on every message). */
export function messageId(): string {
  return `m-${randomUUID()}`;
}

/** Agent-side run id reported in `job.accept.agent_run_id`. */
export function agentRunId(): string {
  return `run-${randomUUID()}`;
}
