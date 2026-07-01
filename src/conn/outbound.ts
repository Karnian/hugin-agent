/**
 * Outbound message builders. Every message gets the shared envelope (`id`, `ts`)
 * stamped here. (Attempt-scoped `lease_id` + `seq` stamping lands in P2 with the
 * job path.)
 */

import type { Message } from "../../protocol/v1/index";
import { messageId } from "../util/ids";

export function envelope(): { id: string; ts: string } {
  return { id: messageId(), ts: new Date().toISOString() };
}

/** Liveness heartbeat (agent→server). P1: bare; `active_attempts`/`capacity`
 *  arrive with the job path (P2). */
export function heartbeatMsg(): Message {
  return { ...envelope(), type: "heartbeat" };
}

// ---- Attempt-scoped builders: every one stamps `lease_id` via `ctx` (A3) ----

export interface AttemptCtx {
  job_id: string;
  attempt_id: string;
  lease_id: string;
}

export function jobAccept(ctx: AttemptCtx, agentRunId: string): Message {
  return { ...envelope(), type: "job.accept", ...ctx, agent_run_id: agentRunId };
}

export type RejectCode =
  | "root_not_allowlisted"
  | "engine_unavailable"
  | "busy"
  | "stale_lease"
  | "bad_request"
  | "policy_violation";

export function jobReject(ctx: AttemptCtx, code: RejectCode, message: string): Message {
  return { ...envelope(), type: "job.reject", ...ctx, code, message };
}

export type JobStatusValue =
  | "accepted"
  | "starting"
  | "running"
  | "cancelling"
  | "cancelled"
  | "completed"
  | "failed";

export function jobStatusMsg(ctx: AttemptCtx, status: JobStatusValue): Message {
  return { ...envelope(), type: "job.status", ...ctx, status };
}

export function streamEvent(
  ctx: AttemptCtx,
  seq: number,
  eventId: string,
  event: { kind: string; [k: string]: unknown },
): Message {
  return { ...envelope(), type: "stream.event", ...ctx, seq, event_id: eventId, event };
}

export type FinalStatusValue = "success" | "error" | "cancelled" | "timeout";

export interface JobResultFields {
  final_status: FinalStatusValue;
  exit_code?: number;
  signal?: string;
  error_kind?: string;
  duration_ms: number;
  stats: { event_count: number; bytes: number };
  head_sha?: string;
}

export function jobResultMsg(ctx: AttemptCtx, f: JobResultFields): Message {
  return {
    ...envelope(),
    type: "job.result",
    ...ctx,
    final_status: f.final_status,
    exit_code: f.exit_code,
    signal: f.signal,
    error_kind: f.error_kind,
    duration_ms: f.duration_ms,
    stats: f.stats,
    head_sha: f.head_sha,
  };
}
