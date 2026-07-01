/**
 * In-memory live-job registry, keyed by `attempt_id` (idempotency + capacity).
 * The durable record is in the SQLite event log; this is the running-process
 * state (engine handle, current seq, backpressure flag).
 */

import type { EngineRun } from "../engine/types";

export type JobStatus =
  | "accepted"
  | "starting"
  | "running"
  | "cancelling"
  | "cancelled"
  | "completed"
  | "failed";

export interface JobState {
  job_id: string;
  attempt_id: string;
  lease_id: string;
  agent_run_id: string;
  status: JobStatus;
  /** Last emitted stream `seq` (monotonic from 1). */
  seq: number;
  /** Total output bytes emitted (for `job.result.stats.bytes`). */
  totalBytes: number;
  run: EngineRun | null;
  paused: boolean;
  /** Set on lease revoke/loss — suppresses the terminal result (local fence). */
  fenced: boolean;
  /** In-flight approvals: request_id → auto-deny timer (approval_timeout). */
  approvalTimers: Map<string, ReturnType<typeof setTimeout>>;
  /** Previous lease during a `lease.granted` rotation — accepted on inbound until
   *  `leaseOverlapUntil` to avoid false-nacking in-flight messages. */
  prevLease?: string;
  leaseOverlapUntil?: number;
}

export class JobRegistry {
  private readonly jobs = new Map<string, JobState>();

  constructor(private readonly maxConcurrent: number) {}

  get(attemptId: string): JobState | undefined {
    return this.jobs.get(attemptId);
  }

  has(attemptId: string): boolean {
    return this.jobs.has(attemptId);
  }

  add(state: JobState): void {
    this.jobs.set(state.attempt_id, state);
  }

  remove(attemptId: string): void {
    this.jobs.delete(attemptId);
  }

  size(): number {
    return this.jobs.size;
  }

  atCapacity(): boolean {
    return this.jobs.size >= this.maxConcurrent;
  }

  all(): JobState[] {
    return [...this.jobs.values()];
  }
}
