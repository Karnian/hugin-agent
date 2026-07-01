/**
 * Job orchestration (P2a): dispatch `job.assign`/`stream.ack`/`job.result.ack`/
 * `job.cancel`, run the engine, stream events (persist-before-send + cumulative
 * ack GC + backpressure), and produce a digest-acked terminal result.
 *
 * Idempotent by `attempt_id`: a duplicate `job.assign` re-confirms, never spawns
 * a second run. Lease is validated on every inbound attempt-scoped message.
 */

import type { Message } from "../../protocol/v1/index";
import { resultDigest } from "../../protocol/v1/digest";
import type { Engine, EngineEvent, EngineOutcome } from "../engine/types";
import type { EventLog } from "../store/eventlog";
import { JobRegistry, type JobState } from "./registry";
import { leaseMatches } from "./lease";
import {
  type AttemptCtx,
  jobAccept,
  jobReject,
  jobResultMsg,
  jobStatusMsg,
  streamEvent,
} from "../conn/outbound";
import { agentRunId } from "../util/ids";
import { log } from "../log";

type JobAssign = Extract<Message, { type: "job.assign" }>;
type StreamAck = Extract<Message, { type: "stream.ack" }>;
type JobResultAck = Extract<Message, { type: "job.result.ack" }>;
type JobCancel = Extract<Message, { type: "job.cancel" }>;
type LeaseRevoke = Extract<Message, { type: "lease.revoke" }>;

export interface Caps {
  events: number;
  bytes: number;
  conn: number;
}

export class JobManager {
  private readonly startedAt = new Map<string, number>();

  constructor(
    private readonly registry: JobRegistry,
    private readonly store: EventLog,
    private readonly engine: Engine,
    private readonly send: (m: Message) => void,
    private readonly caps: Caps,
    private readonly now: () => number = () => Date.now(),
  ) {}

  handleAssign(msg: JobAssign): void {
    const ctx: AttemptCtx = { job_id: msg.job_id, attempt_id: msg.attempt_id, lease_id: msg.lease_id };

    // Idempotency (at-least-once delivery) across BOTH the in-memory registry
    // (same connection) and the DURABLE store (survives reconnect — the registry
    // is per-session, the store is not). A duplicate re-confirms and MUST NOT
    // spawn a second engine/worktree. A duplicate carrying a DIFFERENT lease than
    // the one we accepted is fenced (`stale_lease`).
    const existing = this.registry.get(msg.attempt_id) ?? this.store.getAttempt(msg.attempt_id);
    if (existing) {
      if (!leaseMatches(existing.lease_id, msg.lease_id)) {
        log.warn("duplicate job.assign with mismatched lease — fencing", { attempt_id: msg.attempt_id });
        this.send(jobReject(ctx, "stale_lease", "attempt already accepted under a different lease"));
        return;
      }
      log.info("duplicate job.assign — re-confirming (no re-spawn)", { attempt_id: msg.attempt_id });
      this.send(jobAccept({ ...ctx, lease_id: existing.lease_id }, existing.agent_run_id));
      return;
    }

    if (this.registry.atCapacity()) {
      this.send(jobReject(ctx, "busy", "agent at capacity"));
      return;
    }

    const runId = agentRunId();
    this.store.createAttempt({
      attempt_id: msg.attempt_id,
      job_id: msg.job_id,
      lease_id: msg.lease_id,
      agent_run_id: runId,
      status: "accepted",
      created_at: new Date(this.now()).toISOString(),
    });
    const state: JobState = {
      job_id: msg.job_id,
      attempt_id: msg.attempt_id,
      lease_id: msg.lease_id,
      agent_run_id: runId,
      status: "accepted",
      seq: 0,
      totalBytes: 0,
      run: null,
      paused: false,
      fenced: false,
    };
    this.registry.add(state);
    this.send(jobAccept(ctx, runId));

    this.startedAt.set(msg.attempt_id, this.now());
    state.status = "running";
    this.store.setAttemptStatus(msg.attempt_id, "running");
    this.send(jobStatusMsg(ctx, "running"));

    const run = this.engine.run({
      engine: msg.engine,
      prompt: msg.prompt,
      cwd: msg.workspace.cwd ?? msg.workspace.repo_root,
    });
    state.run = run;
    run.onEvent((ev) => this.onEvent(state, ev));
    run.onDone((outcome) => this.onDone(state, outcome));
  }

  private onEvent(state: JobState, ev: EngineEvent): void {
    if (state.fenced) return; // revoked lease — never persist or emit on it
    const seq = ++state.seq;
    const eventId = `${state.attempt_id}-${seq}`;
    const msg = streamEvent(
      { job_id: state.job_id, attempt_id: state.attempt_id, lease_id: state.lease_id },
      seq,
      eventId,
      ev,
    );
    const payload = JSON.stringify(msg);
    const bytes = Buffer.byteLength(payload, "utf8");
    state.totalBytes += bytes;
    this.store.appendEvent(state.attempt_id, seq, eventId, bytes, payload); // persist BEFORE send
    this.send(msg);
    if (this.overCap(state)) {
      state.paused = true;
      state.run?.pause();
      log.debug("backpressure pause", { attempt_id: state.attempt_id, seq });
    }
  }

  private onDone(state: JobState, outcome: EngineOutcome): void {
    const started = this.startedAt.get(state.attempt_id) ?? this.now();
    // Identity-gate cleanup. Once cancellation is async (real engine, P2b/P3), a
    // fenced attempt can be REPLACED by a fresh re-assign under the same
    // attempt_id before this (now stale) callback fires. Only clean up if WE are
    // still the current registered run — never delete the replacement by key.
    const current = this.registry.get(state.attempt_id) === state;
    if (current) this.startedAt.delete(state.attempt_id);
    state.run = null;

    // Fenced (lease revoked/lost): emit NOTHING on the revoked lease; drop state.
    if (state.fenced) {
      if (current) this.registry.remove(state.attempt_id);
      return;
    }

    const ctx: AttemptCtx = { job_id: state.job_id, attempt_id: state.attempt_id, lease_id: state.lease_id };
    const final_status =
      outcome.status === "success" ? "success" : outcome.status === "cancelled" ? "cancelled" : "error";
    const result = jobResultMsg(ctx, {
      final_status,
      exit_code: "exitCode" in outcome ? outcome.exitCode : undefined,
      error_kind: outcome.status === "error" ? outcome.errorKind : undefined,
      duration_ms: this.now() - started,
      stats: { event_count: state.seq, bytes: state.totalBytes },
    });
    const digest = resultDigest(result as unknown as Record<string, unknown>);
    const payload = JSON.stringify(result);
    this.store.saveResult({
      attempt_id: state.attempt_id,
      job_id: state.job_id,
      lease_id: state.lease_id,
      final_status,
      result_digest: digest,
      result_size: Buffer.byteLength(payload, "utf8"),
      payload,
      last_emitted_seq: state.seq,
    });
    state.status = final_status === "success" ? "completed" : final_status === "cancelled" ? "cancelled" : "failed";
    this.store.setAttemptStatus(state.attempt_id, state.status);
    this.send(result);
    // Terminal: free the live-run slot (capacity). The durable pending result is
    // retained until job.result.ack digest-matches and GCs it. Identity-gated so
    // a stale callback can't evict a same-id replacement.
    if (current) this.registry.remove(state.attempt_id);
  }

  handleStreamAck(msg: StreamAck): void {
    const lease = this.leaseFor(msg.attempt_id);
    if (lease === undefined) return; // unknown attempt
    if (!leaseMatches(lease, msg.lease_id)) {
      log.warn("stale lease on stream.ack", { attempt_id: msg.attempt_id });
      return;
    }
    // GC even if the registry entry is already gone (a late ack after terminal),
    // so durable events don't stay pinned against the per-connection byte cap.
    this.store.ackEvents(msg.attempt_id, msg.ack_seq);
    const state = this.registry.get(msg.attempt_id);
    if (state?.paused && !this.overCap(state)) {
      state.paused = false;
      state.run?.resume();
      log.debug("backpressure resume", { attempt_id: msg.attempt_id });
    }
  }

  handleResultAck(msg: JobResultAck): void {
    // Lease-check via the store too: `onDone` removes the registry entry at
    // terminal, so in the normal flow the registry always misses here — but the
    // pending result's lease still lives on the durable AttemptRow. A digest is
    // NOT a capability token, so it must not authorize GC on its own.
    const lease = this.leaseFor(msg.attempt_id);
    if (lease === undefined) {
      log.warn("job.result.ack for unknown attempt", { attempt_id: msg.attempt_id });
      return;
    }
    if (!leaseMatches(lease, msg.lease_id)) {
      log.warn("stale lease on job.result.ack", { attempt_id: msg.attempt_id });
      return;
    }
    if (this.store.ackResult(msg.attempt_id, msg.result_digest)) {
      this.store.deleteAttempt(msg.attempt_id);
      this.registry.remove(msg.attempt_id);
      this.startedAt.delete(msg.attempt_id);
      log.info("result acked + GC'd", { attempt_id: msg.attempt_id });
    } else {
      log.warn("job.result.ack digest mismatch — keeping pending", { attempt_id: msg.attempt_id });
    }
  }

  /** Current lease for an attempt: the live registry first, then the durable
   *  store (which retains it post-terminal until result.ack GCs the attempt). */
  private leaseFor(attemptId: string): string | undefined {
    return this.registry.get(attemptId)?.lease_id ?? this.store.getAttempt(attemptId)?.lease_id;
  }

  handleCancel(msg: JobCancel): void {
    const state = this.registry.get(msg.attempt_id);
    if (!state) return;
    if (!leaseMatches(state.lease_id, msg.lease_id)) return;
    state.status = "cancelling";
    this.store.setAttemptStatus(msg.attempt_id, "cancelling");
    this.send(
      jobStatusMsg(
        { job_id: state.job_id, attempt_id: state.attempt_id, lease_id: state.lease_id },
        "cancelling",
      ),
    );
    state.run?.cancel(msg.grace_ms); // → onDone({status:"cancelled"}) → terminal result
  }

  /** Lease revoked → LOCAL FENCE: stop the engine and drop the attempt WITHOUT
   *  emitting anything on the revoked lease (the server owns the attempt now). */
  handleRevoke(msg: LeaseRevoke): void {
    const state = this.registry.get(msg.attempt_id);
    if (!state) return;
    if (!leaseMatches(state.lease_id, msg.lease_id)) return; // not our current lease
    log.warn("lease revoked — local fence", { attempt_id: msg.attempt_id });
    state.fenced = true;
    state.run?.cancel(0); // → onDone (fenced): no emit, registry.remove
    this.registry.remove(msg.attempt_id); // ensure removal even if run was already null
    this.startedAt.delete(msg.attempt_id);
    // Durable drop so a fresh re-assignment (new lease) starts clean rather than
    // being fenced against the revoked lease.
    this.store.deleteAttempt(msg.attempt_id);
  }

  private overCap(state: JobState): boolean {
    return (
      this.store.unackedEvents(state.attempt_id) >= this.caps.events ||
      this.store.unackedBytes(state.attempt_id) >= this.caps.bytes ||
      this.store.connUnackedBytes() >= this.caps.conn
    );
  }
}
