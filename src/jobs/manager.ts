/**
 * Job orchestration (P2a): dispatch `job.assign`/`stream.ack`/`job.result.ack`/
 * `job.cancel`, run the engine, stream events (persist-before-send + cumulative
 * ack GC + backpressure), and produce a digest-acked terminal result.
 *
 * Idempotent by `attempt_id`: a duplicate `job.assign` re-confirms, never spawns
 * a second run. Lease is validated on every inbound attempt-scoped message.
 */

import { LIMITS, type Message } from "../../protocol/v1/index";
import { resultDigest } from "../../protocol/v1/digest";
import type { ApprovalRequest, Engine, EngineEvent, EngineOutcome, EngineSpec } from "../engine/types";
import type { EventLog } from "../store/eventlog";
import { JobRegistry, type JobState } from "./registry";
import { leaseMatches } from "./lease";
import {
  type AttemptCtx,
  approvalRequestMsg,
  envelope,
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
type ApprovalResponse = Extract<Message, { type: "approval.response" }>;
type LeaseGranted = Extract<Message, { type: "lease.granted" }>;
type ResumeDirectives = Extract<Message, { type: "hello.accepted" }>["resume"];

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
    /** Whether the approval gate is usable (startup isolation self-check). When
     *  false, the daemon fails closed on write/exec jobs. */
    private readonly gateAvailable = true,
    private readonly approvalTimeoutMs: number = LIMITS.APPROVAL_TIMEOUT_MS_DEFAULT,
    private readonly now: () => number = () => Date.now(),
  ) {}

  handleAssign(msg: JobAssign): void {
    const ctx: AttemptCtx = { job_id: msg.job_id, attempt_id: msg.attempt_id, lease_id: msg.lease_id };
    // Log every assign at receipt so a rejected job is diagnosable from the daemon
    // side — the reject frames below go to the server, not the local terminal.
    log.info("job.assign received", {
      attempt_id: msg.attempt_id,
      job_id: msg.job_id,
      engine: msg.engine,
      sandbox: msg.sandbox,
      approval_policy: msg.approval_policy,
      // The job's DECLARED workspace root — the operator needs this to configure
      // HUGIND_PROJECT_ROOTS (or spot a path the C2 sent that isn't on this host).
      repo_root: msg.workspace.repo_root,
    });

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
      log.warn("job.assign rejected — at capacity", { attempt_id: msg.attempt_id });
      this.send(jobReject(ctx, "busy", "agent at capacity"));
      return;
    }

    const spec: EngineSpec = {
      engine: msg.engine,
      prompt: msg.prompt,
      attemptId: msg.attempt_id,
      repoRoot: msg.workspace.repo_root,
      baseSha: msg.workspace.base_sha,
      cwd: msg.workspace.cwd,
      sandbox: msg.sandbox, // ClaudeEngine ENFORCES read_only (disallow write/exec)
    };
    // Pre-accept workspace/policy validation (allowlist, git, path safety) → reject
    // BEFORE accept/spawn (plan §5.10). The fake engine omits validate → skipped.
    const rej = this.engine.validate?.(spec);
    if (rej) {
      // Log only the code — rej.message (workspace validation) can interpolate
      // local filesystem paths (repo_root/cwd), which we keep OUT of the local
      // log. The full message still travels to the server in the reject frame.
      log.warn("job.assign rejected by engine.validate", {
        attempt_id: msg.attempt_id,
        code: rej.code,
      });
      this.send(jobReject(ctx, rej.code, rej.message));
      return;
    }

    // Fail closed: a job needs the approval gate if it can write/execute
    // (sandbox beyond read_only) OR declares an approval policy that expects
    // gating (approval_policy !== "never") — the protocol treats sandbox +
    // approval_policy together as the local-maximum policy. Without a usable
    // gate, reject it. Only a read_only + never job is safe ungated.
    if (!this.gateAvailable && (msg.sandbox !== "read_only" || msg.approval_policy !== "never")) {
      log.warn("job.assign rejected — approval gate unavailable (fail closed)", {
        attempt_id: msg.attempt_id,
        sandbox: msg.sandbox,
        approval_policy: msg.approval_policy,
        hint: "gate needs env-auth (ANTHROPIC_API_KEY/CLAUDE_CODE_OAUTH_TOKEN) or a clean login; read_only+never runs ungated",
      });
      this.send(jobReject(ctx, "policy_violation", "approval gate unavailable — daemon fails closed on gated jobs"));
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
      approvalTimers: new Map(),
    };
    this.registry.add(state);
    this.send(jobAccept(ctx, runId));

    this.startedAt.set(msg.attempt_id, this.now());
    state.status = "running";
    this.store.setAttemptStatus(msg.attempt_id, "running");
    this.send(jobStatusMsg(ctx, "running"));

    const run = this.engine.run(spec);
    state.run = run;
    run.onEvent((ev) => this.onEvent(state, ev));
    run.onDone((outcome) => this.onDone(state, outcome));
    run.onApprovalRequest?.((req) => this.onApprovalRequest(state, req));
  }

  /** Engine needs approval for a tool → forward as approval.request; auto-deny on
   *  timeout (late responses are then ignored). */
  private onApprovalRequest(state: JobState, req: ApprovalRequest): void {
    if (state.fenced) return; // revoked/abandoned — do not emit or arm a timer
    const ctx: AttemptCtx = { job_id: state.job_id, attempt_id: state.attempt_id, lease_id: state.lease_id };
    this.send(
      approvalRequestMsg(ctx, {
        requestId: req.requestId,
        toolName: req.toolName,
        inputSummary: typeof req.input === "string" ? req.input : JSON.stringify(req.input ?? {}),
        risk: req.risk ?? "medium",
        approvalTimeoutMs: this.approvalTimeoutMs,
      }),
    );
    const timer = setTimeout(() => {
      state.approvalTimers.delete(req.requestId);
      log.warn("approval timed out — auto-deny", { attempt_id: state.attempt_id, request_id: req.requestId });
      state.run?.resolveApproval?.(req.requestId, "deny", "approval timeout");
    }, this.approvalTimeoutMs);
    timer.unref?.();
    state.approvalTimers.set(req.requestId, timer);
  }

  handleApprovalResponse(msg: ApprovalResponse): void {
    const state = this.registry.get(msg.attempt_id);
    if (!state) return;
    if (!this.leaseOk(state, msg.attempt_id, msg.lease_id)) {
      log.warn("stale lease on approval.response", { attempt_id: msg.attempt_id });
      return;
    }
    const timer = state.approvalTimers.get(msg.request_id);
    if (!timer) {
      log.warn("approval.response for an unknown/expired request — ignored", { request_id: msg.request_id });
      return;
    }
    clearTimeout(timer);
    state.approvalTimers.delete(msg.request_id);
    state.run?.resolveApproval?.(msg.request_id, msg.decision, msg.reason);
  }

  private clearApprovals(state: JobState): void {
    for (const t of state.approvalTimers.values()) clearTimeout(t);
    state.approvalTimers.clear();
  }

  /** Apply `hello.accepted.resume[]` from the DURABLE store (engine-independent —
   *  survives a connection drop or process restart). Resends stored event/result
   *  payloads (dedup'd server-side by seq/event_id/digest). */
  applyResume(directives: ResumeDirectives): void {
    for (const d of directives) {
      switch (d.action) {
        case "resume_from": {
          // Adopt the directive's lease as current (durable + live) so re-stamped
          // resends AND subsequent live events/inbound acks all agree; a stored
          // payload carries the lease it was first sent under (stale post-rotation).
          if (d.lease_id) this.adoptLease(d.attempt_id, d.lease_id);
          const payloads = this.store.eventsAfter(d.attempt_id, d.resume_after_seq ?? 0);
          for (const p of payloads) {
            const msg = JSON.parse(p) as Record<string, unknown>;
            if (d.lease_id) msg.lease_id = d.lease_id;
            Object.assign(msg, envelope());
            this.send(msg as unknown as Message);
          }
          log.info("resume_from — resent events (re-stamped lease)", { attempt_id: d.attempt_id, count: payloads.length });
          break;
        }
        case "resend_result": {
          if (d.lease_id) this.adoptLease(d.attempt_id, d.lease_id);
          const r = this.store.getResult(d.attempt_id);
          if (r) {
            const msg = JSON.parse(r.payload) as Record<string, unknown>;
            const lease = d.lease_id ?? (msg.lease_id as string);
            msg.lease_id = lease;
            Object.assign(msg, envelope());
            const payload = JSON.stringify(msg);
            // The lease is in the digest (only id/ts are stripped), so persist the
            // re-stamped lease + digest so the eventual result.ack matches on GC.
            const digest = resultDigest(msg);
            this.store.updateResult(d.attempt_id, lease, digest, payload);
            this.send(msg as unknown as Message);
            log.info("resend_result — resent result (re-stamped lease)", { attempt_id: d.attempt_id });
          }
          break;
        }
        case "ack_pending": {
          this.store.deleteResult(d.attempt_id);
          this.store.deleteAttempt(d.attempt_id);
          this.registry.remove(d.attempt_id);
          log.info("ack_pending — GC'd", { attempt_id: d.attempt_id });
          break;
        }
        case "abandon": {
          // Fence like revoke: suppress any late engine output before GC (a live
          // run now survives on the daemon-level registry).
          const state = this.registry.get(d.attempt_id);
          if (state) {
            state.fenced = true;
            this.clearApprovals(state);
            state.run?.cancel(0);
            this.registry.remove(d.attempt_id);
            this.startedAt.delete(d.attempt_id);
          }
          this.store.deleteResult(d.attempt_id);
          this.store.deleteAttempt(d.attempt_id);
          log.info("abandon — fenced + dropped attempt", { attempt_id: d.attempt_id });
          break;
        }
      }
    }
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
    this.clearApprovals(state);

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
    const state = this.registry.get(msg.attempt_id);
    if (!this.leaseOk(state, msg.attempt_id, msg.lease_id)) return; // unknown or stale
    // GC even if the registry entry is already gone (a late ack after terminal),
    // so durable events don't stay pinned against the per-connection byte cap.
    this.store.ackEvents(msg.attempt_id, msg.ack_seq);
    if (state?.paused && !this.overCap(state)) {
      state.paused = false;
      state.run?.resume();
      log.debug("backpressure resume", { attempt_id: msg.attempt_id });
    }
  }

  handleResultAck(msg: JobResultAck): void {
    // Lease-check via the store too: `onDone` removes the registry entry at
    // terminal, so in the normal flow the registry misses here — but the pending
    // result's lease still lives on the durable AttemptRow. A digest is NOT a
    // capability token, so it must not authorize GC on its own.
    const state = this.registry.get(msg.attempt_id);
    if (!this.leaseOk(state, msg.attempt_id, msg.lease_id)) {
      log.warn("stale/unknown lease on job.result.ack", { attempt_id: msg.attempt_id });
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

  /** Lease acceptance for an inbound attempt-scoped message. Accepts the current
   *  lease, OR the previous lease during a `lease.granted` rotation overlap. Post
   *  terminal (registry miss) falls back to the durable attempt's lease. */
  private leaseOk(state: JobState | undefined, attemptId: string, incoming: string): boolean {
    if (state) {
      if (incoming === state.lease_id) return true;
      return (
        state.prevLease !== undefined &&
        incoming === state.prevLease &&
        this.now() < (state.leaseOverlapUntil ?? 0)
      );
    }
    return this.store.getAttempt(attemptId)?.lease_id === incoming;
  }

  /** Adopt a lease (from `lease.granted` or a resume directive) as the current
   *  generation — durable (attempts row) AND live (JobState) — so both outbound
   *  and inbound `leaseOk` use it; the prior lease stays valid for the overlap. */
  private adoptLease(attemptId: string, leaseId: string): void {
    this.store.setAttemptLease(attemptId, leaseId);
    const st = this.registry.get(attemptId);
    if (st && st.lease_id !== leaseId) {
      st.prevLease = st.lease_id;
      st.lease_id = leaseId;
      st.leaseOverlapUntil = this.now() + LIMITS.LEASE_ROTATION_OVERLAP_MS;
    }
  }

  /** `lease.granted` rotation: adopt the new lease immediately (outbound uses it),
   *  and accept the old one on inbound for LEASE_ROTATION_OVERLAP_MS. */
  handleLeaseGranted(msg: LeaseGranted): void {
    const state = this.registry.get(msg.attempt_id);
    if (!state) return;
    state.prevLease = state.lease_id;
    state.lease_id = msg.lease_id;
    state.leaseOverlapUntil = this.now() + LIMITS.LEASE_ROTATION_OVERLAP_MS;
    // Durable too, so the post-terminal `leaseOk` store-fallback is current-gen.
    this.store.setAttemptLease(msg.attempt_id, msg.lease_id);
    log.info("lease rotated", { attempt_id: msg.attempt_id, lease_id: msg.lease_id });
  }

  handleCancel(msg: JobCancel): void {
    const state = this.registry.get(msg.attempt_id);
    if (!state) return;
    if (!this.leaseOk(state, msg.attempt_id, msg.lease_id)) return;
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
    if (!this.leaseOk(state, msg.attempt_id, msg.lease_id)) return; // not our lease
    log.warn("lease revoked — local fence", { attempt_id: msg.attempt_id });
    state.fenced = true;
    this.clearApprovals(state);
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
