/**
 * In-process fake engine for e2e (P2a). Emits a scripted sequence of events, then
 * completes — unless `hang` (never completes until cancel) is set. Honors
 * pause/resume (backpressure) and cancel. Extensible in P3 for approval-prompt
 * simulation.
 */

import type {
  ApprovalDecision,
  ApprovalRequest,
  Engine,
  EngineEvent,
  EngineOutcome,
  EngineRun,
  EngineSpec,
} from "./types";

export interface FakeScript {
  events: EngineEvent[];
  outcome?: EngineOutcome;
  /** Never fire `onDone` until cancelled (simulates a hanging engine). */
  hang?: boolean;
  /** Defer `onDone` after `cancel()` to a later tick — models a real engine's
   *  async SIGTERM→SIGKILL termination (exposes stale-callback races). */
  cancelAsync?: boolean;
  /** After `events`, request approval for a tool, then emit onAllow/onDeny per
   *  the remote decision and finish (models the P3 approval round-trip). */
  approval?: {
    toolName: string;
    input?: unknown;
    risk?: "low" | "medium" | "high";
    onAllow: EngineEvent[];
    onDeny: EngineEvent[];
  };
}

export class FakeEngine implements Engine {
  /** Number of times `run()` was called — lets tests assert no re-spawn. */
  runCount = 0;

  constructor(private readonly script: FakeScript) {}

  run(spec: EngineSpec): EngineRun {
    this.runCount++;
    const eventCbs: Array<(e: EngineEvent) => void> = [];
    const doneCbs: Array<(o: EngineOutcome) => void> = [];
    const approvalCbs: Array<(r: ApprovalRequest) => void> = [];
    let i = 0;
    let paused = false;
    let finished = false;
    let awaitingApproval = false;
    let approvalResolved = false;
    const script = this.script;

    const finish = (o: EngineOutcome) => {
      if (finished) return;
      finished = true;
      for (const cb of doneCbs) cb(o);
    };
    const finishOk = () => {
      if (!script.hang) finish(script.outcome ?? { status: "success" });
    };
    const pump = () => {
      if (finished || awaitingApproval) return;
      while (!paused && i < script.events.length) {
        const ev = script.events[i++]!;
        for (const cb of eventCbs) cb(ev); // synchronous → a cap-hit pause() inside a cb stops the loop
      }
      if (paused || i < script.events.length) return;
      // Events drained → request approval (once) if scripted, else finish.
      if (script.approval && !approvalResolved) {
        awaitingApproval = true;
        const req: ApprovalRequest = {
          requestId: `${spec.attemptId}-appr`,
          toolName: script.approval.toolName,
          input: script.approval.input,
          risk: script.approval.risk,
        };
        for (const cb of approvalCbs) cb(req);
        return;
      }
      finishOk();
    };

    // Start after the caller has registered its handlers (same tick, sync).
    queueMicrotask(pump);

    return {
      onEvent: (cb) => eventCbs.push(cb),
      onDone: (cb) => doneCbs.push(cb),
      onApprovalRequest: (cb) => approvalCbs.push(cb),
      resolveApproval: (_requestId: string, decision: ApprovalDecision) => {
        if (!awaitingApproval || approvalResolved || !script.approval) return;
        awaitingApproval = false;
        approvalResolved = true;
        const evs = decision === "allow" ? script.approval.onAllow : script.approval.onDeny;
        for (const ev of evs) for (const cb of eventCbs) cb(ev);
        finishOk();
      },
      pause: () => {
        paused = true;
      },
      resume: () => {
        if (!paused) return;
        paused = false;
        queueMicrotask(pump);
      },
      cancel: () => {
        if (script.cancelAsync) setTimeout(() => finish({ status: "cancelled" }), 0);
        else finish({ status: "cancelled" });
      },
    };
  }
}
