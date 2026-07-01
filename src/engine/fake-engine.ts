/**
 * In-process fake engine for e2e (P2a). Emits a scripted sequence of events, then
 * completes — unless `hang` (never completes until cancel) is set. Honors
 * pause/resume (backpressure) and cancel. Extensible in P3 for approval-prompt
 * simulation.
 */

import type { Engine, EngineEvent, EngineOutcome, EngineRun, EngineSpec } from "./types";

export interface FakeScript {
  events: EngineEvent[];
  outcome?: EngineOutcome;
  /** Never fire `onDone` until cancelled (simulates a hanging engine). */
  hang?: boolean;
  /** Defer `onDone` after `cancel()` to a later tick — models a real engine's
   *  async SIGTERM→SIGKILL termination (exposes stale-callback races). */
  cancelAsync?: boolean;
}

export class FakeEngine implements Engine {
  /** Number of times `run()` was called — lets tests assert no re-spawn. */
  runCount = 0;

  constructor(private readonly script: FakeScript) {}

  run(_spec: EngineSpec): EngineRun {
    this.runCount++;
    const eventCbs: Array<(e: EngineEvent) => void> = [];
    const doneCbs: Array<(o: EngineOutcome) => void> = [];
    let i = 0;
    let paused = false;
    let finished = false;
    const script = this.script;

    const finish = (o: EngineOutcome) => {
      if (finished) return;
      finished = true;
      for (const cb of doneCbs) cb(o);
    };
    const pump = () => {
      if (finished) return;
      while (!paused && i < script.events.length) {
        const ev = script.events[i++]!;
        for (const cb of eventCbs) cb(ev); // synchronous → a cap-hit pause() inside a cb stops the loop
      }
      if (!paused && i >= script.events.length && !script.hang) {
        finish(script.outcome ?? { status: "success" });
      }
    };

    // Start after the caller has registered its handlers (same tick, sync).
    queueMicrotask(pump);

    return {
      onEvent: (cb) => eventCbs.push(cb),
      onDone: (cb) => doneCbs.push(cb),
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
