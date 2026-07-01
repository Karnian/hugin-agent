/**
 * Engine abstraction. Both the real Claude adapter (P2b) and the fake engine
 * (P2a tests) implement `Engine`; the job manager only ever talks to this
 * interface, so the wire/lifecycle path is testable without a real CLI.
 */

/** A normalized engine event → becomes the `event` payload of a `stream.event`.
 *  `kind` must be a core EventKind or `vendor.<engine>.*` (validated at send). */
export interface EngineEvent {
  kind: string;
  [k: string]: unknown;
}

export type EngineOutcome =
  | { status: "success"; exitCode?: number }
  | { status: "error"; exitCode?: number; errorKind?: string }
  | { status: "cancelled" };

export interface EngineSpec {
  engine: "claude" | "codex";
  prompt: string;
  cwd: string;
}

export interface EngineRun {
  onEvent(cb: (ev: EngineEvent) => void): void;
  onDone(cb: (outcome: EngineOutcome) => void): void;
  /** Backpressure: stop emitting events until `resume()`. */
  pause(): void;
  resume(): void;
  /** Cancel: terminate the run; `onDone` fires with `{status:"cancelled"}`.
   *  `graceMs` is the SIGTERM→SIGKILL window for the real adapter (P3). */
  cancel(graceMs: number): void;
}

export interface Engine {
  run(spec: EngineSpec): EngineRun;
}
