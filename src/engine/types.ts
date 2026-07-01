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
  /** Attempt id — used to name the per-attempt worktree. */
  attemptId: string;
  /** Repo root to run under (validated against the allowlist by the adapter). */
  repoRoot: string;
  /** Optional base commit to branch the worktree from (defaults to HEAD). */
  baseSha?: string;
  /** Optional working subdir within the repo. */
  cwd?: string;
}

/** A tool the engine wants to run that needs remote approval (P3). */
export interface ApprovalRequest {
  requestId: string;
  toolName: string;
  input: unknown;
  risk?: "low" | "medium" | "high";
}

export type ApprovalDecision = "allow" | "deny";

export interface EngineRun {
  onEvent(cb: (ev: EngineEvent) => void): void;
  onDone(cb: (outcome: EngineOutcome) => void): void;
  /** Fired when the engine needs approval for a tool (P3). The manager forwards
   *  it as `approval.request` and later calls `resolveApproval`. */
  onApprovalRequest?(cb: (req: ApprovalRequest) => void): void;
  /** Deliver the remote decision for a prior `onApprovalRequest`. */
  resolveApproval?(requestId: string, decision: ApprovalDecision, reason?: string): void;
  /** Backpressure: stop emitting events until `resume()`. */
  pause(): void;
  resume(): void;
  /** Cancel: terminate the run; `onDone` fires with `{status:"cancelled"}`.
   *  `graceMs` is the SIGTERM→SIGKILL window for the real adapter. */
  cancel(graceMs: number): void;
}

import type { RejectCode } from "../conn/outbound";

export interface Engine {
  run(spec: EngineSpec): EngineRun;
  /** Optional pre-accept validation (workspace/policy). A non-null result makes
   *  the daemon `job.reject` BEFORE accepting/spawning. The fake engine omits it. */
  validate?(spec: EngineSpec): { code: RejectCode; message: string } | null;
}
