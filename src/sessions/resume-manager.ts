import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { LIMITS, type MessageV2 } from "../../protocol/v1/index";
import { envelope } from "../conn/outbound";
import type { EngineEvent, EngineOutcome } from "../engine/types";
import type { SessionEnumerator, SessionHandleTarget } from "./enumerator";
import type { ResumeRun, ResumeRunner, ResumeRunnerRegistry } from "./resume";

type SessionResumeRequestMsg = Extract<MessageV2, { type: "session.resume.request" }>;
type SessionMessageMsg = Extract<MessageV2, { type: "session.message" }>;
type SessionCancelMsg = Extract<MessageV2, { type: "session.cancel" }>;
type SessionAckMsg = Extract<MessageV2, { type: "session.ack" }>;
type TurnStartMsg = SessionResumeRequestMsg | SessionMessageMsg;
type Send = (m: MessageV2) => void;

export interface SessionResumeManagerOpts {
  enumerator?: Pick<SessionEnumerator, "validateHandle" | "registerForked">;
  runners?: ResumeRunnerRegistry;
  runner?: ResumeRunner;
  maxUnackedEvents?: number;
  turnTimeoutMs?: number;
  cancelGraceMs?: number;
}

export class SessionResumeManager {
  private readonly active = new Set<string>();
  private readonly turns = new Map<string, TurnState>();

  constructor(private readonly send: Send, private readonly opts: SessionResumeManagerOpts = {}) {}

  handleRequest(req: SessionResumeRequestMsg): void {
    this.startTurn(req);
  }

  handleMessage(req: SessionMessageMsg): void {
    this.startTurn(req);
  }

  handleCancel(msg: SessionCancelMsg): void {
    const state = this.turns.get(msg.turn_id);
    if (!state || state.finalized) return;
    state.run.cancel(this.cancelGraceMs());
  }

  handleAck(msg: SessionAckMsg): void {
    const state = this.turns.get(msg.turn_id);
    if (!state || state.finalized) return;
    state.ackedSeq = Math.max(state.ackedSeq, Math.min(msg.ack_seq, state.sentSeq));
    this.maybeResume(state);
  }

  private startTurn(req: TurnStartMsg): void {
    const target = this.opts.enumerator?.validateHandle(req.handle) ?? null;
    if (!target) {
      this.reject(req, "handle_invalid", "session handle is invalid or stale");
      return;
    }
    const plan = this.planFor(target.engine);
    if (!plan.runner) {
      this.reject(req, "engine_unavailable", `${target.engine} resume runner is not available`);
      return;
    }

    const key = sessionKey(target);
    if (this.active.has(key)) {
      this.reject(req, "session_busy", "a resume turn is already active for this session");
      return;
    }
    this.active.add(key);

    const turnId = `turn-${randomUUID()}`;
    this.send({
      ...envelope(),
      type: "session.resume.accept",
      request_id: req.request_id,
      turn_id: turnId,
      effective_options: { fork: plan.fork, sandbox: "read_only", mutates_source: plan.mutatesSource },
    });

    try {
      const run = plan.runner.run({
        engine: target.engine,
        sessionId: target.session_id,
        cwd: target.cwd,
        message: req.message,
        fork: plan.fork,
        sandbox: "read_only",
      });
      const state: TurnState = {
        key,
        target,
        run,
        sentSeq: 0,
        ackedSeq: 0,
        finalized: false,
        paused: false,
        timeout: null,
      };
      this.turns.set(turnId, state);
      state.timeout = setTimeout(() => {
        const current = this.turns.get(turnId);
        if (!current || current.finalized) return;
        current.run.cancel(this.cancelGraceMs());
        this.finalize(turnId, "error", "resume turn timed out");
      }, this.turnTimeoutMs());
      state.timeout.unref?.();
      run.onEvent((event) => {
        this.handleRunEvent(turnId, event);
      });
      run.onDone((result) => {
        const current = this.turns.get(turnId);
        if (!current || current.finalized) return;
        const newSessionHandle = plan.fork && result.newSessionId ? this.registerFork(current.target, result.newSessionId) : undefined;
        this.finalize(turnId, statusFromOutcome(result.outcome), result.finalMessage, newSessionHandle);
      });
    } catch (e) {
      const message = String((e as Error).message ?? e);
      if (this.turns.has(turnId)) {
        this.finalize(turnId, "error", message);
      } else {
        this.send({
          ...envelope(),
          type: "session.turn.result",
          turn_id: turnId,
          status: "error",
          final_message: message,
        });
        this.active.delete(key);
      }
    }
  }

  private reject(req: TurnStartMsg, code: string, message: string): void {
    this.send({
      ...envelope(),
      type: "session.resume.reject",
      request_id: req.request_id,
      code,
      message,
    });
  }

  private sendEvent(turnId: string, seq: number, event: EngineEvent): void {
    this.send({
      ...envelope(),
      type: "session.event",
      turn_id: turnId,
      seq,
      event,
    });
  }

  private handleRunEvent(turnId: string, event: EngineEvent): void {
    const state = this.turns.get(turnId);
    if (!state || state.finalized) return;
    state.sentSeq++;
    this.sendEvent(turnId, state.sentSeq, event);
    if (!state.paused && state.sentSeq - state.ackedSeq >= this.backpressureCap()) {
      state.paused = true;
      state.run.pause();
    }
  }

  private maybeResume(state: TurnState): void {
    if (!state.paused || state.finalized) return;
    if (state.sentSeq - state.ackedSeq >= this.backpressureCap()) return;
    state.paused = false;
    state.run.resume();
  }

  private finalize(turnId: string, status: "ok" | "error" | "cancelled", finalMessage: string, newSessionHandle?: string): void {
    const state = this.turns.get(turnId);
    if (!state || state.finalized) return;
    state.finalized = true;
    if (state.timeout) clearTimeout(state.timeout);
    this.send({
      ...envelope(),
      type: "session.turn.result",
      turn_id: turnId,
      status,
      final_message: finalMessage,
      new_session_handle: newSessionHandle,
    });
    this.active.delete(state.key);
    this.turns.delete(turnId);
  }

  private registerFork(target: SessionHandleTarget, newSessionId: string): string | undefined {
    const enumerator = this.opts.enumerator;
    if (!enumerator) return undefined;
    return enumerator.registerForked({
      ...target,
      session_id: newSessionId,
      path: join(dirname(target.path), `${newSessionId}.jsonl`),
      mtime: Date.now(),
    });
  }

  private backpressureCap(): number {
    return this.opts.maxUnackedEvents ?? LIMITS.MAX_UNACKED_EVENTS_PER_ATTEMPT;
  }

  private turnTimeoutMs(): number {
    return this.opts.turnTimeoutMs ?? 3_600_000;
  }

  private cancelGraceMs(): number {
    return this.opts.cancelGraceMs ?? 5_000;
  }

  private planFor(engine: SessionHandleTarget["engine"]): ResumePlan {
    const runners = this.opts.runners ?? (this.opts.runner ? { claude: this.opts.runner } : {});
    if (engine === "claude") return { runner: runners.claude, fork: true, mutatesSource: false };
    return { runner: runners.codex, fork: false, mutatesSource: true };
  }
}

interface TurnState {
  key: string;
  target: SessionHandleTarget;
  run: ResumeRun;
  sentSeq: number;
  ackedSeq: number;
  finalized: boolean;
  paused: boolean;
  timeout: ReturnType<typeof setTimeout> | null;
}

function sessionKey(target: SessionHandleTarget): string {
  return `${target.engine}\0${target.session_id}\0${target.cwd}`;
}

function statusFromOutcome(outcome: EngineOutcome): "ok" | "error" | "cancelled" {
  if (outcome.status === "success") return "ok";
  if (outcome.status === "cancelled") return "cancelled";
  return "error";
}

interface ResumePlan {
  runner?: ResumeRunner;
  fork: boolean;
  mutatesSource: boolean;
}
