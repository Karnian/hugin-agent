import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { EngineEvent, EngineOutcome } from "../engine/types";
import { normalizeClaudeLine, normalizeCodexLine } from "../engine/normalize";
import { scrubbedChildEnv } from "../engine/isolate";

export interface ResumeSpec {
  engine: "claude" | "codex";
  sessionId: string;
  cwd: string;
  message: string;
  fork: boolean;
  sandbox: "read_only" | "workspace_write" | "full";
}

export interface ResumeDone {
  outcome: EngineOutcome;
  finalMessage: string;
  newSessionId?: string;
}

export interface ResumeRun {
  onEvent(cb: (ev: EngineEvent) => void): void;
  onDone(cb: (r: ResumeDone) => void): void;
  pause(): void;
  resume(): void;
  cancel(graceMs: number): void;
}

export interface ResumeRunner {
  run(spec: ResumeSpec): ResumeRun;
}

export interface ResumeRunnerRegistry {
  claude?: ResumeRunner;
  codex?: ResumeRunner;
}

export interface ClaudeResumeRunnerOpts {
  command?: string;
  env?: NodeJS.ProcessEnv;
}

export interface CodexResumeRunnerOpts {
  command?: string;
  env?: NodeJS.ProcessEnv;
}

interface ClaudeStreamLine {
  type?: string;
  session_id?: unknown;
  result?: unknown;
  message?: { content?: unknown };
}

export class ClaudeResumeRunner implements ResumeRunner {
  constructor(private readonly opts: ClaudeResumeRunnerOpts = {}) {}

  run(spec: ResumeSpec): ResumeRun {
    const eventCbs: Array<(e: EngineEvent) => void> = [];
    const doneCbs: Array<(r: ResumeDone) => void> = [];
    let child: ChildProcess | null = null;
    let finished = false;
    let cancelled = false;
    let paused = false;
    let stdoutBuf = "";
    let stderrTail = "";
    let finalAssistantText = "";
    let finalResultText: string | null = null;
    let newSessionId: string | undefined;
    let killTimer: ReturnType<typeof setTimeout> | null = null;
    let closeOutcome: EngineOutcome | null = null;
    const pendingEvents: EngineEvent[] = [];

    const emit = (e: EngineEvent) => {
      if (paused) {
        pendingEvents.push(e);
        return;
      }
      for (const cb of eventCbs) cb(e);
    };
    const finish = (outcome: EngineOutcome) => {
      if (finished) return;
      finished = true;
      if (killTimer) clearTimeout(killTimer);
      const finalMessage = finalResultText ?? (finalAssistantText || stderrTail);
      for (const cb of doneCbs) cb({ outcome, finalMessage, newSessionId });
    };
    const maybeFinishClosed = () => {
      if (!closeOutcome) return;
      if (cancelled) {
        finish(closeOutcome);
        return;
      }
      if (paused) return;
      drain(true);
      finish(closeOutcome);
    };
    const flushPendingEvents = () => {
      while (!paused && pendingEvents.length > 0) {
        const ev = pendingEvents.shift();
        if (ev) for (const cb of eventCbs) cb(ev);
      }
    };
    const observeLine = (parsed: unknown) => {
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
      const line = parsed as ClaudeStreamLine;
      if (typeof line.session_id === "string" && line.session_id.length > 0) {
        newSessionId = line.session_id;
      }
      if (line.type === "result" && typeof line.result === "string") {
        finalResultText = line.result;
      }
      if (line.type === "assistant") {
        const text = assistantText(line.message?.content);
        if (text) finalAssistantText = text;
      }
    };
    const drain = (flush = false) => {
      while (true) {
        const nl = stdoutBuf.indexOf("\n");
        if (nl < 0) {
          if (!flush || stdoutBuf.trim().length === 0) break;
          const tail = stdoutBuf;
          stdoutBuf = "";
          parseAndEmit(tail);
          break;
        }
        const line = stdoutBuf.slice(0, nl);
        stdoutBuf = stdoutBuf.slice(nl + 1);
        parseAndEmit(line);
      }
    };
    const parseAndEmit = (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        return;
      }
      observeLine(parsed);
      for (const ev of normalizeClaudeLine(parsed)) emit(ev);
    };

    queueMicrotask(() => {
      if (finished) return;
      if (cancelled) {
        finish({ status: "cancelled" });
        return;
      }
      const args = [
        "--resume",
        spec.sessionId,
        ...(spec.fork ? ["--fork-session"] : []),
        "-p",
        spec.message,
        "--output-format",
        "stream-json",
        "--verbose",
      ];
      if (spec.sandbox === "read_only") {
        args.push("--disallowedTools", "Write", "Edit", "MultiEdit", "NotebookEdit", "Bash");
      }

      child = spawn(this.opts.command ?? "claude", args, {
        cwd: spec.cwd,
        env: scrubbedChildEnv(this.opts.env),
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,
      });
      child.stdout?.on("data", (d: Buffer) => {
        stdoutBuf += d.toString("utf8");
        if (!paused) drain();
      });
      child.stderr?.on("data", (d: Buffer) => {
        const text = d.toString("utf8");
        stderrTail = `${stderrTail}${text}`.slice(-8192);
        emit({ kind: "stderr_chunk", text });
      });
      child.on("error", (e) => {
        emit({ kind: "engine_error", error: String(e) });
        finish({ status: "error", errorKind: "spawn_failed" });
      });
      child.on("close", (code, signal) => {
        if (cancelled || signal) closeOutcome = { status: "cancelled" };
        else if (code === 0) closeOutcome = { status: "success", exitCode: 0 };
        else closeOutcome = { status: "error", exitCode: code ?? undefined, errorKind: "nonzero_exit" };
        maybeFinishClosed();
      });
    });

    return {
      onEvent: (cb) => eventCbs.push(cb),
      onDone: (cb) => doneCbs.push(cb),
      pause: () => {
        if (finished || paused) return;
        paused = true;
        child?.stdout?.pause();
        child?.stderr?.pause();
      },
      resume: () => {
        if (finished || !paused) return;
        paused = false;
        flushPendingEvents();
        if (paused) return;
        drain(closeOutcome !== null);
        if (paused) return;
        child?.stdout?.resume();
        child?.stderr?.resume();
        maybeFinishClosed();
      },
      cancel: (graceMs) => {
        if (finished) return;
        cancelled = true;
        if (!child?.pid) {
          queueMicrotask(() => finish({ status: "cancelled" }));
          return;
        }
        killProcessGroup(child.pid, "SIGTERM");
        killTimer = setTimeout(() => {
          if (child?.pid) killProcessGroup(child.pid, "SIGKILL");
        }, graceMs);
        killTimer.unref?.();
      },
    };
  }
}

export class CodexResumeRunner implements ResumeRunner {
  constructor(private readonly opts: CodexResumeRunnerOpts = {}) {}

  run(spec: ResumeSpec): ResumeRun {
    if (spec.engine !== "codex") throw new Error("CodexResumeRunner only supports codex sessions");
    if (spec.fork) throw new Error("codex resume is continue-only and cannot fork");
    if (spec.sandbox !== "read_only") throw new Error("codex resume requires read_only sandbox");

    const eventCbs: Array<(e: EngineEvent) => void> = [];
    const doneCbs: Array<(r: ResumeDone) => void> = [];
    let child: ChildProcess | null = null;
    let finished = false;
    let cancelled = false;
    let paused = false;
    let stdoutBuf = "";
    let stderrTail = "";
    let finalAssistantText = "";
    let killTimer: ReturnType<typeof setTimeout> | null = null;
    let closeOutcome: EngineOutcome | null = null;
    const pendingEvents: EngineEvent[] = [];
    const scratchDir = mkdtempSync(join(tmpdir(), "hugin-codex-resume-"));
    const outputFile = join(scratchDir, "last-message.txt");

    const emit = (e: EngineEvent) => {
      if (paused) {
        pendingEvents.push(e);
        return;
      }
      for (const cb of eventCbs) cb(e);
    };
    const cleanup = () => {
      try {
        rmSync(scratchDir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    };
    const readFinalMessage = () => {
      try {
        const text = readFileSync(outputFile, "utf8").trim();
        if (text) return text;
      } catch {
        /* fall back below */
      }
      return finalAssistantText || stderrTail;
    };
    const finish = (outcome: EngineOutcome) => {
      if (finished) return;
      finished = true;
      if (killTimer) clearTimeout(killTimer);
      const finalMessage = readFinalMessage();
      cleanup();
      for (const cb of doneCbs) cb({ outcome, finalMessage });
    };
    const maybeFinishClosed = () => {
      if (!closeOutcome) return;
      if (cancelled) {
        finish(closeOutcome);
        return;
      }
      if (paused) return;
      drain(true);
      finish(closeOutcome);
    };
    const flushPendingEvents = () => {
      while (!paused && pendingEvents.length > 0) {
        const ev = pendingEvents.shift();
        if (ev) for (const cb of eventCbs) cb(ev);
      }
    };
    const drain = (flush = false) => {
      while (true) {
        const nl = stdoutBuf.indexOf("\n");
        if (nl < 0) {
          if (!flush || stdoutBuf.trim().length === 0) break;
          const tail = stdoutBuf;
          stdoutBuf = "";
          parseAndEmit(tail);
          break;
        }
        const line = stdoutBuf.slice(0, nl);
        stdoutBuf = stdoutBuf.slice(nl + 1);
        parseAndEmit(line);
      }
    };
    const parseAndEmit = (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        return;
      }
      for (const ev of normalizeCodexLine(parsed)) {
        if (ev.kind === "assistant_text" && typeof ev.text === "string" && ev.text.length > 0) finalAssistantText = ev.text;
        emit(ev);
      }
    };

    queueMicrotask(() => {
      if (finished) return;
      if (cancelled) {
        finish({ status: "cancelled" });
        return;
      }
      const args = [
        "exec",
        "-s",
        "read-only",
        "resume",
        spec.sessionId,
        spec.message,
        "--json",
        "--skip-git-repo-check",
        "-o",
        outputFile,
      ];
      child = spawn(this.opts.command ?? "codex", args, {
        cwd: spec.cwd,
        env: scrubbedChildEnv(this.opts.env),
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,
      });
      child.stdout?.on("data", (d: Buffer) => {
        stdoutBuf += d.toString("utf8");
        if (!paused) drain();
      });
      child.stderr?.on("data", (d: Buffer) => {
        const text = d.toString("utf8");
        stderrTail = `${stderrTail}${text}`.slice(-8192);
        emit({ kind: "stderr_chunk", text });
      });
      child.on("error", (e) => {
        emit({ kind: "engine_error", error: String(e) });
        finish({ status: "error", errorKind: "spawn_failed" });
      });
      child.on("close", (code, signal) => {
        if (cancelled || signal) closeOutcome = { status: "cancelled" };
        else if (code === 0) closeOutcome = { status: "success", exitCode: 0 };
        else closeOutcome = { status: "error", exitCode: code ?? undefined, errorKind: "nonzero_exit" };
        maybeFinishClosed();
      });
    });

    return {
      onEvent: (cb) => eventCbs.push(cb),
      onDone: (cb) => doneCbs.push(cb),
      pause: () => {
        if (finished || paused) return;
        paused = true;
        child?.stdout?.pause();
        child?.stderr?.pause();
      },
      resume: () => {
        if (finished || !paused) return;
        paused = false;
        flushPendingEvents();
        if (paused) return;
        drain(closeOutcome !== null);
        if (paused) return;
        child?.stdout?.resume();
        child?.stderr?.resume();
        maybeFinishClosed();
      },
      cancel: (graceMs) => {
        if (finished) return;
        cancelled = true;
        if (!child?.pid) {
          queueMicrotask(() => finish({ status: "cancelled" }));
          return;
        }
        killProcessGroup(child.pid, "SIGTERM");
        killTimer = setTimeout(() => {
          if (child?.pid) killProcessGroup(child.pid, "SIGKILL");
        }, graceMs);
        killTimer.unref?.();
      },
    };
  }
}

export interface FakeResumeScript {
  events: EngineEvent[];
  outcome?: EngineOutcome;
  finalMessage?: string;
  newSessionId?: string;
  hang?: boolean;
}

export class FakeResumeRunner implements ResumeRunner {
  runCount = 0;
  cancelCount = 0;
  pauseCount = 0;
  resumeCount = 0;
  specs: ResumeSpec[] = [];
  private readonly activeRuns: FakeRunControl[] = [];

  constructor(private readonly script: FakeResumeScript) {}

  run(spec: ResumeSpec): ResumeRun {
    this.runCount++;
    this.specs.push(spec);
    const eventCbs: Array<(e: EngineEvent) => void> = [];
    const doneCbs: Array<(r: ResumeDone) => void> = [];
    const pending = [...this.script.events];
    let finished = false;
    let paused = false;

    const finish = (outcome: EngineOutcome) => {
      if (finished) return;
      finished = true;
      for (const cb of doneCbs) {
        cb({
          outcome,
          finalMessage: this.script.finalMessage ?? "",
          newSessionId: this.script.newSessionId,
        });
      }
    };
    const pump = () => {
      while (!finished && !paused && pending.length > 0) {
        const ev = pending.shift();
        if (ev) for (const cb of eventCbs) cb(ev);
      }
      if (!finished && !paused && pending.length === 0 && !this.script.hang) {
        finish(this.script.outcome ?? { status: "success" });
      }
    };
    const control: FakeRunControl = {
      emit: (event) => {
        if (finished) return;
        pending.push(event);
        pump();
      },
      finish: (outcome = this.script.outcome ?? { status: "success" }) => finish(outcome),
    };
    this.activeRuns.push(control);

    queueMicrotask(() => {
      pump();
    });

    return {
      onEvent: (cb) => eventCbs.push(cb),
      onDone: (cb) => doneCbs.push(cb),
      pause: () => {
        if (finished || paused) return;
        paused = true;
        this.pauseCount++;
      },
      resume: () => {
        if (finished || !paused) return;
        paused = false;
        this.resumeCount++;
        pump();
      },
      cancel: () => {
        this.cancelCount++;
        queueMicrotask(() => finish({ status: "cancelled" }));
      },
    };
  }

  emit(event: EngineEvent): void {
    this.latestRun()?.emit(event);
  }

  finish(outcome?: EngineOutcome): void {
    this.latestRun()?.finish(outcome);
  }

  private latestRun(): FakeRunControl | undefined {
    return this.activeRuns[this.activeRuns.length - 1];
  }
}

interface FakeRunControl {
  emit(event: EngineEvent): void;
  finish(outcome?: EngineOutcome): void;
}

function assistantText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const parts = content
    .map((part) => {
      if (part && typeof part === "object" && !Array.isArray(part)) {
        const block = part as { type?: unknown; text?: unknown };
        if (block.type === "text" && typeof block.text === "string") return block.text;
      }
      return null;
    })
    .filter((part): part is string => part !== null);
  return parts.join("");
}

function killProcessGroup(pid: number, signal: NodeJS.Signals): void {
  try {
    process.kill(-pid, signal);
  } catch {
    try {
      process.kill(pid, signal);
    } catch {
      /* already gone */
    }
  }
}
