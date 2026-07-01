/**
 * Real Claude Code adapter (P2b). Spawns `claude -p --output-format stream-json`
 * inside a per-attempt git worktree, parses the NDJSON stream into normalized
 * `EngineEvent`s, and terminates via process-group kill.
 *
 * Backpressure = a `paused` flag checked BETWEEN lines while draining a chunk
 * (child.stdout.pause() alone can't interrupt a callback already draining a
 * buffered chunk), plus pausing the OS pipe so no new chunks arrive.
 *
 * The approval-prompt bridge over WSS + fail-closed policy land in P3; here the
 * engine runs under whatever permission config `opts.env` sets.
 */

import { type ChildProcess, spawn } from "node:child_process";
import type { RejectCode } from "../conn/outbound";
import type { Engine, EngineEvent, EngineOutcome, EngineRun, EngineSpec } from "./types";
import { normalizeClaudeLine } from "./normalize";
import { createWorktree, validateWorkspace, type WorktreeError, type WorktreeHandle } from "../workspace/worktree";
import { log } from "../log";

export interface ClaudeEngineOpts {
  command?: string; // default "claude"
  env?: NodeJS.ProcessEnv; // isolation env overlay (from isolate.ts)
  allowlist: string[];
  stateDir: string;
  timeoutMs?: number;
}

export class ClaudeEngine implements Engine {
  constructor(private readonly opts: ClaudeEngineOpts) {}

  /** Pre-accept workspace validation → job.reject on failure (no side effects). */
  validate(spec: EngineSpec): { code: RejectCode; message: string } | null {
    try {
      validateWorkspace({
        repoRoot: spec.repoRoot,
        cwd: spec.cwd,
        allowlist: this.opts.allowlist,
        stateDir: this.opts.stateDir,
        attemptId: spec.attemptId,
      });
      return null;
    } catch (e) {
      const wc = (e as WorktreeError).code;
      const code: RejectCode = wc === "root_not_allowlisted" ? "root_not_allowlisted" : "bad_request";
      return { code, message: String((e as Error).message) };
    }
  }

  run(spec: EngineSpec): EngineRun {
    const eventCbs: Array<(e: EngineEvent) => void> = [];
    const doneCbs: Array<(o: EngineOutcome) => void> = [];
    let finished = false;
    let cancelled = false;
    let paused = false;
    let wt: WorktreeHandle | null = null;
    let child: ChildProcess | null = null;
    let stdoutBuf = "";
    let timeoutTimer: ReturnType<typeof setTimeout> | null = null;
    let killTimer: ReturnType<typeof setTimeout> | null = null;

    const emit = (e: EngineEvent) => {
      for (const cb of eventCbs) cb(e);
    };
    const finish = (o: EngineOutcome) => {
      if (finished) return;
      finished = true;
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (killTimer) clearTimeout(killTimer);
      wt?.cleanup();
      for (const cb of doneCbs) cb(o);
    };

    // Drain complete NDJSON lines, checking `paused` between lines so a cap
    // crossed mid-chunk (manager pauses synchronously in onEvent) stops draining;
    // the remainder stays in stdoutBuf until resume().
    const drain = () => {
      while (!paused) {
        const nl = stdoutBuf.indexOf("\n");
        if (nl < 0) break;
        const line = stdoutBuf.slice(0, nl).trim();
        stdoutBuf = stdoutBuf.slice(nl + 1);
        if (!line) continue;
        let parsed: unknown;
        try {
          parsed = JSON.parse(line);
        } catch {
          continue; // non-JSON line
        }
        for (const ev of normalizeClaudeLine(parsed)) emit(ev);
      }
    };

    // Defer worktree + spawn so the caller registers onEvent/onDone first.
    queueMicrotask(() => {
      if (finished) return;
      try {
        wt = createWorktree({
          repoRoot: spec.repoRoot,
          baseSha: spec.baseSha,
          cwd: spec.cwd,
          allowlist: this.opts.allowlist,
          stateDir: this.opts.stateDir,
          attemptId: spec.attemptId,
        });
      } catch (e) {
        const code = (e as WorktreeError).code ?? "workspace_error";
        emit({ kind: "engine_error", error: String((e as Error).message), code });
        finish({ status: "error", errorKind: code });
        return;
      }

      const args = ["-p", spec.prompt, "--output-format", "stream-json", "--verbose", "--permission-mode", "default"];
      child = spawn(this.opts.command ?? "claude", args, {
        cwd: wt.dir,
        env: { ...process.env, ...this.opts.env },
        stdio: ["ignore", "pipe", "pipe"], // prompt via -p, NOT stdin (spike finding)
        detached: true, // own process group for cancel
      });

      if (this.opts.timeoutMs) {
        timeoutTimer = setTimeout(() => {
          cancelled = true;
          this.killGroup(child, "SIGKILL");
          finish({ status: "error", errorKind: "timeout" });
        }, this.opts.timeoutMs);
        timeoutTimer.unref?.();
      }

      child.stdout?.on("data", (d: Buffer) => {
        stdoutBuf += d.toString("utf8");
        drain();
      });
      child.stderr?.on("data", (d: Buffer) => emit({ kind: "stderr_chunk", text: d.toString("utf8") }));
      child.on("error", (e) => {
        emit({ kind: "engine_error", error: String(e) });
        finish({ status: "error", errorKind: "spawn_failed" });
      });
      child.on("close", (code, signal) => {
        drain(); // flush any buffered tail
        if (cancelled || signal) finish({ status: "cancelled" });
        else if (code === 0) finish({ status: "success", exitCode: 0 });
        else finish({ status: "error", exitCode: code ?? undefined, errorKind: "nonzero_exit" });
      });
    });

    return {
      onEvent: (cb) => eventCbs.push(cb),
      onDone: (cb) => doneCbs.push(cb),
      pause: () => {
        paused = true;
        child?.stdout?.pause();
      },
      resume: () => {
        paused = false;
        child?.stdout?.resume();
        drain(); // process anything buffered while paused
      },
      cancel: (graceMs) => {
        cancelled = true;
        if (!child || finished) {
          finish({ status: "cancelled" });
          return;
        }
        this.killGroup(child, "SIGTERM");
        killTimer = setTimeout(() => this.killGroup(child, "SIGKILL"), Math.max(0, graceMs));
        killTimer.unref?.();
      },
    };
  }

  /** Kill the child's whole process group (detached leader); fall back to the
   *  child pid if the group is already gone. */
  private killGroup(child: ChildProcess | null, sig: NodeJS.Signals): void {
    if (!child?.pid) return;
    try {
      process.kill(-child.pid, sig);
    } catch {
      try {
        child.kill(sig);
      } catch {
        /* already exited */
      }
    }
    log.debug("engine killGroup", { sig });
  }
}
