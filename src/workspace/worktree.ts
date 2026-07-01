/**
 * git-worktree isolation for one attempt. Validation (allowlist + realpath
 * symlink guard + git + cwd-containment + path-injection-safe attempt segment) is
 * split out so the daemon can run it BEFORE accepting a job (→ job.reject on
 * failure). `createWorktree` then adds a detached worktree off base_sha.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, realpathSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

export type WorktreeCode = "root_not_allowlisted" | "not_a_git_repo" | "cwd_escape" | "worktree_failed";

export interface WorktreeError extends Error {
  code: WorktreeCode;
}

function err(code: WorktreeCode, message: string): WorktreeError {
  return Object.assign(new Error(message), { code });
}

/** A filesystem-safe path segment for a (relay-controlled) attempt_id — strips
 *  slashes AND dots so `../../x` can't escape the worktree base. */
function safeSegment(id: string): string {
  return id.replace(/[^A-Za-z0-9_-]/g, "_") || "_";
}

export interface Validated {
  /** Realpath'd repo root. */
  root: string;
  /** The worktree directory to create. */
  wtDir: string;
  /** Relative cwd within the repo (empty = repo root). */
  relCwd: string;
}

/** Pure validation (no side effects). Throws WorktreeError on any violation. */
export function validateWorkspace(opts: {
  repoRoot: string;
  cwd?: string;
  allowlist: string[];
  stateDir: string;
  attemptId: string;
}): Validated {
  let root: string;
  try {
    root = realpathSync(opts.repoRoot);
  } catch {
    throw err("root_not_allowlisted", `repo_root does not exist: ${opts.repoRoot}`);
  }
  const allowed = opts.allowlist
    .map((r) => {
      try {
        return realpathSync(r);
      } catch {
        return null;
      }
    })
    .filter((r): r is string => r !== null);
  if (!allowed.some((a) => root === a || root.startsWith(a + sep))) {
    throw err("root_not_allowlisted", `repo_root not on the allowlist: ${root}`);
  }
  if (!existsSync(join(root, ".git"))) throw err("not_a_git_repo", `repo_root is not a git repository: ${root}`);

  let relCwd = "";
  if (opts.cwd) {
    let c: string;
    try {
      c = realpathSync(resolve(root, opts.cwd));
    } catch {
      throw err("cwd_escape", `cwd does not resolve: ${opts.cwd}`);
    }
    if (c !== root && !c.startsWith(root + sep)) throw err("cwd_escape", `cwd escapes repo_root: ${opts.cwd}`);
    relCwd = relative(root, c);
  }

  const wtBase = resolve(opts.stateDir, "worktrees");
  const wtDir = join(wtBase, safeSegment(opts.attemptId));
  // Defense in depth: the sanitized segment can't escape, but assert containment.
  if (!(resolve(wtDir) + sep).startsWith(wtBase + sep)) {
    throw err("worktree_failed", "unsafe worktree path for attempt_id");
  }
  return { root, wtDir, relCwd };
}

export interface WorktreeHandle {
  /** Directory the engine should run in (worktree root, or its cwd subdir). */
  dir: string;
  /** Remove the worktree (best-effort; safe to call once). */
  cleanup: () => void;
}

export function createWorktree(opts: {
  repoRoot: string;
  baseSha?: string;
  cwd?: string;
  allowlist: string[];
  stateDir: string;
  attemptId: string;
}): WorktreeHandle {
  const { root, wtDir, relCwd } = validateWorkspace(opts);
  mkdirSync(resolve(opts.stateDir, "worktrees"), { recursive: true });
  const ref = opts.baseSha ?? "HEAD";
  try {
    execFileSync("git", ["-C", root, "worktree", "add", "--detach", wtDir, ref], { stdio: "pipe" });
  } catch (e) {
    throw err("worktree_failed", `git worktree add failed: ${String((e as Error).message).slice(0, 200)}`);
  }
  return {
    dir: relCwd ? join(wtDir, relCwd) : wtDir,
    cleanup: () => {
      try {
        execFileSync("git", ["-C", root, "worktree", "remove", "--force", wtDir], { stdio: "pipe" });
      } catch {
        /* best-effort — the daemon can reclaim orphaned worktrees on restart */
      }
    },
  };
}
