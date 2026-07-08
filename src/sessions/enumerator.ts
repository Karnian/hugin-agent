import { createHash, randomBytes } from "node:crypto";
import { closeSync, fstatSync, lstatSync, openSync, readdirSync, readSync, realpathSync, statSync } from "node:fs";
import { basename, join, relative, sep } from "node:path";
import type { MessageV2 } from "../../protocol/v1/index";
import { HistoryCursorError, readSessionHistory, type SessionHistoryEntry } from "./history";

type SessionListRequestMsg = Extract<MessageV2, { type: "session.list.request" }>;
export type SessionInfo = Extract<MessageV2, { type: "session.list.response" }>["sessions"][number];

export interface SessionEnumeratorOpts {
  claudeProjectsDir: string;
  codexSessionsDir: string;
  allowlist: readonly string[];
  maxSubagentFiles?: number;
  now?: () => number;
}

export interface SessionListResult {
  sessions: SessionInfo[];
  next_cursor: string | null;
  truncated: boolean;
}

export interface SessionHandleTarget {
  engine: SessionInfo["engine"];
  session_id: string;
  cwd: string;
  path: string;
  mtime: number;
}

interface SessionCandidate {
  info: SessionInfo;
  sessionId: string;
  cursorKey: string;
  path: string;
  cwdAbs: string;
  updatedMs: number;
}

interface ReadSessionFile {
  path: string;
  content: string;
  mtimeMs: number;
}

interface ClaudeScanResult {
  candidates: SessionCandidate[];
  subagentCapReached: boolean;
}

interface SubagentScanState {
  files: number;
  maxFiles: number;
  capReached: boolean;
}

const HEAD_RECORD_LIMIT = 80;
const MAX_SESSION_BYTES = 64 * 1024 * 1024;
const MAX_RESPONSE_SESSIONS = 256;
const MAX_SUBAGENT_FILES = 2000;
const ACTIVE_WINDOW_MS = 15 * 60 * 1000;
const TITLE_MAX = 80;
const UUID_PATTERN = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
const CLAUDE_FILE_RE = new RegExp(`^(${UUID_PATTERN})\\.jsonl$`);
const CLAUDE_SESSION_DIR_RE = new RegExp(`^${UUID_PATTERN}$`);
const CODEX_FILE_RE = new RegExp(`^rollout-.+-(${UUID_PATTERN})\\.jsonl$`);

function stableSessionId(engine: "claude" | "codex", rawSessionId: string): string {
  return `s_${createHash("sha256").update(`${engine}\0${rawSessionId}`).digest("hex").slice(0, 32)}`;
}

export class SessionEnumerator {
  private readonly now: () => number;
  private readonly keyToHandle = new Map<string, string>();
  private readonly handleToTarget = new Map<string, SessionHandleTarget>();

  constructor(private readonly opts: SessionEnumeratorOpts) {
    this.now = opts.now ?? Date.now;
  }

  list(req: Pick<SessionListRequestMsg, "filter" | "page"> = {}): SessionListResult {
    const allowed = this.realAllowlist();
    if (allowed.length === 0) return { sessions: [], next_cursor: null, truncated: false };

    const candidates: SessionCandidate[] = [];
    let subagentCapReached = false;
    if (req.filter?.engine !== "codex") {
      const claude = this.scanClaude(allowed, req.filter?.include_subagents === true);
      candidates.push(...claude.candidates);
      subagentCapReached = claude.subagentCapReached;
    }
    if (req.filter?.engine !== "claude") candidates.push(...this.scanCodex(allowed));

    const updatedAfter = req.filter?.updated_after ? Date.parse(req.filter.updated_after) : null;
    const filtered = candidates
      .filter((c) => (req.filter?.active_only ? c.info.active : true))
      .filter((c) => (req.filter?.include_subagents ? true : !c.info.is_subagent))
      .filter((c) => (updatedAfter !== null && Number.isFinite(updatedAfter) ? c.updatedMs > updatedAfter : true))
      .filter((c) => (req.filter?.cwd_prefix ? cwdMatchesPrefix(c.info.cwd, req.filter.cwd_prefix) : true))
      .sort((a, b) => b.updatedMs - a.updatedMs || a.cursorKey.localeCompare(b.cursorKey));

    const cursor = decodeCursor(req.page?.cursor);
    const cursorIsCurrent = cursor ? filtered.some((c) => c.updatedMs === cursor.updatedMs && c.cursorKey === cursor.cursorKey) : false;
    const afterCursor =
      cursor && cursorIsCurrent
        ? filtered.filter((c) => c.updatedMs < cursor.updatedMs || (c.updatedMs === cursor.updatedMs && c.cursorKey > cursor.cursorKey))
        : filtered;

    const requestedLimit = req.page?.limit ?? MAX_RESPONSE_SESSIONS;
    const limit = Math.max(1, Math.min(requestedLimit, MAX_RESPONSE_SESSIONS));
    const page = afterCursor.slice(0, limit);
    const pageTruncated = afterCursor.length > limit;
    const truncated = pageTruncated || subagentCapReached;
    const last = page[page.length - 1];

    return {
      sessions: page.map((c) => c.info),
      next_cursor: pageTruncated && last ? encodeCursor(last) : null,
      truncated,
    };
  }

  resolveHandle(handle: string): SessionHandleTarget | null {
    return this.handleToTarget.get(handle) ?? null;
  }

  validateHandle(handle: string): SessionHandleTarget | null {
    const target = this.resolveHandle(handle);
    if (!target) return null;
    try {
      const st = statSync(target.path);
      if (!st.isFile()) return null;
      const scoped = this.scopeCwd(target.cwd, this.realAllowlist());
      if (!scoped || scoped.abs !== target.cwd) return null;
      return { ...target, mtime: st.mtimeMs };
    } catch {
      return null;
    }
  }

  readHistory(
    handle: string,
    opts: { cursor?: string; limit?: number },
  ):
    | { ok: true; entries: SessionHistoryEntry[]; next_cursor: string | null; truncated: boolean }
    | { ok: false; code: "handle_invalid" | "file_unreadable" | "payload_too_large" | "cursor_invalid" | "history_unavailable" } {
    const target = this.validateHandle(handle);
    if (!target) return { ok: false, code: "handle_invalid" };

    try {
      if (statSync(target.path).size > MAX_SESSION_BYTES) return { ok: false, code: "payload_too_large" };
    } catch {
      return { ok: false, code: "file_unreadable" };
    }

    const file = this.readSessionFile(target.path);
    if (!file) return { ok: false, code: "file_unreadable" };

    try {
      const cursorScope = `${target.engine}\0${target.session_id}\0${target.path}`;
      const result = readSessionHistory(target.engine, file.content, target.session_id, opts, cursorScope);
      return { ok: true, ...result };
    } catch (e) {
      if (e instanceof HistoryCursorError) return { ok: false, code: "cursor_invalid" };
      return { ok: false, code: "history_unavailable" };
    }
  }

  registerForked(target: SessionHandleTarget): string {
    return this.handleFor(target);
  }

  private scanClaude(allowed: readonly string[], includeSubagents: boolean): ClaudeScanResult {
    const out: SessionCandidate[] = [];
    const subagentScan: SubagentScanState = { files: 0, maxFiles: this.maxSubagentFiles(), capReached: false };
    for (const project of safeReadDir(this.opts.claudeProjectsDir)) {
      if (!project.isDirectory()) continue;
      const projectDir = join(this.opts.claudeProjectsDir, project.name);
      for (const entry of safeReadDir(projectDir)) {
        const path = join(projectDir, entry.name);
        if (entry.isFile()) {
          const match = CLAUDE_FILE_RE.exec(entry.name);
          const sessionId = match?.[1];
          if (!sessionId) continue;
          const file = this.readSessionFile(path);
          if (!file) continue;
          const candidate = this.parseClaudeFile(file, sessionId, allowed, false);
          if (candidate) out.push(candidate);
          continue;
        }
        if (!includeSubagents || !entry.isDirectory() || !CLAUDE_SESSION_DIR_RE.test(entry.name)) continue;
        this.scanClaudeSubagentDir(join(path, "subagents"), allowed, out, subagentScan, 0);
      }
    }
    return { candidates: out, subagentCapReached: subagentScan.capReached };
  }

  private scanClaudeSubagentDir(
    dir: string,
    allowed: readonly string[],
    out: SessionCandidate[],
    state: SubagentScanState,
    depth: number,
  ): void {
    if (depth > 12 || state.capReached) return;
    for (const entry of safeReadDir(dir)) {
      if (state.capReached) return;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        this.scanClaudeSubagentDir(path, allowed, out, state, depth + 1);
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith(".jsonl")) continue;
      if (state.files >= state.maxFiles) {
        state.capReached = true;
        return;
      }
      state.files++;
      const sessionId = basename(entry.name, ".jsonl");
      if (!sessionId) continue;
      const file = this.readSessionFile(path);
      if (!file) continue;
      const candidate = this.parseClaudeFile(file, sessionId, allowed, true);
      if (candidate) out.push(candidate);
    }
  }

  private maxSubagentFiles(): number {
    const configured = this.opts.maxSubagentFiles;
    if (configured === undefined || !Number.isFinite(configured)) return MAX_SUBAGENT_FILES;
    return Math.max(0, Math.trunc(configured));
  }

  private scanCodex(allowed: readonly string[]): SessionCandidate[] {
    const out: SessionCandidate[] = [];
    this.scanCodexDir(this.opts.codexSessionsDir, allowed, out, 0);
    return out;
  }

  private scanCodexDir(dir: string, allowed: readonly string[], out: SessionCandidate[], depth: number): void {
    if (depth > 12) return;
    for (const entry of safeReadDir(dir)) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        this.scanCodexDir(path, allowed, out, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      const match = CODEX_FILE_RE.exec(entry.name);
      const fileSessionId = match?.[1];
      if (!fileSessionId) continue;
      const file = this.readSessionFile(path);
      if (!file) continue;
      const candidate = this.parseCodexFile(file, fileSessionId, allowed);
      if (candidate) out.push(candidate);
    }
  }

  private parseClaudeFile(file: ReadSessionFile, sessionId: string, allowed: readonly string[], isSubagent: boolean): SessionCandidate | null {
    const lines = jsonlLines(file.content);
    if (lines.length === 0) return null;
    const head = parseHead(lines);

    let cwd: string | null = null;
    let gitBranch: string | null = null;
    let cliVersion: string | null = null;
    for (const rec of head) {
      cwd ??= stringField(rec, "cwd");
      gitBranch ??= stringField(rec, "gitBranch");
      cliVersion ??= stringField(rec, "version");
      if (cwd && gitBranch && cliVersion) break;
    }
    if (!cwd) return null;
    const scoped = this.scopeCwd(cwd, allowed);
    if (!scoped) return null;

    // Historical wire field: `is_subagent` now marks any non-primary session,
    // either a nested subagent or a non-interactive/programmatic run.
    const isNonPrimarySession = isSubagent || isProgrammaticClaude(head);
    const updatedAt = new Date(file.mtimeMs).toISOString();
    const createdAt = isoFromUnknown(head[0]?.timestamp) ?? updatedAt;
    const title = findClaudeTitle(head) ?? genericSessionTitle("claude", scoped.redacted, scoped.abs);
    const handle = this.handleFor({
      engine: "claude",
      session_id: sessionId,
      cwd: scoped.abs,
      path: file.path,
      mtime: file.mtimeMs,
    });

    return {
      info: {
        handle,
        session_id: stableSessionId("claude", sessionId),
        engine: "claude",
        cwd: scoped.redacted,
        git_branch: gitBranch,
        cli_version: cliVersion,
        title,
        created_at: createdAt,
        updated_at: updatedAt,
        active: this.now() - file.mtimeMs <= ACTIVE_WINDOW_MS,
        is_subagent: isNonPrimarySession,
        msg_count: lines.length,
      },
      sessionId,
      cursorKey: `claude:${sessionId}`,
      path: file.path,
      cwdAbs: scoped.abs,
      updatedMs: file.mtimeMs,
    };
  }

  private parseCodexFile(file: ReadSessionFile, fileSessionId: string, allowed: readonly string[]): SessionCandidate | null {
    const lines = jsonlLines(file.content);
    if (lines.length === 0) return null;
    const head = parseHead(lines);
    const first = head[0];
    const payload = objectField(first, "payload");
    if (first?.type !== "session_meta" || !payload) return null;
    const sourceObj = objectField(payload, "source");
    const sourceStr = stringField(payload, "source");
    const originator = stringField(payload, "originator");
    const isSubagentObj = sourceObj !== null && Object.prototype.hasOwnProperty.call(sourceObj, "subagent");
    const isExec = sourceStr === "exec" || originator === "codex_exec";
    const isSubagent = isSubagentObj || isExec;

    const cwd = stringField(payload, "cwd");
    if (!cwd) return null;
    const scoped = this.scopeCwd(cwd, allowed);
    if (!scoped) return null;

    const sessionId = stringField(payload, "id") ?? fileSessionId;
    const updatedAt = new Date(file.mtimeMs).toISOString();
    const createdAt = isoFromUnknown(payload.timestamp) ?? updatedAt;
    const cliVersion = stringField(payload, "cli_version");
    const title = genericSessionTitle("codex", scoped.redacted, scoped.abs);
    const handle = this.handleFor({
      engine: "codex",
      session_id: sessionId,
      cwd: scoped.abs,
      path: file.path,
      mtime: file.mtimeMs,
    });

    return {
      info: {
        handle,
        session_id: stableSessionId("codex", sessionId),
        engine: "codex",
        cwd: scoped.redacted,
        git_branch: null,
        cli_version: cliVersion,
        title,
        created_at: createdAt,
        updated_at: updatedAt,
        active: this.now() - file.mtimeMs <= ACTIVE_WINDOW_MS,
        is_subagent: isSubagent,
        msg_count: lines.length,
      },
      sessionId,
      cursorKey: `codex:${sessionId}`,
      path: file.path,
      cwdAbs: scoped.abs,
      updatedMs: file.mtimeMs,
    };
  }

  private readSessionFile(path: string): ReadSessionFile | null {
    let fd: number | null = null;
    try {
      const lst = lstatSync(path);
      if (!lst.isFile() || lst.size > MAX_SESSION_BYTES) return null;
      fd = openSync(path, "r");
      const st = fstatSync(fd);
      if (!st.isFile() || st.size > MAX_SESSION_BYTES) return null;
      const buf = Buffer.allocUnsafe(st.size);
      const bytesRead = readSync(fd, buf, 0, st.size, 0);
      return { path, content: buf.subarray(0, bytesRead).toString("utf8"), mtimeMs: st.mtimeMs };
    } catch {
      return null;
    } finally {
      if (fd !== null) {
        try {
          closeSync(fd);
        } catch {
          /* ignore close errors while enumerating metadata */
        }
      }
    }
  }

  private realAllowlist(): string[] {
    return this.opts.allowlist
      .map((root) => {
        try {
          return realpathSync(root);
        } catch {
          return null;
        }
      })
      .filter((root): root is string => root !== null);
  }

  private scopeCwd(cwd: string, allowed: readonly string[]): { abs: string; redacted: string } | null {
    let real: string;
    try {
      real = realpathSync(cwd);
    } catch {
      return null;
    }
    const root = allowed
      .filter((a) => real === a || real.startsWith(a + sep))
      .sort((a, b) => b.length - a.length)[0];
    if (!root) return null;
    const rel = relative(root, real);
    return { abs: real, redacted: rel ? rel.split(sep).join("/") : "." };
  }

  private handleFor(target: SessionHandleTarget): string {
    const key = `${target.engine}\0${target.session_id}\0${target.path}`;
    let handle = this.keyToHandle.get(key);
    if (!handle) {
      handle = `h_${randomBytes(16).toString("hex")}`;
      this.keyToHandle.set(key, handle);
    }
    this.handleToTarget.set(handle, target);
    return handle;
  }
}

function safeReadDir(dir: string) {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

function jsonlLines(content: string): string[] {
  return content.split(/\r?\n/).filter((line) => line.trim().length > 0);
}

function parseHead(lines: readonly string[]): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const line of lines.slice(0, HEAD_RECORD_LIMIT)) {
    try {
      const parsed: unknown = JSON.parse(line);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) out.push(parsed as Record<string, unknown>);
    } catch {
      /* malformed JSONL lines are ignored */
    }
  }
  return out;
}

function stringField(obj: Record<string, unknown> | undefined, key: string): string | null {
  const value = obj?.[key];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function objectField(obj: Record<string, unknown> | undefined, key: string): Record<string, unknown> | null {
  const value = obj?.[key];
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function isoFromUnknown(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function findClaudeTitle(head: readonly Record<string, unknown>[]): string | null {
  for (const rec of head) {
    if (rec.type === "ai-title") {
      const title = stringField(rec, "title") ?? stringField(rec, "summary") ?? stringField(rec, "text") ?? contentToText(rec.message);
      const label = cleanLabel(title);
      if (label) return label;
    }
  }
  return null;
}

function isProgrammaticClaude(head: readonly Record<string, unknown>[]): boolean {
  for (const rec of head) {
    const entrypoint = stringField(rec, "entrypoint");
    if (entrypoint !== null) return entrypoint.startsWith("sdk");
  }
  return false;
}

function contentToText(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    const parts = value
      .map((part) => {
        if (typeof part === "string") return part;
        if (part && typeof part === "object") {
          const obj = part as Record<string, unknown>;
          return contentToText(obj.text) ?? contentToText(obj.content);
        }
        return null;
      })
      .filter((part): part is string => part !== null);
    return parts.length > 0 ? parts.join(" ") : null;
  }
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return contentToText(obj.text) ?? contentToText(obj.content);
  }
  return null;
}

function cleanLabel(value: string | null | undefined): string | null {
  const label = value?.replace(/\s+/g, " ").trim();
  if (!label) return null;
  if (label.length <= TITLE_MAX) return label;
  return `${label.slice(0, TITLE_MAX - 3).trimEnd()}...`;
}

function genericSessionTitle(engine: "claude" | "codex", redactedCwd: string, absCwd: string): string {
  const cwdBase = basename(redactedCwd === "." ? absCwd : redactedCwd) || ".";
  return cleanLabel(`${engine} · ${cwdBase}`) ?? `${engine} session`;
}

function cwdMatchesPrefix(cwd: string, prefix: string): boolean {
  const p = prefix.replace(/\\/g, "/").replace(/^\/+/, "").replace(/\/+$/, "");
  if (!p || p === ".") return true;
  return cwd === p || cwd.startsWith(`${p}/`);
}

function encodeCursor(candidate: SessionCandidate): string {
  return Buffer.from(JSON.stringify({ v: 1, u: candidate.updatedMs, k: candidate.cursorKey }), "utf8").toString("base64url");
}

function decodeCursor(cursor: string | undefined): { updatedMs: number; cursorKey: string } | null {
  if (!cursor) return null;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const obj = parsed as Record<string, unknown>;
    return typeof obj.u === "number" && Number.isFinite(obj.u) && typeof obj.k === "string"
      ? { updatedMs: obj.u, cursorKey: obj.k }
      : null;
  } catch {
    return null;
  }
}
