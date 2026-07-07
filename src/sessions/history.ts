import { createHash } from "node:crypto";
import type { MessageV2 } from "../../protocol/v1/index";

export type SessionHistoryEntry = Extract<MessageV2, { type: "session.history.response" }>["entries"][number];
type SessionToolCall = NonNullable<SessionHistoryEntry["tool_calls"]>[number];
type HistoryEngine = "claude" | "codex";
type HistoryRole = SessionHistoryEntry["role"];
type OmittedKind = NonNullable<SessionHistoryEntry["omitted"]>[number]["kind"];
type ToolStatus = NonNullable<SessionToolCall["status"]>;

export const HISTORY_CONTENT_CAP = 16_384;
export const HISTORY_TOOL_IO_CAP = 8_192;
export const HISTORY_PAGE_DEFAULT = 50;
export const HISTORY_PAGE_MAX = 256;

export class HistoryCursorError extends Error {
  readonly code = "cursor_invalid" as const;

  constructor(message = "invalid history cursor") {
    super(message);
    this.name = "HistoryCursorError";
  }
}

export function readSessionHistory(
  engine: HistoryEngine,
  content: string,
  sessionId: string,
  opts: { cursor?: string; limit?: number },
): { entries: SessionHistoryEntry[]; next_cursor: string | null; truncated: boolean } {
  return paginateHistory(buildHistoryEntries(engine, content, sessionId), opts);
}

export function buildHistoryEntries(engine: HistoryEngine, content: string, sessionId: string): SessionHistoryEntry[] {
  const lines = parseJsonlLines(content);
  return engine === "claude" ? buildClaudeHistoryEntries(lines, sessionId) : buildCodexHistoryEntries(lines, sessionId);
}

export function paginateHistory(
  entries: readonly SessionHistoryEntry[],
  opts: { cursor?: string; limit?: number } = {},
): { entries: SessionHistoryEntry[]; next_cursor: string | null; truncated: boolean } {
  const limit = clampLimit(opts.limit);
  const boundary = opts.cursor === undefined ? entries.length : decodeHistoryCursor(opts.cursor, entries.length).b;
  const start = Math.max(0, boundary - limit);
  const page = entries.slice(start, boundary);
  return {
    entries: page,
    next_cursor: start > 0 ? encodeHistoryCursor(start, entries.length) : null,
    truncated: start > 0,
  };
}

interface JsonlLine {
  lineIndex: number;
  rec: Record<string, unknown>;
}

interface TextExtraction {
  content: string;
  content_truncated?: true;
  omitted?: SessionHistoryEntry["omitted"];
}

interface MutableEntry {
  entry_id: string;
  role: HistoryRole;
  content: string;
  content_truncated?: true;
  tool_calls?: SessionToolCall[];
  omitted?: SessionHistoryEntry["omitted"];
  created_at: string | null;
}

interface ToolResult {
  output: string;
  status: ToolStatus;
}

interface ToolEnrichment {
  lineIndex: number;
  timestamp: unknown;
  callId: string | null;
  name: string;
  output: string;
  status: ToolStatus;
}

const OMITTED_ORDER: readonly OmittedKind[] = ["image", "document", "thinking", "fallback", "other"];

function buildClaudeHistoryEntries(lines: readonly JsonlLine[], sessionId: string): SessionHistoryEntry[] {
  const resultById = new Map<string, ToolResult>();
  for (const line of lines) {
    const message = objectField(line.rec, "message");
    const content = message?.content;
    for (const block of arrayBlocks(content)) {
      if (stringField(block, "type") !== "tool_result") continue;
      const id = stringField(block, "tool_use_id");
      if (id && !resultById.has(id)) resultById.set(id, claudeToolResult(block));
    }
  }

  const entries: SessionHistoryEntry[] = [];
  for (const line of lines) {
    if (line.rec.type !== "user" && line.rec.type !== "assistant") continue;
    const message = objectField(line.rec, "message");
    const role = message?.role === "user" || message?.role === "assistant" ? message.role : null;
    if (!role) continue;

    const contentValue = message?.content;
    if (role === "user" && isOnlyClaudeToolResults(contentValue)) continue;

    const text = extractClaudeText(contentValue);
    const entry: MutableEntry = {
      entry_id: entryId("claude", sessionId, line.lineIndex),
      role,
      content: text.content,
      created_at: isoFromUnknown(line.rec.timestamp),
    };
    if (text.content_truncated) entry.content_truncated = true;
    if (text.omitted && text.omitted.length > 0) entry.omitted = text.omitted;

    if (role === "assistant") {
      const calls = claudeToolCalls(contentValue, resultById).slice(0, HISTORY_PAGE_MAX);
      if (calls.length > 0) entry.tool_calls = calls;
    }

    entries.push(entry);
  }
  return entries;
}

function buildCodexHistoryEntries(lines: readonly JsonlLine[], sessionId: string): SessionHistoryEntry[] {
  const resultById = new Map<string, ToolResult>();
  const enrichmentsById = new Map<string, ToolEnrichment[]>();
  const callIds = new Set<string>();

  for (const line of lines) {
    const payload = objectField(line.rec, "payload");
    if (!payload) continue;
    const payloadType = stringField(payload, "type");

    if (line.rec.type === "response_item" && (payloadType === "function_call" || payloadType === "custom_tool_call")) {
      const id = stringField(payload, "call_id");
      if (id) callIds.add(id);
      continue;
    }

    if (line.rec.type === "response_item" && (payloadType === "function_call_output" || payloadType === "custom_tool_call_output")) {
      const id = stringField(payload, "call_id");
      if (id && !resultById.has(id)) resultById.set(id, codexToolResult(payload));
      continue;
    }

    const enrichment = codexEnrichment(line);
    if (enrichment?.callId) {
      const existing = enrichmentsById.get(enrichment.callId) ?? [];
      existing.push(enrichment);
      enrichmentsById.set(enrichment.callId, existing);
    }
  }

  const entries: MutableEntry[] = [];
  let currentAssistant: MutableEntry | null = null;

  for (const line of lines) {
    const payload = objectField(line.rec, "payload");
    if (!payload) continue;
    const payloadType = stringField(payload, "type");

    if (line.rec.type === "response_item" && payloadType === "message") {
      if (payload.role !== "user" && payload.role !== "assistant") continue;
      const role = payload.role;
      const text = extractCodexMessageText(payload.content);
      const entry: MutableEntry = {
        entry_id: entryId("codex", sessionId, line.lineIndex),
        role,
        content: text.content,
        created_at: isoFromUnknown(line.rec.timestamp),
      };
      if (text.content_truncated) entry.content_truncated = true;
      if (text.omitted && text.omitted.length > 0) entry.omitted = text.omitted;
      entries.push(entry);
      currentAssistant = role === "assistant" ? entry : null;
      continue;
    }

    if (line.rec.type === "response_item" && (payloadType === "function_call" || payloadType === "custom_tool_call")) {
      const call = codexToolCall(payload, resultById, enrichmentsById);
      if (!call) continue;
      const owner = currentAssistant ?? createSyntheticAssistantEntry(entries, "codex", sessionId, line);
      owner.tool_calls = [...(owner.tool_calls ?? []), call].slice(0, HISTORY_PAGE_MAX);
      currentAssistant = owner;
      continue;
    }

    const enrichment = codexEnrichment(line);
    if (enrichment && (!enrichment.callId || !callIds.has(enrichment.callId))) {
      const owner = currentAssistant ?? createSyntheticAssistantEntry(entries, "codex", sessionId, line);
      const synthetic = syntheticCodexToolCall(enrichment);
      owner.tool_calls = [...(owner.tool_calls ?? []), synthetic].slice(0, HISTORY_PAGE_MAX);
      currentAssistant = owner;
    }
  }

  return entries;
}

function parseJsonlLines(content: string): JsonlLine[] {
  const out: JsonlLine[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (raw === undefined || raw.trim().length === 0) continue;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) out.push({ lineIndex: i, rec: parsed as Record<string, unknown> });
    } catch {
      /* Ignore malformed JSONL records; they are not valid history turns. */
    }
  }
  return out;
}

function extractClaudeText(content: unknown): TextExtraction {
  if (typeof content === "string") return capContent(cleanText(content));
  const textParts: string[] = [];
  const omitted = newOmittedCounts();

  for (const block of arrayBlocks(content)) {
    const type = stringField(block, "type");
    if (type === "text") {
      pushTextPart(textParts, blockText(block));
      continue;
    }
    if (type === "tool_use" || type === "tool_result") continue;
    countOmitted(omitted, omittedKind(type));
  }

  return { ...capContent(joinTextParts(textParts)), omitted: omittedList(omitted) };
}

function extractCodexMessageText(content: unknown): TextExtraction {
  if (typeof content === "string") return capContent(cleanText(content));
  const textParts: string[] = [];
  const omitted = newOmittedCounts();

  for (const block of arrayBlocks(content)) {
    const type = stringField(block, "type");
    if (type === "input_text" || type === "output_text" || type === "text") {
      pushTextPart(textParts, blockText(block));
      continue;
    }
    countOmitted(omitted, omittedKind(type));
  }

  return { ...capContent(joinTextParts(textParts)), omitted: omittedList(omitted) };
}

function claudeToolCalls(content: unknown, resultById: ReadonlyMap<string, ToolResult>): SessionToolCall[] {
  const out: SessionToolCall[] = [];
  for (const block of arrayBlocks(content)) {
    if (stringField(block, "type") !== "tool_use") continue;
    const id = stringField(block, "id");
    const name = stringField(block, "name");
    if (!id || !name) continue;
    out.push(buildToolCall({ id, name, inputValue: block.input, result: resultById.get(id), enrichments: [] }));
  }
  return out;
}

function claudeToolResult(block: Record<string, unknown>): ToolResult {
  return {
    output: toolValueToString(block.content ?? block.output ?? block.text),
    status: statusFromPayload(block),
  };
}

function codexToolCall(
  payload: Record<string, unknown>,
  resultById: ReadonlyMap<string, ToolResult>,
  enrichmentsById: ReadonlyMap<string, readonly ToolEnrichment[]>,
): SessionToolCall | null {
  const id = stringField(payload, "call_id");
  const name = stringField(payload, "name");
  if (!id || !name) return null;
  const inputValue = payload.type === "custom_tool_call" ? payload.input : payload.arguments;
  return buildToolCall({
    id,
    name,
    inputValue,
    result: resultById.get(id),
    enrichments: enrichmentsById.get(id) ?? [],
  });
}

function codexToolResult(payload: Record<string, unknown>): ToolResult {
  return {
    output: toolValueToString(payload.output ?? payload.formatted_output),
    status: statusFromPayload(payload),
  };
}

function buildToolCall(args: {
  id: string;
  name: string;
  inputValue: unknown;
  result: ToolResult | undefined;
  enrichments: readonly ToolEnrichment[];
}): SessionToolCall {
  const call: SessionToolCall = { id: args.id, name: args.name };
  const input = capToolIo(toolValueToString(args.inputValue));
  if (input.value.length > 0) call.input = input.value;
  if (input.truncated) call.input_truncated = true;

  const combined = combinedToolResult(args.result, args.enrichments);
  if (combined) {
    const output = capToolIo(combined.output);
    if (output.value.length > 0) call.output = output.value;
    if (output.truncated) call.output_truncated = true;
    call.status = combined.status;
  }

  return call;
}

function combinedToolResult(result: ToolResult | undefined, enrichments: readonly ToolEnrichment[]): ToolResult | null {
  if (!result && enrichments.length === 0) return null;
  const parts = [result?.output ?? "", ...enrichments.map((e) => e.output)].filter((part) => part.length > 0);
  const status = result?.status === "error" || enrichments.some((e) => e.status === "error") ? "error" : "ok";
  return { output: parts.join("\n"), status };
}

function syntheticCodexToolCall(enrichment: ToolEnrichment): SessionToolCall {
  const output = capToolIo(enrichment.output);
  const call: SessionToolCall = {
    id: enrichment.callId ?? `call_${createHash("sha256").update(`${enrichment.name}\0${enrichment.lineIndex}`).digest("hex").slice(0, 24)}`,
    name: enrichment.name,
    status: enrichment.status,
  };
  if (output.value.length > 0) call.output = output.value;
  if (output.truncated) call.output_truncated = true;
  return call;
}

function codexEnrichment(line: JsonlLine): ToolEnrichment | null {
  if (line.rec.type !== "event_msg" && line.rec.type !== "response_item") return null;
  const payload = objectField(line.rec, "payload");
  const type = stringField(payload, "type");
  if (type !== "patch_apply_end" && type !== "exec_command_end") return null;
  return {
    lineIndex: line.lineIndex,
    timestamp: line.rec.timestamp,
    callId: stringField(payload, "call_id"),
    name: type === "patch_apply_end" ? "apply_patch" : "exec_command",
    output: summarizeCodexEnrichment(payload),
    status: statusFromPayload(payload),
  };
}

function summarizeCodexEnrichment(payload: Record<string, unknown> | null): string {
  if (!payload) return "";
  const type = stringField(payload, "type") ?? "tool_event";
  const parts = [type];
  const status = stringField(payload, "status");
  if (status) parts.push(`status=${status}`);
  if (typeof payload.success === "boolean") parts.push(`success=${payload.success}`);
  if (typeof payload.exit_code === "number") parts.push(`exit_code=${payload.exit_code}`);
  const changes = payload.changes === undefined ? "" : safeStringify(payload.changes);
  if (changes) parts.push(`changes=${changes}`);
  const stdout = toolValueToString(payload.stdout);
  if (stdout.length > 0) parts.push(`stdout=${stdout}`);
  const stderr = toolValueToString(payload.stderr);
  if (stderr.length > 0) parts.push(`stderr=${stderr}`);
  return parts.join(" ");
}

function createSyntheticAssistantEntry(entries: MutableEntry[], engine: HistoryEngine, sessionId: string, line: JsonlLine): MutableEntry {
  const entry: MutableEntry = {
    entry_id: entryId(engine, sessionId, line.lineIndex),
    role: "assistant",
    content: "",
    created_at: isoFromUnknown(line.rec.timestamp),
  };
  entries.push(entry);
  return entry;
}

function isOnlyClaudeToolResults(content: unknown): boolean {
  const blocks = arrayBlocks(content);
  return blocks.length > 0 && blocks.every((block) => stringField(block, "type") === "tool_result");
}

function capContent(value: string): TextExtraction {
  const capped = capString(value, HISTORY_CONTENT_CAP);
  return capped.truncated ? { content: capped.value, content_truncated: true } : { content: capped.value };
}

function capToolIo(value: string): { value: string; truncated?: true } {
  const capped = capString(value, HISTORY_TOOL_IO_CAP);
  return capped.truncated ? { value: capped.value, truncated: true } : { value: capped.value };
}

function capString(value: string, cap: number): { value: string; truncated: boolean } {
  return value.length > cap ? { value: value.slice(0, cap), truncated: true } : { value, truncated: false };
}

function entryId(engine: HistoryEngine, sessionId: string, startLineIndex: number): string {
  return `e_${createHash("sha256").update(`${engine}\0${sessionId}\0${startLineIndex}`).digest("hex").slice(0, 24)}`;
}

function encodeHistoryCursor(boundary: number, sig: number): string {
  return Buffer.from(JSON.stringify({ b: boundary, sig }), "utf8").toString("base64url");
}

function decodeHistoryCursor(cursor: string, entryCount: number): { b: number; sig: number } {
  if (!/^[A-Za-z0-9_-]+$/.test(cursor)) throw new HistoryCursorError();
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
  } catch {
    throw new HistoryCursorError();
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new HistoryCursorError();
  const obj = parsed as Record<string, unknown>;
  if (!Number.isInteger(obj.b) || !Number.isInteger(obj.sig)) throw new HistoryCursorError();
  const b = obj.b as number;
  const sig = obj.sig as number;
  if (b < 0 || b > entryCount || sig < 0) throw new HistoryCursorError();
  return { b, sig };
}

function clampLimit(limit: number | undefined): number {
  if (limit === undefined || !Number.isFinite(limit)) return HISTORY_PAGE_DEFAULT;
  return Math.max(1, Math.min(Math.trunc(limit), HISTORY_PAGE_MAX));
}

function cleanText(value: string): string {
  return value.trim();
}

function pushTextPart(parts: string[], value: string | null): void {
  const cleaned = value?.trim();
  if (cleaned) parts.push(cleaned);
}

function joinTextParts(parts: readonly string[]): string {
  return parts.join("\n");
}

function blockText(block: Record<string, unknown>): string | null {
  return stringFromUnknown(block.text) ?? stringFromUnknown(block.content);
}

function arrayBlocks(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  return value.filter((part): part is Record<string, unknown> => Boolean(part) && typeof part === "object" && !Array.isArray(part));
}

function newOmittedCounts(): Record<OmittedKind, number> {
  return { image: 0, document: 0, thinking: 0, fallback: 0, other: 0 };
}

function countOmitted(counts: Record<OmittedKind, number>, kind: OmittedKind | null): void {
  if (kind) counts[kind]++;
}

function omittedList(counts: Record<OmittedKind, number>): SessionHistoryEntry["omitted"] {
  return OMITTED_ORDER.flatMap((kind) => {
    const count = counts[kind];
    return count > 0 ? [{ kind, count }] : [];
  });
}

function omittedKind(type: string | null): OmittedKind {
  if (type === "image" || type === "input_image" || type === "image_url") return "image";
  if (type === "document" || type === "input_file" || type === "file") return "document";
  if (type === "thinking" || type === "reasoning") return "thinking";
  if (type === "fallback") return "fallback";
  return "other";
}

function toolValueToString(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") return String(value);
  if (Array.isArray(value)) {
    const textParts = value
      .map((part) => {
        if (typeof part === "string") return part;
        if (part && typeof part === "object" && !Array.isArray(part)) {
          const obj = part as Record<string, unknown>;
          const type = stringField(obj, "type");
          if (type === "text" || type === "input_text" || type === "output_text") return blockText(obj);
        }
        return null;
      })
      .filter((part): part is string => part !== null);
    if (textParts.length > 0) return textParts.join("\n");
  }
  return safeStringify(value);
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return String(value);
  }
}

function statusFromPayload(payload: Record<string, unknown> | null): ToolStatus {
  if (!payload) return "ok";
  if (payload.is_error === true || payload.success === false) return "error";
  const status = stringField(payload, "status")?.toLowerCase();
  if (status === "error" || status === "failed" || status === "failure") return "error";
  const exitCode = payload.exit_code;
  if (typeof exitCode === "number" && exitCode !== 0) return "error";
  return "ok";
}

function stringField(obj: Record<string, unknown> | null | undefined, key: string): string | null {
  return stringFromUnknown(obj?.[key]);
}

function stringFromUnknown(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function objectField(obj: Record<string, unknown> | null | undefined, key: string): Record<string, unknown> | null {
  const value = obj?.[key];
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function isoFromUnknown(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}
