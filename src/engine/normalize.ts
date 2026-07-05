/**
 * Normalize Claude Code `--output-format stream-json` lines into the daemon's
 * `EngineEvent`s (core EventKind where known; `vendor.claude.*` otherwise). One
 * stream line can yield several events (an assistant message = text + tool_use).
 * Kept adapter-local and defensive — unknown shapes never throw, they pass
 * through opaquely under the vendor namespace.
 */

import type { EngineEvent } from "./types";

interface ContentBlock {
  type?: string;
  text?: string;
  name?: string;
  id?: string;
  input?: unknown;
  tool_use_id?: string;
  is_error?: boolean;
  content?: unknown;
}

interface StreamLine {
  type?: string;
  subtype?: string;
  message?: { role?: string; content?: ContentBlock[] | string; usage?: unknown; model?: string };
  usage?: unknown;
  total_cost_usd?: number;
  duration_ms?: number;
  is_error?: boolean;
}

/** `vendor.claude.<suffix>` sanitized to the EventKind vendor grammar
 *  (`[a-z0-9_.]+`) so the resulting `stream.event` always parses. */
function vendorKind(engine: "claude" | "codex", suffix: string): string {
  return `vendor.${engine}.${(suffix || "unknown").toLowerCase().replace(/[^a-z0-9_.]/g, "_")}`;
}

export function normalizeClaudeLine(raw: unknown): EngineEvent[] {
  if (!raw || typeof raw !== "object") return [];
  const line = raw as StreamLine;
  switch (line.type) {
    case "system":
      return [{ kind: "system_status", subtype: line.subtype ?? "system" }];

    case "assistant": {
      const events: EngineEvent[] = [];
      const content = line.message?.content;
      if (Array.isArray(content)) {
        for (const b of content) {
          if (b.type === "text" && typeof b.text === "string") {
            events.push({ kind: "assistant_text", text: b.text });
          } else if (b.type === "tool_use") {
            events.push({ kind: "tool_use", tool_name: b.name, tool_use_id: b.id, input: b.input });
          } else {
            events.push({ kind: vendorKind("claude", `assistant_${b.type ?? "block"}`), block: b });
          }
        }
      } else if (typeof content === "string") {
        events.push({ kind: "assistant_text", text: content });
      }
      if (line.message?.usage) events.push({ kind: "usage", usage: line.message.usage });
      return events;
    }

    case "user": {
      const events: EngineEvent[] = [];
      const content = line.message?.content;
      if (Array.isArray(content)) {
        for (const b of content) {
          if (b.type === "tool_result") {
            events.push({ kind: "tool_result", tool_use_id: b.tool_use_id, is_error: b.is_error ?? false, content: b.content });
          } else {
            events.push({ kind: vendorKind("claude", `user_${b.type ?? "block"}`), block: b });
          }
        }
      }
      return events;
    }

    case "result":
      return [
        {
          kind: "usage",
          subtype: line.subtype,
          usage: line.usage,
          cost_usd: line.total_cost_usd,
          duration_ms: line.duration_ms,
          is_error: line.is_error ?? false,
        },
      ];

    default:
      return [{ kind: vendorKind("claude", line.type ?? "unknown"), raw: line }];
  }
}

interface CodexLine {
  type?: unknown;
  payload?: unknown;
  role?: unknown;
  content?: unknown;
  message?: unknown;
  item?: unknown;
  delta?: unknown;
  usage?: unknown;
}

export function normalizeCodexLine(raw: unknown): EngineEvent[] {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return [];
  const line = raw as CodexLine;
  const lineType = stringValue(line.type);
  const payload = objectValue(line.payload);
  const candidate = payload ?? objectValue(line.item) ?? objectValue(line.delta) ?? (raw as Record<string, unknown>);
  const candidateType = stringValue(candidate.type);

  const text = codexAssistantText(candidate);
  if (text) return [{ kind: "assistant_text", text }];

  if (isCodexFunctionCall(candidate)) {
    return [
      {
        kind: "tool_use",
        tool_name: stringValue(candidate.name),
        tool_use_id: stringValue(candidate.call_id) ?? stringValue(candidate.id),
        input: candidate.arguments ?? candidate.input,
      },
    ];
  }

  if (candidateType === "function_call_output") {
    return [
      {
        kind: "tool_result",
        tool_use_id: stringValue(candidate.call_id) ?? stringValue(candidate.id),
        is_error: booleanValue(candidate.is_error) ?? false,
        content: candidate.output ?? candidate.content,
      },
    ];
  }

  if (candidateType === "token_count" || candidate.usage || line.usage) {
    return [{ kind: "usage", usage: candidate.usage ?? line.usage ?? candidate.info ?? candidate }];
  }

  return [{ kind: vendorKind("codex", [lineType, candidateType].filter(Boolean).join("_") || "unknown"), raw: line }];
}

function codexAssistantText(item: Record<string, unknown>): string {
  const itemType = stringValue(item.type);
  if ((itemType === "agent_message" || itemType === "assistant_message") && typeof item.message === "string") {
    return item.message;
  }
  if (itemType === "message" && item.role === "assistant") return codexContentText(item.content);
  if ((item.role === "assistant" || itemType === "assistant") && typeof item.message === "string") return item.message;
  return "";
}

function codexContentText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((part) => {
      if (!part || typeof part !== "object" || Array.isArray(part)) return null;
      const block = part as { type?: unknown; text?: unknown };
      const type = stringValue(block.type);
      if ((type === "output_text" || type === "text") && typeof block.text === "string") return block.text;
      return null;
    })
    .filter((part): part is string => part !== null)
    .join("");
}

function isCodexFunctionCall(item: Record<string, unknown>): boolean {
  return stringValue(item.type) === "function_call" || typeof item.name === "string";
}

function objectValue(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function stringValue(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function booleanValue(v: unknown): boolean | undefined {
  return typeof v === "boolean" ? v : undefined;
}
