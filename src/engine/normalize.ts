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
function vendorKind(suffix: string): string {
  return `vendor.claude.${(suffix || "unknown").toLowerCase().replace(/[^a-z0-9_.]/g, "_")}`;
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
            events.push({ kind: vendorKind(`assistant_${b.type ?? "block"}`), block: b });
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
            events.push({ kind: vendorKind(`user_${b.type ?? "block"}`), block: b });
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
      return [{ kind: vendorKind(line.type ?? "unknown"), raw: line }];
  }
}
