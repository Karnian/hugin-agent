/**
 * The SINGLE inbound parse path (plan §5.1): size-check → JSON.parse → schema
 * (zod) → direction/phase (`validateInbound`). Nothing inbound bypasses this.
 */

import { LIMITS, type Message, safeParseMessage, validateInbound } from "../../protocol/v1/index";

export type DecodeResult =
  | { ok: true; msg: Message }
  | {
      ok: false;
      code: "payload_too_large" | "invalid_message" | "bad_direction" | "bad_state";
      reason: string;
    };

export function decodeInbound(
  raw: Buffer | string,
  opts: { receiver: "agent" | "server"; authed: boolean },
): DecodeResult {
  // 1. Size BEFORE parse — never parse a frame to discover it's too large.
  const bytes = typeof raw === "string" ? Buffer.byteLength(raw, "utf8") : raw.length;
  if (bytes > LIMITS.MAX_FRAME_BYTES) {
    return { ok: false, code: "payload_too_large", reason: `frame ${bytes}B > ${LIMITS.MAX_FRAME_BYTES}B` };
  }
  // 2. JSON.
  let json: unknown;
  try {
    json = JSON.parse(typeof raw === "string" ? raw : raw.toString("utf8"));
  } catch {
    return { ok: false, code: "invalid_message", reason: "invalid JSON" };
  }
  // 3. Schema.
  const parsed = safeParseMessage(json);
  if (!parsed.success) {
    return {
      ok: false,
      code: "invalid_message",
      reason: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "),
    };
  }
  // 4. Direction + handshake phase.
  const dir = validateInbound(parsed.data, opts);
  if (!dir.ok) return { ok: false, code: dir.code, reason: dir.code };
  return { ok: true, msg: parsed.data };
}

export function encodeOutbound(msg: Message): string {
  return JSON.stringify(msg);
}
