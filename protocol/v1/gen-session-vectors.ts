/**
 * v2 session.* schema-conformance test vectors (generator).
 * =========================================================
 *
 *   tsx protocol/v1/gen-session-vectors.ts  # (re)writes ./session-test-vectors.json
 *
 * Emits deterministic JSON fixtures for the current v2 session.* surface.
 * These are NOT frozen-ABI vectors; messages.ts remains the single source of
 * truth, and JSON key order/whitespace is not wire-normative.
 *
 * `selftest.ts` imports the types below (no side effect on import - the file
 * write is guarded to direct invocation) and verifies the COMMITTED JSON:
 * positives must parse through safeParseMessageV2, negatives must reject, and
 * stored canonical strings must be deterministic JCS.
 */

import { realpathSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { jcsCanonicalize } from "./digest";
import {
  PROTOCOL_VERSION,
  safeParseMessage,
  safeParseMessageV2,
  type MessageV2,
  type MessageV2Type,
} from "./messages";

// ---------------------------------------------------------------------------
// Vector shapes
// ---------------------------------------------------------------------------

export type SessionVectorType = Extract<MessageV2Type, `session.${string}`>;
export type SessionPositiveMessage = Extract<MessageV2, { type: SessionVectorType }>;

export interface SessionPositiveVector {
  label: string;
  type: SessionVectorType;
  message: SessionPositiveMessage;
  canonical: string;
}

export type SessionNegativeReason =
  | "non-positive-int"
  | "null-on-non-nullable"
  | "strict-unknown-field"
  | "bad-event-kind"
  | "v1-rejects-session-cap";

export interface SessionNegativeVector {
  label: string;
  reason: SessionNegativeReason;
  raw: unknown;
}

export interface SessionVectorsFile {
  meta: string;
  positives: SessionPositiveVector[];
  negatives: SessionNegativeVector[];
}

// ---------------------------------------------------------------------------
// Fixed inputs
// ---------------------------------------------------------------------------

const META =
  "v2 schema-conformance fixtures generated from messages.ts. messages.ts is SSOT. JSON key order/whitespace is NOT wire-normative. NOT a frozen ABI — session.* is additive/evolving v2 surface.";
const TS = "2026-01-01T00:00:00.000Z";
const TS_LATER = "2026-01-01T00:01:00.000Z";
const SIG = "A".repeat(86);

const REQUIRED_SESSION_TYPES = [
  "session.list.request",
  "session.list.response",
  "session.resume.request",
  "session.resume.accept",
  "session.resume.reject",
  "session.event",
  "session.ack",
  "session.turn.result",
  "session.message",
  "session.cancel",
  "session.error",
] as const satisfies readonly SessionVectorType[];

function base(id: string) {
  return { id, ts: TS };
}

const sessionInfoFull = {
  handle: "sess-main",
  session_id: "s_0123456789abcdef0123456789abcdef",
  engine: "codex",
  cwd: "/work/repo",
  git_branch: "main",
  cli_version: "0.140.0",
  title: "Investigate failing test",
  created_at: TS,
  updated_at: TS_LATER,
  active: true,
  msg_count: 3,
} as const;

const sessionInfoNulls = {
  handle: "sess-no-meta",
  session_id: "s_fedcba9876543210fedcba9876543210",
  engine: "claude",
  cwd: "/work/other",
  git_branch: null,
  cli_version: null,
  title: "Draft migration plan",
  created_at: TS,
  updated_at: TS_LATER,
  active: false,
  msg_count: 1,
} as const;

function issueSummary(error: { issues: Array<{ path: PropertyKey[]; message: string }> }): string {
  return error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join("; ");
}

function positive(label: string, message: SessionPositiveMessage): SessionPositiveVector {
  const result = safeParseMessageV2(message);
  if (!result.success) {
    throw new Error(`positive ${label}: ${issueSummary(result.error)}`);
  }
  if (result.data.type !== message.type || !message.type.startsWith("session.")) {
    throw new Error(`positive ${label}: parsed discriminator mismatch`);
  }
  return {
    label,
    type: message.type,
    message,
    canonical: jcsCanonicalize(message),
  };
}

function negative(label: string, reason: SessionNegativeReason, raw: unknown): SessionNegativeVector {
  return { label, reason, raw };
}

function buildNegatives(): SessionNegativeVector[] {
  const ack = {
    ...base("m-session-neg-ack"),
    type: "session.ack",
    turn_id: "turn-main",
    ack_seq: 1,
  };
  const event = {
    ...base("m-session-neg-event"),
    type: "session.event",
    turn_id: "turn-main",
    seq: 1,
    event: { kind: "assistant_text", text: "hello" },
  };
  const listRequest = {
    ...base("m-session-neg-list"),
    type: "session.list.request",
    request_id: "req-list-neg",
  };
  const resumeRequest = {
    ...base("m-session-neg-resume"),
    type: "session.resume.request",
    request_id: "req-resume-neg",
    handle: "sess-main",
    message: "Continue from the last step.",
  };
  const helloWithSessionCapability = {
    ...base("m-session-neg-hello"),
    type: "hello",
    protocol_version: PROTOCOL_VERSION,
    agent_id: "agent-abc",
    agent_version: PROTOCOL_VERSION,
    auth: { challenge_id: "ch-1", key_id: "key-1", signature: SIG, alg: "ed25519" },
    os: { platform: "darwin", arch: "arm64", release: "25.5.0" },
    capabilities: {
      engines: {
        claude: { installed: true, version: "2.1.170", logged_in: true },
        codex: { installed: true, version: "0.140.0", logged_in: false },
      },
      project_roots: ["/work/repo"],
      sessions: { supported: true },
    },
    active_jobs: [],
    pending_results: [],
  };

  return [
    negative("session.ack-ack_seq-zero", "non-positive-int", { ...ack, ack_seq: 0 }),
    negative("session.event-seq-zero", "non-positive-int", { ...event, seq: 0 }),
    negative("session.list.request-page-limit-zero", "non-positive-int", {
      ...listRequest,
      page: { limit: 0 },
    }),
    negative("session.list.request-filter-engine-null", "null-on-non-nullable", {
      ...listRequest,
      filter: { engine: null },
    }),
    negative("session.resume.request-options-model-null", "null-on-non-nullable", {
      ...resumeRequest,
      options: { model: null },
    }),
    negative("session.ack-unknown-top-level-field", "strict-unknown-field", {
      ...ack,
      unexpected: true,
    }),
    negative("session.event-kind-not-a-kind", "bad-event-kind", {
      ...event,
      event: { kind: "not.a.kind" },
    }),
    negative("session.event-kind-vendor-gemini", "bad-event-kind", {
      ...event,
      event: { kind: "vendor.gemini.foo" },
    }),
    negative("v1-hello-capabilities-sessions", "v1-rejects-session-cap", helloWithSessionCapability),
  ];
}

export function buildSessionVectors(): SessionVectorsFile {
  const positives: SessionPositiveVector[] = [
    positive("session.list.request-filter-omitted-page-omitted", {
      ...base("m-session-list-req-1"),
      type: "session.list.request",
      request_id: "req-list-1",
    }),
    positive("session.list.request-filter-present-page-present", {
      ...base("m-session-list-req-2"),
      type: "session.list.request",
      request_id: "req-list-2",
      filter: { engine: "codex", cwd_prefix: "/work", active_only: true, updated_after: TS },
      page: { cursor: "cursor-1", limit: 2 },
    }),
    positive("session.list.response-empty-next-cursor-string", {
      ...base("m-session-list-resp-1"),
      type: "session.list.response",
      request_id: "req-list-1",
      sessions: [],
      next_cursor: "cursor-2",
      truncated: true,
    }),
    positive("session.list.response-one-session-next-cursor-null", {
      ...base("m-session-list-resp-2"),
      type: "session.list.response",
      request_id: "req-list-2",
      sessions: [sessionInfoFull],
      next_cursor: null,
      truncated: false,
    }),
    positive("session.list.response-one-session-next-cursor-omitted", {
      ...base("m-session-list-resp-3"),
      type: "session.list.response",
      request_id: "req-list-3",
      sessions: [sessionInfoNulls],
      truncated: false,
    }),
    positive("session.resume.request-options-omitted", {
      ...base("m-session-resume-req-1"),
      type: "session.resume.request",
      request_id: "req-resume-1",
      handle: "sess-main",
      message: "Continue from the last checkpoint.",
    }),
    positive("session.resume.request-options-present", {
      ...base("m-session-resume-req-2"),
      type: "session.resume.request",
      request_id: "req-resume-2",
      handle: "sess-main",
      message: "Fork this session and run the migration tests.",
      options: { fork: true, sandbox: "workspace_write", model: "codex-large" },
    }),
    positive("session.cancel", {
      ...base("m-session-cancel-1"),
      type: "session.cancel",
      turn_id: "turn-main",
    }),
    positive("session.ack", {
      ...base("m-session-ack-1"),
      type: "session.ack",
      turn_id: "turn-main",
      ack_seq: 4,
    }),
    positive("session.message", {
      ...base("m-session-message-1"),
      type: "session.message",
      request_id: "req-message-1",
      handle: "sess-main",
      message: "Please inspect the failing snapshot.",
    }),
    positive("session.resume.accept-effective-options-mutates-source", {
      ...base("m-session-resume-accept-1"),
      type: "session.resume.accept",
      request_id: "req-resume-1",
      turn_id: "turn-main",
      effective_options: { fork: true, sandbox: "workspace_write", mutates_source: true },
    }),
    positive("session.resume.accept-effective-options-mutates-source-omitted", {
      ...base("m-session-resume-accept-2"),
      type: "session.resume.accept",
      request_id: "req-resume-2",
      turn_id: "turn-readonly",
      effective_options: { fork: false, sandbox: "read_only" },
    }),
    positive("session.resume.accept-effective-options-omitted", {
      ...base("m-session-resume-accept-3"),
      type: "session.resume.accept",
      request_id: "req-resume-3",
      turn_id: "turn-default",
    }),
    positive("session.resume.reject", {
      ...base("m-session-resume-reject-1"),
      type: "session.resume.reject",
      request_id: "req-resume-4",
      code: "unknown_session",
      message: "Session handle was not found.",
    }),
    positive("session.event-core-kind", {
      ...base("m-session-event-1"),
      type: "session.event",
      turn_id: "turn-main",
      seq: 1,
      event: { kind: "assistant_text", text: "I will check the failing case." },
    }),
    positive("session.event-vendor-kind", {
      ...base("m-session-event-2"),
      type: "session.event",
      turn_id: "turn-main",
      seq: 2,
      event: { kind: "vendor.codex.reasoning_delta", delta: { tokens: 12 } },
    }),
    positive("session.turn.result-new-session-handle-string", {
      ...base("m-session-turn-result-1"),
      type: "session.turn.result",
      turn_id: "turn-main",
      status: "ok",
      final_message: "Created a forked session.",
      new_session_handle: "sess-fork",
    }),
    positive("session.turn.result-new-session-handle-null", {
      ...base("m-session-turn-result-2"),
      type: "session.turn.result",
      turn_id: "turn-readonly",
      status: "cancelled",
      final_message: "Cancelled before creating a new session.",
      new_session_handle: null,
    }),
    positive("session.turn.result-new-session-handle-omitted", {
      ...base("m-session-turn-result-3"),
      type: "session.turn.result",
      turn_id: "turn-default",
      status: "error",
      final_message: "The engine returned an error.",
    }),
    positive("session.error-request-id-only", {
      ...base("m-session-error-1"),
      type: "session.error",
      request_id: "req-resume-5",
      code: "invalid_request",
      message: "The requested session is inactive.",
    }),
    positive("session.error-turn-id-only", {
      ...base("m-session-error-2"),
      type: "session.error",
      turn_id: "turn-main",
      code: "engine_error",
      message: "The engine process exited unexpectedly.",
    }),
  ];

  const negatives = buildNegatives();
  const seen = new Set(positives.map((v) => v.type));
  for (const type of REQUIRED_SESSION_TYPES) {
    if (!seen.has(type)) throw new Error(`missing positive vector for ${type}`);
  }

  for (const v of positives) {
    const reparsed = JSON.parse(v.canonical) as unknown;
    if (jcsCanonicalize(reparsed) !== v.canonical) {
      throw new Error(`positive ${v.label}: stored canonical is not deterministic`);
    }
  }
  for (const v of negatives) {
    if (safeParseMessageV2(v.raw).success) {
      throw new Error(`negative ${v.label}: accepted by safeParseMessageV2`);
    }
    if (v.reason === "v1-rejects-session-cap" && safeParseMessage(v.raw).success) {
      throw new Error(`negative ${v.label}: accepted by safeParseMessage`);
    }
  }

  return { meta: META, positives, negatives };
}

// ---------------------------------------------------------------------------
// Write only when invoked directly (no side effect when imported by selftest).
// ---------------------------------------------------------------------------

/** True iff this module is the entry script. Compares realpaths (not file URLs)
 *  so a symlinked `tsx`/script invocation still resolves to this module; when
 *  selftest imports it the paths differ -> no write. */
function invokedDirectly(): boolean {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return fileURLToPath(import.meta.url) === realpathSync(argv1);
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  const out = new URL("./session-test-vectors.json", import.meta.url);
  const data = buildSessionVectors();
  writeFileSync(out, `${JSON.stringify(data, null, 2)}\n`);
  console.log(`wrote ${fileURLToPath(out)} (${data.positives.length} positive, ${data.negatives.length} negative)`);
}
