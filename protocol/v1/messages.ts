/**
 * Hugin Agent — Wire protocol v1.0.0 (FROZEN)
 * =========================================================
 *
 * Single source of truth for the WSS JSON contract shared between:
 *   - the local daemon  (`hugind`, "agent")          — runs behind NAT, dials out
 *   - the cloud relay   ("server" / orchestrator)    — assigns jobs, collects events
 *
 * Transport: one JSON object per WebSocket text frame. TLS is mandatory.
 *
 * Design principles (see ../README.md):
 *   1. Outbound-only. The agent always initiates the connection.
 *   2. At-least-once delivery + idempotent consumers. NOT exactly-once.
 *   3. Lease-based ownership. `lease_id` is the current-generation fencing
 *      token and rides on EVERY attempt-scoped message, both directions.
 *   4. Explicit, digest-acked completion.
 *   5. Versioned + authenticated handshake (auth.challenge → signed hello).
 *   6. Relative durations (`*_ms`) are authoritative; ISO times are audit only.
 *
 * rev 1.3 — folds in two cloud-side reviews (cloud team + Codex):
 *   + lease_id fencing on all attempt-scoped messages (both directions)
 *   + connection_epoch (fence older WSS sessions for the same agent_id)
 *   + REMOVED job.assign.session_id (engine resume is out of MVP scope)
 *   + result digest/size + resend_result resume directive
 *   + decided_by -> remote-only provenance (server can't assert local_user)
 *   + JobReject.policy_violation (agent rejects unsafe assignments, no clamp)
 *   + Ed25519-only + key_id; nonce = 32-byte base64url; *_ms expiries
 *   + strict objects, safe-integer bounds, semver fields, string/array caps
 *   + core event.kind enum + vendor.<engine>.* namespace
 *
 * rev 1.4 — third cross-review:
 *   + lease_id on ResumeDirective (resend_result needs a generation)
 *   + fixed-size crypto fields: Ed25519 signature, SHA-256 digest
 *   + bounded (signed) exit_code
 *
 * rev 1.5 — freeze-readiness fixes:
 *   + exact-length crypto fields (Ed25519 86, SHA-256 43)
 *   + lease rotation overlap window (LIMITS) + PendingResult.lease_id
 *   + ResumeDirective enforces lease_id for resume_from/resend_result
 *
 * rev 1.6 — mechanical pre-freeze pass (cloud F1–F6 + Codex A/B/C):
 *   + nonce exact length 43 (F1); AuthId charset on signed ids (Codex B)
 *   + SemVer deduped into this file + bounded .max(64) (Codex A); SIG_MAX removed
 *   + EventKind core FROZEN for v1 (Option A) — unknown core → NACK (F6)
 *   + F4 cross-language test vectors (v1/gen-vectors.ts → v1/test-vectors.json)
 *
 * v1.0.0 — FROZEN (cloud diff-review verdict: FREEZE-OK, 0 blockers). Tagged from
 * 1.6.0-draft. Pre-tag nits applied: vectors regenerated with the SIGNED
 * protocol_version "1.0.0"; strict Ed25519 negatives (non-canonical S, low-order
 * key, wrong length) + nonce canonical/alphabet negatives added; nonce now must
 * be canonical base64url. A new CORE message/field now requires a major bump (v2).
 *
 * Canonical signing bytes, pairing, key rotation/revocation: see
 * ../../docs/auth-pairing-spec.md (separate security surface).
 *
 * NOTE: FROZEN as v1.0.0. Wire-visible changes now require both sides to agree
 * and (for core additions) a major bump.
 */

import { z } from "zod";

export const PROTOCOL_VERSION = "1.0.0" as const;
export const PROTOCOL_VERSION_V2 = "2.0.0" as const;

// ---------------------------------------------------------------------------
// Operational limits (part of the contract — both sides enforce these)
// ---------------------------------------------------------------------------

export const LIMITS = {
  // Flow control (A4)
  MAX_FRAME_BYTES: 1 << 20, //                      1 MiB per WSS frame
  MAX_UNACKED_BYTES_PER_ATTEMPT: 8 << 20, //        8 MiB
  MAX_UNACKED_EVENTS_PER_ATTEMPT: 1024,
  MAX_UNACKED_BYTES_PER_CONN: 32 << 20, //          32 MiB
  // Stream ack flush, first to trip (A2)
  ACK_FLUSH_MS: 1000,
  ACK_FLUSH_EVENTS: 64,
  ACK_FLUSH_BYTES: 256 << 10, //                    256 KiB
  // Lease (A1)
  LEASE_TTL_MS_DEFAULT: 120_000,
  LEASE_TTL_MS_MIN: 30_000,
  LEASE_TTL_MS_MAX: 300_000,
  LEASE_REASSIGN_GRACE_MS: 30_000,
  LEASE_ROTATION_OVERLAP_MS: 5_000, // accept old+new lease_id during a rotation
  // Heartbeat (A8)
  HEARTBEAT_INTERVAL_MS: 15_000,
  HEARTBEAT_SUSPECT_MISSES: 3,
  HEARTBEAT_DEAD_MISSES: 4,
  HEARTBEAT_DEAD_MS: 60_000,
  // Approval (A3)
  APPROVAL_TIMEOUT_MS_DEFAULT: 300_000,
  APPROVAL_TIMEOUT_MS_MAX: 900_000,
  // Auth (A7)
  CHALLENGE_TTL_MS: 60_000,
  // Payload caps
  MAX_PROMPT_CHARS: 100_000,
} as const;

const ID_MAX = 256;
const TEXT_MAX = 8_192;
const PATH_MAX = 4_096;
const ARRAY_MAX = 256;
const TIMEOUT_MS_MAX = 3_600_000; //                1 hour
const OUTPUT_BYTES_MAX = 100 << 20; //              100 MiB

// ---------------------------------------------------------------------------
// Reusable scalars (all bounded — no unbounded strings or unsafe integers)
// ---------------------------------------------------------------------------

const Iso = z.string().datetime({ offset: true });
const Id = z.string().min(1).max(ID_MAX);
const Text = z.string().max(TEXT_MAX);
const Path = z.string().min(1).max(PATH_MAX);
/** JSON-safe non-negative integer (guards against 2^53 precision loss). */
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const PosInt = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
/** SemVer 2.0 core + optional prerelease, bounded to 64 chars. `+build` metadata
 *  is INTENTIONALLY rejected: build tags must not affect version identity or
 *  negotiation. Single source of truth — index.ts imports this (Codex A). */
export const SemVer = z.string().regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/).max(64);
const Base64Url = z.string().regex(/^[A-Za-z0-9_-]+$/);
/** Charset for ids that enter the signed auth transcript (challenge_id, agent_id,
 *  key_id). ASCII-only, no `:` (avoids IPv6/host ambiguity). A loose `Id` would let
 *  unicode/control chars cause TS-UTF16-vs-Go-byte signature mismatches (Codex B). */
const AuthId = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/);
/** Fixed-size crypto material, base64url unpadded (no `=` padding). */
const Ed25519Sig = Base64Url.length(86); // 64 bytes → exactly 86 chars
const Sha256Digest = Base64Url.length(43); // 32 bytes → exactly 43 chars
/** Signed JSON-safe integer (exit codes may be negative). */
const Int = z.number().int().min(-Number.MAX_SAFE_INTEGER).max(Number.MAX_SAFE_INTEGER);

const JobId = Id.describe("Stable id for a logical job (survives retries).");
const AttemptId = Id.describe("Unique id for ONE execution attempt of a job.");
const LeaseId = Id.describe("Current-generation fencing token; rotates on lease.granted.");
const RequestId = Id;
const MessageId = Id;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export const Engine = z.enum(["claude", "codex"]);
export const Sandbox = z.enum(["read_only", "workspace_write", "full"]);
export const ApprovalPolicy = z.enum(["never", "on_request", "on_write", "always"]);

/** All job states. */
export const JobStatus = z.enum([
  "accepted", "starting", "running", "cancelling", "cancelled", "completed", "failed",
]);

/** Only NON-terminal states are legal inside hello.active_jobs (C4). Terminal
 *  results travel through pending_results, never active_jobs. */
export const ActiveJobStatus = z.enum(["accepted", "starting", "running", "cancelling"]);

/** `rejected` absent: a refused assignment ends at job.reject. `timeout` is a
 *  terminal reason carried by job.result; its last JobStatus is `failed`. */
export const FinalStatus = z.enum(["success", "error", "cancelled", "timeout"]);

export const Risk = z.enum(["low", "medium", "high"]);

/** Approval provenance is REMOTE-only — a server message must not assert a
 *  local decision (B7). The local gate/audit state is owned by the daemon. */
export const RemoteDecisionBy = z.enum(["remote_user", "remote_policy", "remote_system"]);

export const NackCode = z.enum([
  "unsupported_version", "invalid_message", "stale_lease", "unknown_job",
  "unknown_attempt", "duplicate_attempt", "rate_limited",
  "bad_direction", "bad_state", "payload_too_large", "lease_expired", "policy_violation",
]);

export const ErrorCode = z.enum([
  "internal", "engine_unavailable", "workspace_error", "approval_timeout", "policy_violation",
]);

/** Core event kinds are FROZEN for v1 (EventKind Option A): the closed enum below
 *  is the COMPLETE core set — a new core kind is a major bump (v2). This closed
 *  enum IS the F6 enforcement: an unknown CORE kind fails to parse, and the
 *  daemon/relay's parse-error→nack layer turns that into `invalid_message`
 *  (`validateInbound` can't enforce F6 — parse throws first). Engine-specific
 *  events use the `vendor.<engine>.*` namespace only; unknown VENDOR events MAY be
 *  stored/passed through opaquely but not trusted/rendered (A5). Do NOT add a
 *  "non-critical unknown core" branch — cores are frozen, so it cannot occur.
 *
 *  The vendor regex MUST track the `Engine` enum above: adding a 3rd engine is a
 *  contract change (there is no mechanical binding to `Engine` in v1). */
export const EventKind = z.union([
  z.enum([
    "assistant_text", "tool_use", "tool_result", "usage",
    "stdout_chunk", "stderr_chunk", "system_status", "engine_error",
  ]),
  z.string().regex(/^vendor\.(claude|codex)\.[a-z0-9_.]+$/),
]);

// ---------------------------------------------------------------------------
// Composite value objects
// ---------------------------------------------------------------------------

const EnvPolicy = z.strictObject({
  mode: z.literal("whitelist"),
  allow: z.array(Id).max(ARRAY_MAX).default([]),
});

// v1: mode only. restricted/on host grammar (CIDR/wildcard/DNS-rebind guard)
// is deferred; MVP coding tasks run with network off unless a repo opts in.
const NetworkPolicy = z.strictObject({
  mode: z.enum(["off", "restricted", "on"]),
});

const Limits = z.strictObject({
  timeout_ms: PosInt.max(TIMEOUT_MS_MAX),
  max_output_bytes: PosInt.max(OUTPUT_BYTES_MAX),
});

// repo_root/cwd canonicalization is NORMATIVE (not advisory): the daemon MUST
// realpath them, reject symlink escapes, and reject a cwd outside repo_root,
// which itself must be on the local allowlist.
const Workspace = z.strictObject({
  repo_root: Path,
  base_sha: Id.optional(),
  cwd: Path.optional(),
});

const EngineStatus = z.strictObject({
  installed: z.boolean(),
  version: Id.optional(),
  logged_in: z.boolean().optional(),
});

const Capabilities = z.strictObject({
  engines: z.strictObject({ claude: EngineStatus, codex: EngineStatus }),
  project_roots: z.array(Path).max(ARRAY_MAX),
});

const ActiveJob = z.strictObject({
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  status: ActiveJobStatus,
  last_emitted_seq: SafeInt,
});

/** A terminal result produced but not yet acked. The agent MUST durably store
 *  the full job.result payload locally; this is the index + verification info
 *  so the server can distinguish "payload acked" from "id acked" (B5). */
const PendingResult = z.strictObject({
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  final_status: FinalStatus,
  result_digest: Sha256Digest.describe("base64url(SHA-256(canonical job.result bytes)); see auth-pairing-spec."),
  result_size: SafeInt,
  last_emitted_seq: SafeInt,
});

// ---------------------------------------------------------------------------
// Envelope: every message is a strict object sharing { id, ts }.
// ---------------------------------------------------------------------------

const base = { id: MessageId, ts: Iso };

// ---- Handshake (authenticated) --------------------------------------------

export const AuthChallenge = z.strictObject({
  ...base,
  type: z.literal("auth.challenge"),
  challenge_id: AuthId,
  /** 32 random bytes, base64url — exactly 43 chars, unpadded, and CANONICAL:
   *  re-encoding the decoded bytes must yield the same string, so non-zero
   *  trailing pad bits are rejected (F1 nit). Single-use, server-tracked. */
  nonce: Base64Url.length(43).refine(
    (s) => Buffer.from(s, "base64url").toString("base64url") === s,
    "nonce is not canonical base64url (non-zero trailing pad bits)",
  ),
  server_time: Iso,
  challenge_ttl_ms: PosInt,
});

export const Hello = z.strictObject({
  ...base,
  type: z.literal("hello"),
  protocol_version: SemVer,
  agent_id: AuthId,
  agent_version: SemVer,
  /** Ed25519 signature over the canonical transcript defined in the
   *  auth/pairing spec — NOT the bare nonce. `key_id` selects the device key. */
  auth: z.strictObject({
    challenge_id: AuthId,
    key_id: AuthId,
    signature: Ed25519Sig,
    alg: z.literal("ed25519"),
  }),
  os: z.strictObject({
    platform: z.enum(["darwin", "linux", "win32"]),
    arch: Id,
    release: Id.optional(),
  }),
  capabilities: Capabilities,
  active_jobs: z.array(ActiveJob).max(ARRAY_MAX).default([]),
  pending_results: z.array(PendingResult).max(ARRAY_MAX).default([]),
});

const ResumeDirective = z.strictObject({
  job_id: JobId,
  attempt_id: AttemptId,
  // resume_from: re-send stream events after resume_after_seq.
  // resend_result: server lacks the terminal result — re-send job.result.
  // ack_pending: server already has it — GC locally.
  // abandon: drop the attempt.
  action: z.enum(["resume_from", "resend_result", "ack_pending", "abandon"]),
  resume_after_seq: SafeInt.optional(),
  /** The current lease the agent must stamp on resumed/resent attempt messages
   *  (required for resume_from / resend_result; omitted for ack_pending/abandon). */
  lease_id: LeaseId.optional(),
}).superRefine((v, ctx) => {
  if ((v.action === "resume_from" || v.action === "resend_result") && !v.lease_id) {
    ctx.addIssue({ code: "custom", message: "lease_id is required for resume_from / resend_result" });
  }
});

export const HelloAccepted = z.strictObject({
  ...base,
  type: z.literal("hello.accepted"),
  negotiated_version: SemVer,
  /** Server-assigned; monotonically increasing per agent_id. The agent must
   *  abandon any older connection_epoch — older WSS sessions are fenced (B2). */
  connection_epoch: SafeInt,
  heartbeat_interval_ms: PosInt,
  resume: z.array(ResumeDirective).max(ARRAY_MAX).default([]),
});

export const HelloRejected = z.strictObject({
  ...base,
  type: z.literal("hello.rejected"),
  code: z.enum(["unsupported_version", "unauthorized", "agent_unknown", "bad_signature", "expired_challenge"]),
  message: Text,
});

// ---- Lease fencing ---------------------------------------------------------

export const LeaseRenew = z.strictObject({
  ...base,
  type: z.literal("lease.renew"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
});

export const LeaseGranted = z.strictObject({
  ...base,
  type: z.literal("lease.granted"),
  job_id: JobId,
  attempt_id: AttemptId,
  /** The NEW current-generation token. The agent switches to it immediately; the
   *  server accepts BOTH old and new for LEASE_ROTATION_OVERLAP_MS to avoid
   *  false-nacking in-flight messages, then nacks the old one (`stale_lease`). */
  lease_id: LeaseId,
  lease_ttl_ms: PosInt.min(LIMITS.LEASE_TTL_MS_MIN).max(LIMITS.LEASE_TTL_MS_MAX),
});

export const LeaseRevoke = z.strictObject({
  ...base,
  type: z.literal("lease.revoke"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  reason: Text,
});

// ---- Job assignment & acceptance ------------------------------------------

export const JobAssign = z.strictObject({
  ...base,
  type: z.literal("job.assign"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  lease_ttl_ms: PosInt.min(LIMITS.LEASE_TTL_MS_MIN).max(LIMITS.LEASE_TTL_MS_MAX),
  engine: Engine,
  workspace: Workspace,
  prompt: z.string().max(LIMITS.MAX_PROMPT_CHARS),
  // NOTE: no `session_id`. Engine session resume/fork is out of MVP scope and
  // was a cross-job leak surface; reintroduce later as an agent-owned mapping.
  sandbox: Sandbox,
  approval_policy: ApprovalPolicy,
  env_policy: EnvPolicy,
  network_policy: NetworkPolicy,
  limits: Limits,
  priority: SafeInt.optional(),
  created_at: Iso,
  assignment_start_timeout_ms: PosInt,
});

export const JobAccept = z.strictObject({
  ...base,
  type: z.literal("job.accept"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  agent_run_id: Id,
});

export const JobReject = z.strictObject({
  ...base,
  type: z.literal("job.reject"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  // policy_violation: requested sandbox/approval_policy exceeds the daemon's
  // local maximum. The agent REJECTS (no silent clamp) so cloud + daemon never
  // disagree on the effective execution mode (B8).
  code: z.enum(["root_not_allowlisted", "engine_unavailable", "busy", "stale_lease", "bad_request", "policy_violation"]),
  message: Text,
});

// ---- Streaming + acknowledgement ------------------------------------------

export const StreamEvent = z.strictObject({
  ...base,
  type: z.literal("stream.event"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  seq: PosInt.describe("Monotonic per-attempt, starting at 1."),
  event_id: Id,
  // Event payloads are adapter data → bounded by the frame cap, not by strict
  // keys. `kind` is locked to the core enum or a vendor namespace.
  event: z.object({ kind: EventKind }).catchall(z.unknown()),
});

export const StreamAck = z.strictObject({
  ...base,
  type: z.literal("stream.ack"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  ack_seq: SafeInt.describe("Cumulative: every seq <= ack_seq is durably stored, in order."),
});

// ---- Approval gate ---------------------------------------------------------

export const ApprovalRequest = z.strictObject({
  ...base,
  type: z.literal("approval.request"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  request_id: RequestId,
  tool_name: Id,
  input_summary: Text,
  redaction: z.strictObject({
    applied: z.boolean(),
    truncated: z.boolean(),
    byte_count: SafeInt,
  }),
  risk: Risk,
  approval_timeout_ms: PosInt.max(LIMITS.APPROVAL_TIMEOUT_MS_MAX),
});

export const ApprovalResponse = z.strictObject({
  ...base,
  type: z.literal("approval.response"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  request_id: RequestId,
  decision: z.enum(["allow", "deny"]),
  reason: Text.optional(),
  decided_by: RemoteDecisionBy,
  // No `updated_input`: the server cannot rewrite tool input. The daemon caches
  // the original input and reconstructs `updatedInput` for the engine locally.
});

// ---- Status + terminal result ---------------------------------------------

export const JobStatusMsg = z.strictObject({
  ...base,
  type: z.literal("job.status"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  status: JobStatus,
});

export const JobResult = z.strictObject({
  ...base,
  type: z.literal("job.result"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  final_status: FinalStatus,
  exit_code: Int.optional(),
  signal: Id.optional(),
  error_kind: Id.optional(),
  duration_ms: SafeInt,
  stats: z.strictObject({ event_count: SafeInt, bytes: SafeInt }),
  head_sha: Id.optional(),
});

/** Confirms DURABLE storage of a specific terminal payload (digest-matched),
 *  not merely its id — so the agent can GC with confidence (B5). */
export const JobResultAck = z.strictObject({
  ...base,
  type: z.literal("job.result.ack"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  result_digest: Sha256Digest,
});

// ---- Cancellation ----------------------------------------------------------

export const JobCancel = z.strictObject({
  ...base,
  type: z.literal("job.cancel"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId, // C5: without this a stale server message could cancel the wrong live attempt
  reason: Text,
  grace_ms: SafeInt.max(60_000).default(5000),
});

// ---- Liveness + lifecycle --------------------------------------------------

export const Heartbeat = z.strictObject({
  ...base,
  type: z.literal("heartbeat"),
  active_attempts: z.array(AttemptId).max(ARRAY_MAX).optional(),
  capacity: z.strictObject({ max_concurrent: SafeInt, running: SafeInt }).optional(),
});

export const AgentDraining = z.strictObject({
  ...base,
  type: z.literal("agent.draining"),
  reason: z.enum(["shutdown", "update", "idle_timeout"]),
  eta_ms: SafeInt.optional(),
});

export const CapabilitiesUpdate = z.strictObject({
  ...base,
  type: z.literal("capabilities.update"),
  capabilities: Capabilities,
});

// ---- Errors ----------------------------------------------------------------

export const Nack = z.strictObject({
  ...base,
  type: z.literal("nack"),
  ref_id: MessageId.optional(),
  code: NackCode,
  message: Text,
});

export const ErrorMsg = z.strictObject({
  ...base,
  type: z.literal("error"),
  code: ErrorCode,
  message: Text,
  job_id: JobId.optional(),
  attempt_id: AttemptId.optional(),
  lease_id: LeaseId.optional(),
});

// ---- v2 session metadata ---------------------------------------------------

export const SessionInfo = z.strictObject({
  handle: Id,
  session_id: Id,
  engine: Engine,
  cwd: z.string(),
  git_branch: z.string().nullable(),
  cli_version: z.string().nullable(),
  title: z.string(),
  created_at: Iso,
  updated_at: Iso,
  active: z.boolean(),
  msg_count: PosInt,
});

export const SessionToolCall = z.strictObject({
  id: Id,
  name: z.string(),
  input: z.string().optional(),
  input_truncated: z.boolean().optional(),
  output: z.string().optional(),
  output_truncated: z.boolean().optional(),
  status: z.enum(["ok", "error"]).optional(),
});

export const SessionHistoryEntry = z.strictObject({
  entry_id: Id,
  role: z.enum(["user", "assistant"]),
  content: z.string(),
  content_truncated: z.boolean().optional(),
  tool_calls: z.array(SessionToolCall).max(ARRAY_MAX).optional(),
  omitted: z.array(z.strictObject({
    kind: z.enum(["image", "document", "thinking", "fallback", "other"]),
    count: PosInt,
  })).max(ARRAY_MAX).optional(),
  created_at: Iso.nullable(),
});

const SessionListFilter = z.strictObject({
  engine: Engine.optional(),
  cwd_prefix: z.string().optional(),
  active_only: z.boolean().optional(),
  updated_after: Iso.optional(),
});

const SessionListPage = z.strictObject({
  cursor: z.string().optional(),
  limit: PosInt,
});

export const SessionListRequest = z.strictObject({
  ...base,
  type: z.literal("session.list.request"),
  request_id: Id,
  filter: SessionListFilter.optional(),
  page: SessionListPage.optional(),
});

export const SessionListResponse = z.strictObject({
  ...base,
  type: z.literal("session.list.response"),
  request_id: Id,
  sessions: z.array(SessionInfo).max(ARRAY_MAX),
  next_cursor: z.string().nullable().optional(),
  truncated: z.boolean(),
});

export const SessionHistoryRequest = z.strictObject({
  ...base,
  type: z.literal("session.history.request"),
  request_id: Id,
  handle: Id,
  cursor: z.string().optional(),
  limit: PosInt.optional(),
});

export const SessionHistoryResponse = z.strictObject({
  ...base,
  type: z.literal("session.history.response"),
  request_id: Id,
  entries: z.array(SessionHistoryEntry).max(ARRAY_MAX),
  next_cursor: z.string().nullable().optional(),
  truncated: z.boolean(),
});

const SessionResumeOptions = z.strictObject({
  fork: z.boolean().optional(),
  sandbox: z.enum(["read_only", "workspace_write", "full"]).optional(),
  model: z.string().optional(),
});

export const SessionResumeRequest = z.strictObject({
  ...base,
  type: z.literal("session.resume.request"),
  request_id: Id,
  handle: Id,
  message: z.string(),
  options: SessionResumeOptions.optional(),
});

export const SessionCancel = z.strictObject({
  ...base,
  type: z.literal("session.cancel"),
  turn_id: Id,
});

export const SessionAck = z.strictObject({
  ...base,
  type: z.literal("session.ack"),
  turn_id: Id,
  ack_seq: PosInt,
});

export const SessionMessage = z.strictObject({
  ...base,
  type: z.literal("session.message"),
  request_id: Id,
  handle: Id,
  message: z.string(),
});

export const SessionResumeAccept = z.strictObject({
  ...base,
  type: z.literal("session.resume.accept"),
  request_id: Id,
  turn_id: Id,
  effective_options: z.strictObject({
    fork: z.boolean(),
    sandbox: z.string(),
    mutates_source: z.boolean().optional(),
  }).optional(),
});

export const SessionResumeReject = z.strictObject({
  ...base,
  type: z.literal("session.resume.reject"),
  request_id: Id,
  code: z.string(),
  message: z.string(),
});

export const SessionEvent = z.strictObject({
  ...base,
  type: z.literal("session.event"),
  turn_id: Id,
  seq: PosInt,
  event: z.object({ kind: EventKind }).catchall(z.unknown()),
});

export const SessionTurnResult = z.strictObject({
  ...base,
  type: z.literal("session.turn.result"),
  turn_id: Id,
  status: z.enum(["ok", "error", "cancelled"]),
  final_message: z.string(),
  new_session_handle: Id.nullable().optional(),
});

// History fetches may emit history_unavailable, file_unreadable, or
// payload_too_large; SessionError.code remains a free string.
export const SessionError = z.strictObject({
  ...base,
  type: z.literal("session.error"),
  request_id: Id.optional(),
  turn_id: Id.optional(),
  code: z.string(),
  message: z.string(),
});

// ---------------------------------------------------------------------------
// Discriminated union + helpers
// ---------------------------------------------------------------------------

export const V1_VARIANTS = [
  AuthChallenge,
  Hello,
  HelloAccepted,
  HelloRejected,
  LeaseRenew,
  LeaseGranted,
  LeaseRevoke,
  JobAssign,
  JobAccept,
  JobReject,
  StreamEvent,
  StreamAck,
  ApprovalRequest,
  ApprovalResponse,
  JobStatusMsg,
  JobResult,
  JobResultAck,
  JobCancel,
  Heartbeat,
  AgentDraining,
  CapabilitiesUpdate,
  Nack,
  ErrorMsg,
] as const;

export const Message = z.discriminatedUnion("type", V1_VARIANTS);

export type Message = z.infer<typeof Message>;
export type MessageType = Message["type"];
type SessionListRequestMsg = z.infer<typeof SessionListRequest>;
type SessionListResponseMsg = z.infer<typeof SessionListResponse>;
type SessionHistoryRequestMsg = z.infer<typeof SessionHistoryRequest>;
type SessionHistoryResponseMsg = z.infer<typeof SessionHistoryResponse>;
type SessionResumeRequestMsg = z.infer<typeof SessionResumeRequest>;
type SessionCancelMsg = z.infer<typeof SessionCancel>;
type SessionAckMsg = z.infer<typeof SessionAck>;
type SessionMessageMsg = z.infer<typeof SessionMessage>;
type SessionResumeAcceptMsg = z.infer<typeof SessionResumeAccept>;
type SessionResumeRejectMsg = z.infer<typeof SessionResumeReject>;
type SessionEventMsg = z.infer<typeof SessionEvent>;
type SessionTurnResultMsg = z.infer<typeof SessionTurnResult>;
type SessionErrorMsg = z.infer<typeof SessionError>;

export const V2_VARIANTS = [
  ...V1_VARIANTS,
  SessionListRequest,
  SessionListResponse,
  SessionHistoryRequest,
  SessionHistoryResponse,
  SessionResumeRequest,
  SessionCancel,
  SessionAck,
  SessionMessage,
  SessionResumeAccept,
  SessionResumeReject,
  SessionEvent,
  SessionTurnResult,
  SessionError,
] as const;

export const MessageV2: z.ZodType<
  | Message
  | SessionListRequestMsg
  | SessionListResponseMsg
  | SessionHistoryRequestMsg
  | SessionHistoryResponseMsg
  | SessionResumeRequestMsg
  | SessionCancelMsg
  | SessionAckMsg
  | SessionMessageMsg
  | SessionResumeAcceptMsg
  | SessionResumeRejectMsg
  | SessionEventMsg
  | SessionTurnResultMsg
  | SessionErrorMsg
> =
  z.discriminatedUnion("type", V2_VARIANTS);

export type MessageV2 = z.infer<typeof MessageV2>;
export type MessageV2Type = MessageV2["type"];

/** a2s = agent→server, s2a = server→agent. */
export const DIRECTION = {
  "auth.challenge": "s2a",
  hello: "a2s",
  "hello.accepted": "s2a",
  "hello.rejected": "s2a",
  "lease.renew": "a2s",
  "lease.granted": "s2a",
  "lease.revoke": "s2a",
  "job.assign": "s2a",
  "job.accept": "a2s",
  "job.reject": "a2s",
  "stream.event": "a2s",
  "stream.ack": "s2a",
  "approval.request": "a2s",
  "approval.response": "s2a",
  "job.status": "a2s",
  "job.result": "a2s",
  "job.result.ack": "s2a",
  "job.cancel": "s2a",
  heartbeat: "both",
  "agent.draining": "a2s",
  "capabilities.update": "a2s",
  nack: "both",
  error: "both",
  "session.list.request": "s2a",
  "session.list.response": "a2s",
  "session.history.request": "s2a",
  "session.history.response": "a2s",
  "session.resume.request": "s2a",
  "session.cancel": "s2a",
  "session.ack": "s2a",
  "session.message": "s2a",
  "session.resume.accept": "a2s",
  "session.resume.reject": "a2s",
  "session.event": "a2s",
  "session.turn.result": "a2s",
  "session.error": "a2s",
} as const satisfies Record<MessageV2Type, "a2s" | "s2a" | "both">;

/** Messages permitted before the handshake completes (pre-auth phase). */
export const HANDSHAKE_TYPES = new Set<MessageType>([
  "auth.challenge", "hello", "hello.accepted", "hello.rejected", "nack", "error",
]);

export function parseMessage(raw: unknown): Message {
  return Message.parse(raw);
}

export function safeParseMessage(raw: unknown) {
  return Message.safeParse(raw);
}

export function safeParseMessageV2(raw: unknown) {
  return MessageV2.safeParse(raw);
}
