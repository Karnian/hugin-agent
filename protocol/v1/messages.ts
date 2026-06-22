/**
 * Hugin Agent — Wire protocol v1 (STRAWMAN / DRAFT, rev 1.1)
 * =========================================================
 *
 * Single source of truth for the WSS JSON contract shared between:
 *   - the local daemon  (`hugind`, "agent")          — runs behind NAT, dials out
 *   - the cloud relay   ("server" / orchestrator)    — assigns jobs, collects events
 *
 * Transport: one JSON object per WebSocket text frame.
 *
 * Design principles (see ../README.md for rationale):
 *   1. Outbound-only. The agent always initiates the connection.
 *   2. At-least-once delivery + idempotent consumers. NOT exactly-once.
 *   3. Lease-based job ownership; reconnect/reassign mint a NEW attempt.
 *   4. Explicit completion. `job.result` is authoritative; it is acked.
 *   5. Versioned + authenticated handshake. The server challenges; the agent
 *      proves possession of its paired device key before any job flows.
 *
 * rev 1.1 — folds in cloud-team review:
 *   + auth.challenge / signed hello (was: agent_id with no proof)
 *   + lease.renew / lease.granted / lease.revoke (explicit fencing)
 *   + job.result.ack + hello.pending_results (terminal-result durability)
 *   + approval.request.expires_at, structured redaction, decided_by enum,
 *     removed server-rewritten updated_input (injection surface)
 *   + bounded prompt, heartbeat.capacity (backpressure)
 *
 * rev 1.2 — folds in cross-review:
 *   + JobStatus.cancelled (state machine ↔ FinalStatus were inconsistent)
 *   + auth.challenge nonce entropy/TTL + signed transcript (challenge_id)
 *   + PendingResult.final_status + ResumeDirective.ack_pending (reconnect)
 *   + FinalStatus drops `rejected` (job.reject already covers refusal)
 *
 * NOTE: proposal for review, not a frozen contract. See ../README.md.
 */

import { z } from "zod";

/** Semantic version of this protocol revision. */
export const PROTOCOL_VERSION = "1.2.0-draft" as const;

// ---------------------------------------------------------------------------
// Shared scalars
// ---------------------------------------------------------------------------

const Iso = z.string().datetime({ offset: true });
const NonEmpty = z.string().min(1);

const JobId = NonEmpty.describe("Stable id for a logical job (survives retries).");
const AttemptId = NonEmpty.describe("Unique id for ONE execution attempt of a job.");
const LeaseId = NonEmpty.describe("Ownership token for an attempt; renewed explicitly.");
const RequestId = NonEmpty.describe("Correlates an approval.request with its response.");
const MessageId = NonEmpty.describe("Per-message id, used as the `ref_id` in nack/error.");

const MAX_PROMPT_CHARS = 100_000;
const MAX_SUMMARY_CHARS = 2_000;

const NormalizedEvent = z
  .object({
    kind: NonEmpty.describe("Normalized event kind, e.g. assistant_text, tool_use, tool_result, usage."),
  })
  .passthrough()
  .describe("Engine-agnostic NDJSON event. Adapters map claude/codex output into this shape.");

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export const Engine = z.enum(["claude", "codex"]);
export const Sandbox = z.enum(["read_only", "workspace_write", "full"]);
export const ApprovalPolicy = z.enum(["never", "on_request", "on_write", "always"]);

export const JobStatus = z.enum([
  "accepted",
  "starting",
  "running",
  "cancelling",
  "cancelled",
  "completed",
  "failed",
]);

// `rejected` is intentionally absent: a refused *assignment* ends via
// `job.reject` (a2s) and never produces a job.result. `timeout` is a terminal
// reason carried by job.result; the job's last JobStatus for it is `failed`.
export const FinalStatus = z.enum(["success", "error", "cancelled", "timeout"]);
export const Risk = z.enum(["low", "medium", "high"]);

/** Who made an approval decision. Closed set so `local_user` can't be spoofed. */
export const DecidedBy = z.enum(["remote_user", "local_user", "policy", "system"]);

export const NackCode = z.enum([
  "unsupported_version",
  "invalid_message",
  "stale_lease",
  "unknown_job",
  "duplicate_attempt",
  "rate_limited",
]);

export const ErrorCode = z.enum([
  "internal",
  "engine_unavailable",
  "workspace_error",
  "approval_timeout",
  "policy_violation",
]);

// ---------------------------------------------------------------------------
// Composite value objects
// ---------------------------------------------------------------------------

const EnvPolicy = z.object({
  mode: z.literal("whitelist"),
  allow: z.array(NonEmpty).default([]),
});

const NetworkPolicy = z.object({
  mode: z.enum(["off", "restricted", "on"]),
  allow_hosts: z.array(NonEmpty).optional(),
});

const Limits = z.object({
  timeout_ms: z.number().int().positive(),
  max_output_bytes: z.number().int().positive(),
});

const Workspace = z.object({
  repo_root: NonEmpty.describe("Allowlisted, realpath-canonicalized repo root."),
  base_sha: NonEmpty.optional(),
  cwd: z.string().optional().describe("Subdir within repo_root; MUST resolve inside it."),
});

const EngineStatus = z.object({
  installed: z.boolean(),
  version: z.string().optional(),
  logged_in: z.boolean().optional(),
});

const Capabilities = z.object({
  engines: z.object({ claude: EngineStatus, codex: EngineStatus }),
  project_roots: z.array(NonEmpty),
});

const ActiveJob = z.object({
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  status: JobStatus,
  last_emitted_seq: z.number().int().nonnegative(),
});

/**
 * A terminal result the agent produced but hasn't seen acked — replayed on
 * reconnect. The agent MUST durably store the full job.result payload locally
 * (SQLite); this is only the index into it, not the payload.
 */
const PendingResult = z.object({ job_id: JobId, attempt_id: AttemptId, final_status: FinalStatus });

// ---------------------------------------------------------------------------
// Envelope: every message shares { id, ts }. `type` is the discriminant.
// ---------------------------------------------------------------------------

const base = { id: MessageId, ts: Iso };

// ---- Handshake (authenticated) --------------------------------------------

/** Server's FIRST frame: a nonce the agent must sign with its device key. */
export const AuthChallenge = z.object({
  ...base,
  type: z.literal("auth.challenge"),
  challenge_id: NonEmpty.describe("Echoed in hello.auth so the response binds to this challenge."),
  /** >=256-bit random, base64url. Single-use; the server tracks spent nonces. */
  nonce: z.string().min(43),
  server_time: Iso,
  expires_at: Iso.describe("Nonce TTL; a hello arriving after this is rejected."),
});

export const Hello = z.object({
  ...base,
  type: z.literal("hello"),
  protocol_version: z.string(),
  agent_id: NonEmpty,
  agent_version: NonEmpty,
  /**
   * Proof of possession of the paired device key. `signature` signs the
   * canonical transcript `challenge_id | nonce | agent_id | protocol_version |
   * alg` — NOT the bare nonce, which would be replayable. The server resolves
   * the device public key by `agent_id` (registered at pairing).
   */
  auth: z.object({
    challenge_id: NonEmpty,
    signature: NonEmpty,
    alg: z.enum(["ed25519", "ecdsa-p256"]),
  }),
  os: z.object({
    platform: z.enum(["darwin", "linux", "win32"]),
    arch: z.string(),
    release: z.string().optional(),
  }),
  capabilities: Capabilities,
  active_jobs: z.array(ActiveJob).default([]),
  /** Terminal results awaiting ack from a previous connection. */
  pending_results: z.array(PendingResult).default([]),
});

const ResumeDirective = z.object({
  job_id: JobId,
  attempt_id: AttemptId,
  // ack_pending: the server already holds this terminal result; the agent may
  // GC it (a job.result.ack delivered inside the handshake).
  action: z.enum(["resume_from", "abandon", "ack_pending"]),
  resume_after_seq: z.number().int().nonnegative().optional(),
});

export const HelloAccepted = z.object({
  ...base,
  type: z.literal("hello.accepted"),
  negotiated_version: z.string(),
  heartbeat_interval_ms: z.number().int().positive(),
  resume: z.array(ResumeDirective).default([]),
});

export const HelloRejected = z.object({
  ...base,
  type: z.literal("hello.rejected"),
  code: z.enum(["unsupported_version", "unauthorized", "agent_unknown", "bad_signature"]),
  message: z.string(),
});

// ---- Lease fencing ---------------------------------------------------------

export const LeaseRenew = z.object({
  ...base,
  type: z.literal("lease.renew"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
});

export const LeaseGranted = z.object({
  ...base,
  type: z.literal("lease.granted"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  lease_expires_at: Iso,
});

export const LeaseRevoke = z.object({
  ...base,
  type: z.literal("lease.revoke"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  reason: z.string(),
});

// ---- Job assignment & acceptance ------------------------------------------

export const JobAssign = z.object({
  ...base,
  type: z.literal("job.assign"),
  job_id: JobId,
  attempt_id: AttemptId,
  lease_id: LeaseId,
  lease_expires_at: Iso,
  engine: Engine,
  workspace: Workspace,
  prompt: z.string().max(MAX_PROMPT_CHARS),
  session_id: z.string().optional().describe("Resume an existing engine session."),
  sandbox: Sandbox,
  approval_policy: ApprovalPolicy,
  env_policy: EnvPolicy,
  network_policy: NetworkPolicy,
  limits: Limits,
  priority: z.number().int().optional(),
  created_at: Iso,
  expires_at: Iso.describe("Drop the assignment if not started by this time."),
});

export const JobAccept = z.object({
  ...base,
  type: z.literal("job.accept"),
  job_id: JobId,
  attempt_id: AttemptId,
  agent_run_id: NonEmpty,
});

export const JobReject = z.object({
  ...base,
  type: z.literal("job.reject"),
  job_id: JobId,
  attempt_id: AttemptId,
  code: z.enum(["root_not_allowlisted", "engine_unavailable", "busy", "stale_lease", "bad_request"]),
  message: z.string(),
});

// ---- Streaming + acknowledgement ------------------------------------------

export const StreamEvent = z.object({
  ...base,
  type: z.literal("stream.event"),
  job_id: JobId,
  attempt_id: AttemptId,
  seq: z.number().int().positive().describe("Monotonic per-attempt, starting at 1."),
  event_id: NonEmpty,
  event: NormalizedEvent,
});

export const StreamAck = z.object({
  ...base,
  type: z.literal("stream.ack"),
  job_id: JobId,
  attempt_id: AttemptId,
  ack_seq: z.number().int().nonnegative().describe("Cumulative: every seq <= ack_seq is durably stored, in order."),
});

// ---- Approval gate ---------------------------------------------------------

export const ApprovalRequest = z.object({
  ...base,
  type: z.literal("approval.request"),
  job_id: JobId,
  attempt_id: AttemptId,
  request_id: RequestId,
  tool_name: NonEmpty,
  /** Redacted, length-capped summary. Raw secrets never leave the host. */
  input_summary: z.string().max(MAX_SUMMARY_CHARS),
  redacted: z.boolean().describe("True if the daemon stripped sensitive content from input_summary."),
  risk: Risk,
  /** Hard deadline; on expiry the agent auto-denies and emits `error{approval_timeout}`. */
  expires_at: Iso,
});

export const ApprovalResponse = z.object({
  ...base,
  type: z.literal("approval.response"),
  job_id: JobId,
  attempt_id: AttemptId,
  request_id: RequestId,
  decision: z.enum(["allow", "deny"]),
  reason: z.string().optional(),
  decided_by: DecidedBy,
  // NOTE: no server-supplied `updated_input`. The server cannot rewrite tool
  // input — allow/deny only — to remove a remote command-injection surface.
});

// ---- Status + terminal result ---------------------------------------------

export const JobStatusMsg = z.object({
  ...base,
  type: z.literal("job.status"),
  job_id: JobId,
  attempt_id: AttemptId,
  status: JobStatus,
});

export const JobResult = z.object({
  ...base,
  type: z.literal("job.result"),
  job_id: JobId,
  attempt_id: AttemptId,
  final_status: FinalStatus,
  exit_code: z.number().int().optional(),
  signal: z.string().optional(),
  error_kind: z.string().optional(),
  duration_ms: z.number().int().nonnegative(),
  stats: z.object({
    event_count: z.number().int().nonnegative(),
    bytes: z.number().int().nonnegative(),
  }),
  head_sha: z.string().optional(),
});

/** Server confirms durable storage of a terminal result; agent may GC it. */
export const JobResultAck = z.object({
  ...base,
  type: z.literal("job.result.ack"),
  job_id: JobId,
  attempt_id: AttemptId,
});

// ---- Cancellation ----------------------------------------------------------

export const JobCancel = z.object({
  ...base,
  type: z.literal("job.cancel"),
  job_id: JobId,
  attempt_id: AttemptId,
  reason: z.string(),
  grace_ms: z.number().int().nonnegative().default(5000),
});

// ---- Liveness + lifecycle --------------------------------------------------

export const Heartbeat = z.object({
  ...base,
  type: z.literal("heartbeat"),
  active_attempts: z.array(AttemptId).optional(),
  /** Backpressure hint (a2s): concurrency headroom for the scheduler. */
  capacity: z
    .object({ max_concurrent: z.number().int().nonnegative(), running: z.number().int().nonnegative() })
    .optional(),
});

export const AgentDraining = z.object({
  ...base,
  type: z.literal("agent.draining"),
  reason: z.enum(["shutdown", "update", "idle_timeout"]),
  eta_ms: z.number().int().nonnegative().optional(),
});

export const CapabilitiesUpdate = z.object({
  ...base,
  type: z.literal("capabilities.update"),
  capabilities: Capabilities,
});

// ---- Errors ----------------------------------------------------------------

export const Nack = z.object({
  ...base,
  type: z.literal("nack"),
  ref_id: MessageId.optional(),
  code: NackCode,
  message: z.string(),
});

export const ErrorMsg = z.object({
  ...base,
  type: z.literal("error"),
  code: ErrorCode,
  message: z.string(),
  job_id: JobId.optional(),
  attempt_id: AttemptId.optional(),
});

// ---------------------------------------------------------------------------
// Discriminated union + helpers
// ---------------------------------------------------------------------------

export const Message = z.discriminatedUnion("type", [
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
]);

export type Message = z.infer<typeof Message>;
export type MessageType = Message["type"];

/** Direction of each message: a2s = agent→server, s2a = server→agent. */
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
} as const satisfies Record<MessageType, "a2s" | "s2a" | "both">;

export function parseMessage(raw: unknown): Message {
  return Message.parse(raw);
}

export function safeParseMessage(raw: unknown) {
  return Message.safeParse(raw);
}
