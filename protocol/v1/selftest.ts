/**
 * Protocol v1 self-test — a runnable conformance smoke check.
 *
 *   npm run protocol:check
 *
 * Builds one canonical sample of every message type, validates it against the
 * schema, and asserts every `type` in the union is covered. Doubles as
 * executable documentation of the wire format for the cloud team.
 */

import {
  DIRECTION,
  Message,
  type MessageType,
  PROTOCOL_VERSION,
  negotiateVersion,
  parseMessage,
} from "./index";

const now = "2026-06-23T00:00:00.000Z";
const env = { mode: "whitelist" as const, allow: ["PATH", "HOME"] };

const samples: Record<MessageType, unknown> = {
  "auth.challenge": {
    id: "m0", ts: now, type: "auth.challenge", nonce: "n-deadbeef", server_time: now,
  },
  hello: {
    id: "m1", ts: now, type: "hello",
    protocol_version: PROTOCOL_VERSION,
    agent_id: "agent-abc", agent_version: "0.0.0",
    auth: { signature: "base64sig", alg: "ed25519" },
    os: { platform: "darwin", arch: "arm64", release: "25.5.0" },
    capabilities: {
      engines: {
        claude: { installed: true, version: "2.1.170", logged_in: true },
        codex: { installed: true, version: "0.140.0", logged_in: false },
      },
      project_roots: ["/Users/k/code/repo-a"],
    },
    active_jobs: [],
    pending_results: [{ job_id: "j0", attempt_id: "a0" }],
  },
  "hello.accepted": {
    id: "m2", ts: now, type: "hello.accepted",
    negotiated_version: PROTOCOL_VERSION, heartbeat_interval_ms: 15000,
    resume: [{ job_id: "j1", attempt_id: "a1", action: "resume_from", resume_after_seq: 42 }],
  },
  "hello.rejected": {
    id: "m3", ts: now, type: "hello.rejected", code: "bad_signature", message: "sig invalid",
  },
  "lease.renew": {
    id: "m3a", ts: now, type: "lease.renew", job_id: "j1", attempt_id: "a1", lease_id: "l1",
  },
  "lease.granted": {
    id: "m3b", ts: now, type: "lease.granted", job_id: "j1", attempt_id: "a1", lease_id: "l1", lease_expires_at: now,
  },
  "lease.revoke": {
    id: "m3c", ts: now, type: "lease.revoke", job_id: "j1", attempt_id: "a1", lease_id: "l1", reason: "reassigned",
  },
  "job.assign": {
    id: "m4", ts: now, type: "job.assign",
    job_id: "j1", attempt_id: "a1", lease_id: "l1", lease_expires_at: now,
    engine: "claude",
    workspace: { repo_root: "/Users/k/code/repo-a", base_sha: "deadbeef" },
    prompt: "Summarize the README.",
    sandbox: "read_only", approval_policy: "on_write",
    env_policy: env, network_policy: { mode: "off" },
    limits: { timeout_ms: 600000, max_output_bytes: 5_000_000 },
    created_at: now, expires_at: now,
  },
  "job.accept": {
    id: "m5", ts: now, type: "job.accept", job_id: "j1", attempt_id: "a1", agent_run_id: "run-1",
  },
  "job.reject": {
    id: "m6", ts: now, type: "job.reject", job_id: "j1", attempt_id: "a1",
    code: "root_not_allowlisted", message: "cwd outside allowlist",
  },
  "stream.event": {
    id: "m7", ts: now, type: "stream.event", job_id: "j1", attempt_id: "a1",
    seq: 1, event_id: "e1", event: { kind: "assistant_text", text: "hello" },
  },
  "stream.ack": {
    id: "m8", ts: now, type: "stream.ack", job_id: "j1", attempt_id: "a1", ack_seq: 1,
  },
  "approval.request": {
    id: "m9", ts: now, type: "approval.request", job_id: "j1", attempt_id: "a1",
    request_id: "r1", tool_name: "Bash", input_summary: "rm -rf build/", redacted: false,
    risk: "high", expires_at: now,
  },
  "approval.response": {
    id: "m10", ts: now, type: "approval.response", job_id: "j1", attempt_id: "a1",
    request_id: "r1", decision: "deny", decided_by: "local_user",
  },
  "job.status": {
    id: "m11", ts: now, type: "job.status", job_id: "j1", attempt_id: "a1", status: "running",
  },
  "job.result": {
    id: "m12", ts: now, type: "job.result", job_id: "j1", attempt_id: "a1",
    final_status: "success", exit_code: 0, duration_ms: 1234,
    stats: { event_count: 10, bytes: 4096 }, head_sha: "cafebabe",
  },
  "job.result.ack": {
    id: "m12a", ts: now, type: "job.result.ack", job_id: "j1", attempt_id: "a1",
  },
  "job.cancel": {
    id: "m13", ts: now, type: "job.cancel", job_id: "j1", attempt_id: "a1", reason: "user", grace_ms: 5000,
  },
  heartbeat: {
    id: "m14", ts: now, type: "heartbeat", active_attempts: ["a1"], capacity: { max_concurrent: 4, running: 1 },
  },
  "agent.draining": {
    id: "m15", ts: now, type: "agent.draining", reason: "update", eta_ms: 30000,
  },
  "capabilities.update": {
    id: "m16", ts: now, type: "capabilities.update",
    capabilities: {
      engines: { claude: { installed: true }, codex: { installed: false } },
      project_roots: [],
    },
  },
  nack: {
    id: "m17", ts: now, type: "nack", ref_id: "m4", code: "stale_lease", message: "lease expired",
  },
  error: {
    id: "m18", ts: now, type: "error", code: "engine_unavailable", message: "claude not logged in",
  },
};

let failures = 0;
const allTypes = Message.options.map((o) => o.shape.type.value) as MessageType[];

for (const type of allTypes) {
  const sample = samples[type];
  if (sample === undefined) {
    console.error(`✗ ${type}: no sample defined`);
    failures++;
    continue;
  }
  const result = Message.safeParse(sample);
  if (!result.success) {
    console.error(`✗ ${type}: ${result.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join("; ")}`);
    failures++;
  } else {
    parseMessage(JSON.parse(JSON.stringify(sample))); // round-trip through JSON
    console.log(`✓ ${type.padEnd(20)} (${DIRECTION[type]})`);
  }
}

// version negotiation
const checks: Array<[string, boolean]> = [
  ["stable major match (1.4.0 vs {1.0.0,2.0.0})", negotiateVersion("1.4.0", ["1.0.0", "2.0.0"]).ok],
  ["stable rejects major 3 (3.0.0 vs {1.0.0})", !negotiateVersion("3.0.0", ["1.0.0"]).ok],
  ["draft exact match", negotiateVersion(PROTOCOL_VERSION, [PROTOCOL_VERSION]).ok],
  ["draft rejects non-exact (draft vs 1.5.0)", !negotiateVersion(PROTOCOL_VERSION, ["1.5.0"]).ok],
];
for (const [label, pass] of checks) {
  console.log(pass ? `✓ ${label}` : `✗ ${label}`);
  if (!pass) failures++;
}

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log(`\nAll ${allTypes.length} message types valid.`);
