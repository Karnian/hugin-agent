/**
 * Protocol v1 self-test — a runnable conformance smoke check.
 *
 *   npm run protocol:check
 *
 * Validates one canonical sample of every message type, asserts coverage of the
 * union, and exercises version negotiation, strict unknown-field rejection, and
 * inbound direction/phase validation. Executable documentation for the cloud team.
 */

import { readFileSync } from "node:fs";
import { verify } from "node:crypto";
import {
  DIRECTION,
  Message,
  type MessageType,
  PROTOCOL_VERSION,
  SemVer,
  negotiateVersion,
  parseMessage,
  validateInbound,
} from "./index";
import {
  ALG,
  DOMAIN_TAG,
  b64u,
  buildTranscript,
  canonicalizeServerOrigin,
  deriveKeypairFromSeed,
  lp,
  publicKeyFromRaw,
  validateTenantId,
  type VectorsFile,
} from "./gen-vectors";

const now = "2026-06-23T00:00:00.000Z";
const env = { mode: "whitelist" as const, allow: ["PATH", "HOME"] };
const nonce = "A".repeat(43); // 32-byte base64url placeholder
const digest = "A".repeat(43); // SHA-256 base64url placeholder
const sig = "A".repeat(86); // Ed25519 signature base64url placeholder
const lease = "l1";

const samples: Record<MessageType, unknown> = {
  "auth.challenge": {
    id: "m0", ts: now, type: "auth.challenge",
    challenge_id: "ch-1", nonce, server_time: now, challenge_ttl_ms: 60000,
  },
  hello: {
    id: "m1", ts: now, type: "hello",
    protocol_version: PROTOCOL_VERSION, agent_id: "agent-abc", agent_version: "0.0.0",
    auth: { challenge_id: "ch-1", key_id: "key-1", signature: sig, alg: "ed25519" },
    os: { platform: "darwin", arch: "arm64", release: "25.5.0" },
    capabilities: {
      engines: {
        claude: { installed: true, version: "2.1.170", logged_in: true },
        codex: { installed: true, version: "0.140.0", logged_in: false },
      },
      project_roots: ["/Users/k/code/repo-a"],
    },
    active_jobs: [],
    pending_results: [
      { job_id: "j0", attempt_id: "a0", lease_id: lease, final_status: "success", result_digest: digest, result_size: 4096, last_emitted_seq: 10 },
    ],
  },
  "hello.accepted": {
    id: "m2", ts: now, type: "hello.accepted",
    negotiated_version: PROTOCOL_VERSION, connection_epoch: 7, heartbeat_interval_ms: 15000,
    resume: [
      { job_id: "j1", attempt_id: "a1", action: "resume_from", resume_after_seq: 42, lease_id: lease },
      { job_id: "j0", attempt_id: "a0", action: "ack_pending" },
    ],
  },
  "hello.rejected": {
    id: "m3", ts: now, type: "hello.rejected", code: "expired_challenge", message: "nonce expired",
  },
  "lease.renew": {
    id: "m3a", ts: now, type: "lease.renew", job_id: "j1", attempt_id: "a1", lease_id: lease,
  },
  "lease.granted": {
    id: "m3b", ts: now, type: "lease.granted", job_id: "j1", attempt_id: "a1", lease_id: "l2", lease_ttl_ms: 120000,
  },
  "lease.revoke": {
    id: "m3c", ts: now, type: "lease.revoke", job_id: "j1", attempt_id: "a1", lease_id: lease, reason: "reassigned",
  },
  "job.assign": {
    id: "m4", ts: now, type: "job.assign",
    job_id: "j1", attempt_id: "a1", lease_id: lease, lease_ttl_ms: 120000,
    engine: "claude",
    workspace: { repo_root: "/Users/k/code/repo-a", base_sha: "deadbeef" },
    prompt: "Summarize the README.",
    sandbox: "read_only", approval_policy: "on_write",
    env_policy: env, network_policy: { mode: "off" },
    limits: { timeout_ms: 600000, max_output_bytes: 5_000_000 },
    created_at: now, assignment_start_timeout_ms: 30000,
  },
  "job.accept": {
    id: "m5", ts: now, type: "job.accept", job_id: "j1", attempt_id: "a1", lease_id: lease, agent_run_id: "run-1",
  },
  "job.reject": {
    id: "m6", ts: now, type: "job.reject", job_id: "j1", attempt_id: "a1", lease_id: lease,
    code: "policy_violation", message: "requested sandbox:full exceeds local maximum",
  },
  "stream.event": {
    id: "m7", ts: now, type: "stream.event", job_id: "j1", attempt_id: "a1", lease_id: lease,
    seq: 1, event_id: "e1", event: { kind: "assistant_text", text: "hello" },
  },
  "stream.ack": {
    id: "m8", ts: now, type: "stream.ack", job_id: "j1", attempt_id: "a1", lease_id: lease, ack_seq: 1,
  },
  "approval.request": {
    id: "m9", ts: now, type: "approval.request", job_id: "j1", attempt_id: "a1", lease_id: lease,
    request_id: "r1", tool_name: "Bash", input_summary: "rm -rf build/",
    redaction: { applied: false, truncated: false, byte_count: 12 }, risk: "high", approval_timeout_ms: 300000,
  },
  "approval.response": {
    id: "m10", ts: now, type: "approval.response", job_id: "j1", attempt_id: "a1", lease_id: lease,
    request_id: "r1", decision: "deny", decided_by: "remote_user",
  },
  "job.status": {
    id: "m11", ts: now, type: "job.status", job_id: "j1", attempt_id: "a1", lease_id: lease, status: "cancelled",
  },
  "job.result": {
    id: "m12", ts: now, type: "job.result", job_id: "j1", attempt_id: "a1", lease_id: lease,
    final_status: "success", exit_code: 0, duration_ms: 1234,
    stats: { event_count: 10, bytes: 4096 }, head_sha: "cafebabe",
  },
  "job.result.ack": {
    id: "m12a", ts: now, type: "job.result.ack", job_id: "j1", attempt_id: "a1", lease_id: lease, result_digest: digest,
  },
  "job.cancel": {
    id: "m13", ts: now, type: "job.cancel", job_id: "j1", attempt_id: "a1", lease_id: lease, reason: "user", grace_ms: 5000,
  },
  heartbeat: {
    id: "m14", ts: now, type: "heartbeat", active_attempts: ["a1"], capacity: { max_concurrent: 4, running: 1 },
  },
  "agent.draining": {
    id: "m15", ts: now, type: "agent.draining", reason: "update", eta_ms: 30000,
  },
  "capabilities.update": {
    id: "m16", ts: now, type: "capabilities.update",
    capabilities: { engines: { claude: { installed: true }, codex: { installed: false } }, project_roots: [] },
  },
  nack: {
    id: "m17", ts: now, type: "nack", ref_id: "m4", code: "lease_expired", message: "lease expired",
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

const checks: Array<[string, boolean]> = [
  // version negotiation (incl. the malformed-input edge cases Codex found)
  ["stable major match", negotiateVersion("1.4.0", ["1.0.0", "2.0.0"]).ok],
  ["stable rejects major 3", !negotiateVersion("3.0.0", ["1.0.0"]).ok],
  ["draft exact match", negotiateVersion(PROTOCOL_VERSION, [PROTOCOL_VERSION]).ok],
  ["draft rejects non-exact", !negotiateVersion(PROTOCOL_VERSION, ["1.5.0"]).ok],
  ["rejects empty agent version", !negotiateVersion("", [".1.0"]).ok],
  ["ignores malformed server entry", !negotiateVersion("1.2.3", ["1.x.y"]).ok],
  ["rejects empty server list", !negotiateVersion("1.2.3", []).ok],
  // strict: unknown top-level field is rejected (C1)
  ["strict rejects unknown field", !Message.safeParse({ ...(samples.hello as object), bogus: 1 }).success],
  // safe-integer bound (C2)
  ["rejects unsafe seq", !Message.safeParse({ ...(samples["stream.event"] as object), seq: 2 ** 53 }).success],
  // resume_from/resend_result must carry a lease_id (G3)
  ["resume_from requires lease_id", !Message.safeParse({ ...(samples["hello.accepted"] as object), resume: [{ job_id: "j1", attempt_id: "a1", action: "resume_from" }] }).success],
  // inbound direction + phase enforcement (C3)
  ["agent accepts s2a auth.challenge pre-auth", validateInbound(parseMessage(samples["auth.challenge"]), { receiver: "agent", authed: false }).ok],
  ["agent rejects a2s hello (bad_direction)", !validateInbound(parseMessage(samples.hello), { receiver: "agent", authed: false }).ok],
  ["agent rejects job.assign pre-auth (bad_state)", !validateInbound(parseMessage(samples["job.assign"]), { receiver: "agent", authed: false }).ok],
  ["agent accepts job.assign once authed", validateInbound(parseMessage(samples["job.assign"]), { receiver: "agent", authed: true }).ok],
  // --- v1.6 schema tightenings (5a) ---
  ["reject 44-char nonce", !Message.safeParse({ ...(samples["auth.challenge"] as object), nonce: "A".repeat(44) }).success],
  ["reject 42-char nonce", !Message.safeParse({ ...(samples["auth.challenge"] as object), nonce: "A".repeat(42) }).success],
  ["accept exact 43-char nonce", Message.safeParse({ ...(samples["auth.challenge"] as object), nonce: "A".repeat(43) }).success],
  ["reject non-ASCII agent_id", !Message.safeParse({ ...(samples.hello as object), agent_id: "agent-café" }).success],
  ["reject invalid agent_id (@)", !Message.safeParse({ ...(samples.hello as object), agent_id: "agent@host" }).success],
  ["accept valid AuthId agent_id", Message.safeParse({ ...(samples.hello as object), agent_id: "agent.dev_01-x" }).success],
  ["reject >64-char SemVer protocol_version", !Message.safeParse({ ...(samples.hello as object), protocol_version: `1.0.0-${"a".repeat(60)}` }).success],
  ["dedup'd SemVer validates good versions", SemVer.safeParse("1.2.3").success && SemVer.safeParse(PROTOCOL_VERSION).success],
  ["SemVer rejects >64 chars directly", !SemVer.safeParse(`1.0.0-${"a".repeat(60)}`).success],
  ["SemVer rejects +build metadata", !SemVer.safeParse("1.2.3+build").success],
];

// --- F4 cross-language auth vectors (5d): verify the committed test-vectors.json ---
const vectors = JSON.parse(
  readFileSync(new URL("./test-vectors.json", import.meta.url), "utf8"),
) as VectorsFile;

for (const v of vectors.positives) {
  const kp = deriveKeypairFromSeed(Buffer.from(v.ed25519_seed_hex, "hex"));
  const nonceRaw = Buffer.from(v.nonce_raw_hex, "hex");
  const transcript = buildTranscript({
    challenge_id: v.challenge_id, nonce_raw: nonceRaw, agent_id: v.agent_id, key_id: v.key_id,
    protocol_version: v.protocol_version, tenant_id: v.tenant_id, server_origin: v.canonical_server_origin,
  });
  const sig = Buffer.from(v.expected_signature_base64url, "base64url");
  // The wire fields embedded in this vector must themselves parse.
  const wireOk =
    Message.safeParse({ ...(samples["auth.challenge"] as object), challenge_id: v.challenge_id, nonce: v.nonce_base64url }).success &&
    Message.safeParse({
      ...(samples.hello as object),
      agent_id: v.agent_id,
      protocol_version: v.protocol_version,
      auth: { challenge_id: v.challenge_id, key_id: v.key_id, signature: v.expected_signature_base64url, alg: "ed25519" },
    }).success;
  const pass =
    kp.publicRaw.toString("hex") === v.ed25519_public_hex &&
    transcript.toString("hex") === v.transcript_hex &&
    lp(DOMAIN_TAG).toString("hex") === v.domain_tag_hex &&
    lp(ALG).toString("hex") === v.alg_lp_hex &&
    b64u(nonceRaw) === v.nonce_base64url &&
    v.nonce_base64url.length === 43 &&
    canonicalizeServerOrigin(v.input_server_origin) === v.canonical_server_origin &&
    validateTenantId(v.tenant_id) &&
    verify(null, transcript, kp.publicKey, sig) && // verify recomputed transcript with seed-derived key
    verify(null, transcript, publicKeyFromRaw(kp.publicRaw), sig) && // ...and with raw-imported key (cross-impl path)
    verify(null, Buffer.from(v.transcript_hex, "hex"), kp.publicKey, sig) && // ...and against the COMMITTED bytes (independent of buildTranscript)
    wireOk;
  checks.push([`vector+ ${v.label}: transcript+signature+wire`, pass]);
}

for (const v of vectors.negatives) {
  let pass = false;
  switch (v.failure_mode) {
    case "parse": {
      const base = samples[v.wire_message as MessageType] as object;
      const res = Message.safeParse({ ...base, [v.field as string]: v.value });
      // Must fail AND fail on the patched field — guards against base-sample drift
      // silently making a negative pass for the wrong reason (Codex P2 review).
      pass = res.success ? false : res.error.issues.some((i) => i.path[0] === v.field);
      break;
    }
    case "origin":
      pass = canonicalizeServerOrigin(v.input_server_origin as string) === null;
      break;
    case "tenant":
      pass = !validateTenantId(v.tenant_id as string);
      break;
    case "signature": {
      const kp = deriveKeypairFromSeed(Buffer.from(v.ed25519_seed_hex as string, "hex"));
      const transcript = buildTranscript({
        challenge_id: v.challenge_id as string, nonce_raw: Buffer.from(v.nonce_raw_hex as string, "hex"),
        agent_id: v.agent_id as string, key_id: v.key_id as string, protocol_version: v.protocol_version as string,
        tenant_id: v.tenant_id as string, server_origin: v.canonical_server_origin as string,
      });
      const sig = Buffer.from(v.expected_signature_base64url as string, "base64url");
      pass = !verify(null, transcript, kp.publicKey, sig); // signature must NOT verify
      break;
    }
  }
  checks.push([`vector- ${v.label} (${v.failure_mode}): rejected`, pass]);
}
for (const [label, pass] of checks) {
  console.log(pass ? `✓ ${label}` : `✗ ${label}`);
  if (!pass) failures++;
}

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log(`\nAll ${allTypes.length} message types valid.`);
