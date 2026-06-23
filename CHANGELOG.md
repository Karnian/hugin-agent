# Changelog — Wire Protocol

All notable changes to the `hugind ↔ orchestrator` wire contract. The protocol is
**frozen at v1.0.0** (cloud diff-review: FREEZE-OK, 0 blockers); entries below
1.0.0 are draft history.

## [1.0.0] — 2026-06-23

**FROZEN.** Cloud diff-review returned **FREEZE-OK (0 blockers)**, with Codex
independently reproducing the auth transcript + positive signatures. Frozen from
`1.6.0-draft`; the wire shape is unchanged. Pre-tag nits applied:

- Auth test vectors **regenerated with the signed `protocol_version: "1.0.0"`**
  (the version is part of the signed transcript, so signatures change).
- Added strict-Ed25519 negative vectors — non-canonical S, low-order public key,
  wrong signature length — plus nonce **canonical base64url** negatives (invalid
  alphabet, non-zero trailing pad bits). `nonce` now requires canonical base64url
  at parse. `protocol:check` = 73 checks (2 positive + 18 negative F4 vectors).
- Recorded the cloud-side condition for the off-wire `user_id` model: the relay
  MUST enforce active `(tenant_id, agent_id)` uniqueness / no cross-user reuse and
  resolve `user_id` only from the pairing record (auth-spec §2).

Post-freeze production gates (NOT freeze blockers, cloud-side): real §5 Ed25519
verification, PG-concurrency tests for nonce/epoch/lease, static quota
enforcement, approval binding.

## [1.6.0-draft] — 2026-06-23

Mechanical pre-freeze pass — closes cloud F1–F6 and Codex A/B/C. No redesign.
Locks two decisions: the `event.kind` core list is **frozen** for v1 (no longer
"deferred"), and `agent_id` is **per-device** under a `user_id` 1:N layer
(`user_id` off-wire).

### Fixed (messages.ts)
- **F1** — `auth.challenge.nonce` is exact length 43 (was `min(43).max(44)`).
- **Codex B** — `challenge_id` / `agent_id` / `key_id` use a strict `AuthId`
  charset (`^[A-Za-z0-9._-]{1,128}$`; ASCII, no `:`). These enter the signed
  transcript, so a loose `Id` risked UTF-16-vs-byte signature mismatches.
- **Codex A** — `SemVer` deduped into `messages.ts` (was also copied in
  `index.ts`), bounded to ≤64 chars; `+build` metadata stays intentionally rejected.
- Removed the dead `SIG_MAX` constant (superseded by `Ed25519Sig`).

### Added
- **F4** — cross-language auth **test vectors**: `v1/gen-vectors.ts` →
  `v1/test-vectors.json` (deterministic Ed25519 from a fixed seed; canonical
  transcript per auth-spec §5; positive + negative vectors). Loaded and verified
  by `selftest.ts` — positives must sign-match, negatives must fail.
- **F6 / EventKind Option A** — documented in README "Event kinds": unknown
  **core** kind → NACK; unknown **vendor** kind → may be ignored/passed through;
  the core list is frozen (no `non-critical` field — cores can't be unknown-but-ok).

### Changed (auth-pairing-spec.md)
- **F2** — `server_origin`: REJECT non-canonical input (no silent normalize);
  DNS-only in production, `ws://` loopback-only, default ports omitted, port 0 /
  trailing-dot / zone-id / raw-IDN rejected, lowercase after IDNA.
- **F3** — `tenant_id`: grammar `1*128(ALPHA/DIGIT/-/_/.)` (≤128; was ≤64 in
  §2/§11); stable for the key lifetime; no silent cross-tenant rebind.
- **F5** — linearizability made concrete: atomic nonce-consume, per-`agent_id`
  monotonic `connection_epoch`, CAS/fenced lease ownership; OK/NOT-OK store list.
- Identity model `tenant_id > user_id > agent_id(device) > engines`; `user_id`
  lives in the pairing record/response/audit, never on the wire.
- Clarified: all base64url unpadded; `server_origin`/`tenant_id` reconstructed by
  the verifier (not in `hello`); transcript `protocol_version` = exact `hello`
  value; `challenge_ttl_ms` advisory.

### Version
- `PROTOCOL_VERSION` → `1.6.0-draft`.

## [1.5.0-draft] — 2026-06-23

Freeze-readiness pass (third cross-review follow-up). Closes G1–G4; G5
(identifier formats) has a proposed value pending cloud confirmation.

### Fixed
- Crypto fields are exact-length: Ed25519 `signature` = 86, SHA-256
  `result_digest` = 43 base64url chars (were loosely `max(88)`/`max(44)`).

### Added
- `LIMITS.LEASE_ROTATION_OVERLAP_MS` + `PendingResult.lease_id`; `lease.granted`
  doc now matches the README overlap rule (no false-nack of in-flight messages).
- `ResumeDirective` enforces `lease_id` for `resume_from`/`resend_result`
  (was documented-but-not-enforced).

### Changed
- README "Still open" aligned with the auth spec — multi-region/cross-POP is out
  of MVP scope; `tenant_id`/`server_origin` formats proposed for confirmation.

## [1.4.0-draft] — 2026-06-23

Folds in a third cross-review (pre-freeze). Closes the auth/crypto + lease
precision gaps that blocked the freeze.

### Protocol (messages.ts)
- `ResumeDirective.lease_id` — `resume_from`/`resend_result` now carry the lease
  generation to stamp on resent attempt messages.
- Fixed-size crypto fields: Ed25519 `signature` (64B), SHA-256 `result_digest`
  (32B) — were loosely `max`-bounded.
- `exit_code` is a bounded signed integer (was unbounded).

### Auth/pairing spec
- `key_id` added to the signed transcript (defeats key substitution).
- Canonical `result_digest` defined — RFC 8785 JCS over job.result minus id/ts.
- Ed25519 verification made normative (key/sig sizes, canonical-S, low-order
  rejection, no batch). `server_time`/`challenge_ttl_ms` documented as unsigned.
- Single-POP / linearizable-store assumption stated; multi-region out of scope.
- Provider-token isolation model made normative (env scrub, path deny, network).

### Protocol spec (README)
- `lease.granted` rotation overlap window — no false-nack of in-flight messages.

## [1.3.0-draft] — 2026-06-23

Folds in two cloud-side reviews (cloud team + Codex). Largest revision so far:
lease fencing, removed `session_id`, relative-duration authority, broad hardening.

### Added
- `lease_id` on **every attempt-scoped message, both directions** (fencing
  token); `lease.granted` rotates it. `connection_epoch` fences older WSS sessions.
- `PendingResult.result_digest`/`result_size`/`last_emitted_seq`,
  `JobResultAck.result_digest`, `resend_result` resume directive — replay now
  distinguishes "payload acked" from "id acked".
- `key_id` on `hello.auth`; 32-byte base64url nonce; `LIMITS` constants (flow
  caps, ack flush, lease/heartbeat/approval/nonce values).
- `validateInbound()` enforcing DIRECTION + pre-auth handshake phase.
- `NackCode`: bad_direction, bad_state, payload_too_large, unknown_attempt,
  lease_expired, policy_violation. `JobReject.policy_violation`.
- Strict objects (unknown fields rejected), safe-integer bounds, semver-typed
  version fields, bounded strings/arrays, core `event.kind` enum + vendor namespace.

### Changed
- Authoritative expiries → relative `*_ms` (`challenge_ttl_ms`, `lease_ttl_ms`,
  `assignment_start_timeout_ms`, `approval_timeout_ms`); ISO kept for audit only.
- `auth.alg` Ed25519-only (ECDSA dropped). `decided_by` → remote-only enum.
- `approval.request.redacted` (bool) → structured `redaction{applied, truncated, byte_count}`.
- `active_jobs` restricted to non-terminal status.

### Removed
- `job.assign.session_id` — engine resume/fork is out of MVP scope and was a
  cross-job leak surface.

### Deferred to a standalone auth/pairing security spec
- Canonical signing bytes, pairing/registration, key rotation/revocation.

## [1.2.0-draft] — 2026-06-23

Folds in a second-pass cross-review. Hardens the handshake and fixes
inconsistencies the review caught in 1.1.

### Added
- `JobStatus.cancelled` — 1.1 updated the diagram but not the enum, leaving the
  state machine inconsistent with `FinalStatus`. Now consistent.
- `auth.challenge.challenge_id` + `expires_at`; `nonce` is now ≥256-bit. The
  `hello.auth` signature covers the transcript
  `challenge_id|nonce|agent_id|protocol_version|alg`, not the bare nonce (which
  was replayable).
- `PendingResult.final_status` + `ResumeDirective.ack_pending` — explicit path
  to confirm a stored terminal result on reconnect.
- `negotiateVersion` strict-semver input validation + regression tests
  (`negotiateVersion("", [".1.0"])` used to return ok).

### Changed
- `FinalStatus` trimmed to {success, error, cancelled, timeout}. `rejected`
  removed — a refused assignment ends at `job.reject`, never `job.result`.

### Corrected (1.1 overstatements)
- "can't be lost on crash" holds **only if** the daemon durably stores the full
  `job.result` payload locally; `pending_results` is just the index. Now stated
  in the spec.
- "cancelled transitions now match FinalStatus" was false in 1.1 (the enum
  lacked `cancelled`); fixed here.

## [1.1.0-draft] — 2026-06-23

Folds in the first cloud-side review. Themes: authenticate the handshake, make
reconnect/lease/result durability coherent, and lock down approval security.

### Added
- `auth.challenge` (s2a) + `hello.auth` signature — prove possession of the
  paired device key before any job flows. Previously `agent_id` had no proof.
- `lease.renew` / `lease.granted` / `lease.revoke` — explicit lease fencing
  instead of relying on connection liveness alone.
- `job.result.ack` (s2a) + `hello.pending_results` — terminal results are now
  durably acked and replayed on reconnect, so they can't be lost on crash.
- `approval.request.expires_at` + `redacted` flag — bounded approval wait with
  auto-deny; redaction is now a declared field, not just a comment.
- `heartbeat.capacity` — backpressure/concurrency headroom hint.

### Changed
- `approval.response.decided_by` is now an enum
  (`remote_user | local_user | policy | system`) — an open string let a remote
  response spoof `local_user`.
- `job.assign.prompt` is length-bounded (100k chars) — was unbounded (DoS / log
  pollution / injection surface).
- `negotiateVersion()` is prerelease-aware: drafts require an **exact** match;
  the old major-only check let `1.0.0-draft` match `1.999.0`.
- Job/lease state machines in the spec now show `cancelled` and `starting →
  failed` transitions explicitly, matching `FinalStatus`.

### Removed
- `approval.response.updated_input` — the server can no longer rewrite tool
  input (remote command-injection surface). Allow/deny only; the daemon owns
  any local re-application of policy.

## [1.0.0-draft] — 2026-06-22

Initial strawman: outbound-only WSS contract with `hello`/`capabilities`,
`job.assign`, `stream.event`/`stream.ack`, `approval.request`/`response`,
`job.result`, `job.cancel`, `heartbeat`, `nack`/`error`, and lease/seq/ack
scaffolding.
