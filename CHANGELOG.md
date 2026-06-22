# Changelog — Wire Protocol

All notable changes to the `hugind ↔ orchestrator` wire contract. The protocol
is a draft strawman; nothing here is frozen until the `-draft` suffix is dropped.

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
