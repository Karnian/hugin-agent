# Freeze Review Request — Wire Protocol v1.5 → v1.0.0

**To:** cloud team. **Ask:** confirm the one remaining item (§G5) + two
deferrals; then we drop `-draft` and freeze `v1.0.0`.

## Where we are

Five review rounds (cloud ×2, Codex ×3) since v1.2. Each found less —
big design gaps → security/contract → precision → crypto lengths → naming.
All blockers are now closed in the schema/spec. Conformance: **23/23 messages +
strict / safe-integer / direction-phase / refine checks** (`npm run protocol:check`).
Full history in [CHANGELOG](../CHANGELOG.md); contract in
[protocol/README](../protocol/README.md); security in
[auth-pairing-spec](auth-pairing-spec.md).

## Blocker closure checklist

| From | Item | Status |
|------|------|--------|
| cloud B1 | lease fencing both directions + rotation (overlap window) | ✅ |
| cloud B2 | `connection_epoch` (fence older sessions) | ✅ |
| cloud B3/B4 | auth proof + canonical signing bytes (transcript w/ `key_id`) | ✅ spec §5 |
| cloud B5 | result digest + `resend_result` | ✅ |
| cloud B6 | `session_id` cross-job leak | ✅ removed |
| cloud B7 | `decided_by` remote-only | ✅ |
| cloud B8 | safety downgrade → `policy_violation` reject (no clamp) | ✅ |
| Codex | strict objects, safe-int, `validateInbound`, semver, NackCode | ✅ |
| Codex G1–G4 | exact crypto lengths, lease overlap, lease coverage, multi-region doc | ✅ |

## What we need from you

1. **§G5 — confirm identifier formats.** They enter the signed transcript, so
   they must be fixed before production auth. **Proposed:**
   - `tenant_id` = opaque ASCII ≤64 chars, issued in the pairing response
   - `server_origin` = `wss://host[:port]`, lowercase, no path/query, as dialed
2. **Confirm deferrals** (not freeze blockers — agree they're post-freeze):
   - Per-job credit-window flow control → Phase 2 (static caps + `capacity` now)
   - Final `event.kind` core-enum membership → when the claude/codex adapters lock
3. **Re-affirm cloud-side commitments** (your §D): linearizable
   `(job_id, attempt_id, lease_generation)` leasing, durable stream log keyed by
   `(attempt_id, seq)`/`(attempt_id, event_id)` with ack-after-commit, global
   nonce/replay store, quotas, approval binding. Single logical POP assumed
   (cross-POP is out of MVP scope).

## On freeze

Once §1 is confirmed we drop `-draft` across `messages.ts` + spec → **`v1.0.0`**.
The shared package `@contextualai/hugin-agent/protocol` becomes the single import
for both codebases (preferred over codegen — no generator drift).

**Sequencing:** mock-relay `hugind` development (daemon skeleton, WSS dial-out,
Claude adapter, non-auth job/stream/cancel paths) can start in parallel now. The
**production auth path waits on §1** — `tenant_id`/`server_origin` are signed, so
implementing pairing/handshake before they're fixed means redoing the signing
bytes.
