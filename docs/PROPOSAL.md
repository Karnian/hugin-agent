# Freeze Record — Wire Protocol v1.6 → v1.0.0 (FROZEN)

**Status:** cloud diff-review **complete → FREEZE-OK (0 blockers)**; Codex
independently reproduced the auth transcript + signatures. `1.6.0-draft` is frozen
as **`v1.0.0`** with the pre-tag nits applied (vectors regenerated at `1.0.0`,
strict-Ed25519 + nonce-canonical negatives — see [CHANGELOG](../CHANGELOG.md)).
This doc is retained as the freeze record. Remaining cloud-side items are
post-freeze production gates, not freeze blockers.

## Where we are

Six review rounds (cloud ×2, Codex ×3, plus a brief review) since v1.2. v1.6 is the
last mechanical pass: it closes the cloud `CONDITIONAL-GO` items **F1–F6** and the
Codex findings **A/B/C**, with **no wire redesign**. Conformance is green —
**23/23 messages + strict / safe-integer / direction-phase / refine checks + F4
cross-language auth vectors** (`npm run typecheck` + `npm run protocol:check`).
History in [CHANGELOG](../CHANGELOG.md); contract in
[protocol/README](../protocol/README.md); security in
[auth-pairing-spec](auth-pairing-spec.md).

## Closed in v1.6

| Item | Resolution |
|------|------------|
| **F1** nonce length | `auth.challenge.nonce` exact length 43 (base64url, unpadded). |
| **F2** `server_origin` | Canonical form is normative; the verifier **rejects** non-canonical input — DNS-only in production, `ws://` loopback-only, default ports omitted, port 0 / trailing-dot / zone-id / raw-IDN rejected. Reconstructed by the verifier — not on the wire. |
| **F3** `tenant_id` | Grammar `1*128(ALPHA/DIGIT/-/_/.)` (≤128); stable for the key lifetime; no silent cross-tenant rebind. |
| **F4** test vectors | Deterministic cross-language Ed25519 vectors (`v1/test-vectors.json`) — positives sign-match, negatives fail; verified by `protocol:check`. |
| **F5** linearizability | Made concrete: atomic nonce-consume, per-`agent_id` monotonic `connection_epoch`, CAS/fenced lease ownership; acceptable vs unacceptable stores enumerated. Single-POP; cross-POP out of MVP. |
| **F6** unknown `event.kind` | Closed `EventKind` enum → an unknown **core** kind parse-rejects → the daemon/relay NACKs `invalid_message`; engine extras via `vendor.<engine>.*`. |
| **Codex A** `SemVer` | Deduped to one definition, bounded ≤64; `+build` rejected. |
| **Codex B** signed ids | `challenge_id`/`agent_id`/`key_id` use a strict ASCII `AuthId` (defeats UTF-16-vs-byte signature mismatch). |
| **Codex C** `EventKind` vs same-major compat | Resolved by the **EventKind Option A** decision below. |

## Locked decisions (no longer open)

1. **`event.kind` core list is FROZEN for v1** (EventKind Option A). A new *core*
   kind is a major bump (v2); engine-specific events use `vendor.<engine>.*` only.
   This **supersedes** the earlier "membership deferred to adapter lock" note —
   there is no deferred membership; the core set is final at freeze.
2. **`agent_id` is per-device**, under a **user 1:N agent** layer:
   `tenant_id > user_id > agent_id (one device/daemon) > engines[]`. The wire is
   unchanged — `agent_id` stays per-device; `user_id` is **off-wire** (pairing
   record + pairing response + audit events). The signed transcript binds
   `tenant_id` only; `agent_id` represents the (user, device) pair.

## Remaining items — post-freeze operational confirms (NOT blockers)

Operational parameters, not wire/transcript shape; they do **not** block `v1.0.0`
and can be confirmed after freeze (strawman values in
[auth-pairing-spec §11](auth-pairing-spec.md)):

- Rotation grace window + max concurrent `key_id`s per host.
- Pairing-code TTL, device limits, re-pair UX.
- Audit event schema for pair/rotate/revoke.

Plus the standing, already-agreed deferral: per-job credit-window flow control →
Phase 2 (v1 enforces static caps independent of the `capacity` hint).

## Cloud verdict (received)

1. **Diff-review → FREEZE-OK (0 blockers)**, with Codex independently reproducing
   the auth transcript + signatures. F1–F6 + Codex A/B/C closed; two pre-tag nits
   applied — vectors regenerated at the signed `protocol_version:"1.0.0"`, plus
   strict-Ed25519 and nonce-canonical negatives (see [CHANGELOG](../CHANGELOG.md)).
2. **Cloud-side commitments** (your §D): [AFFIRMED] durable stream log keyed by
   `(attempt_id, seq)`/`(attempt_id, event_id)` with ack-after-commit + result
   durability-before-ack. [CONDITIONAL on PG-concurrency tests] single-use
   nonce/replay, monotonic `connection_epoch`, lease CAS/fencing. [GAP — production
   gates, not freeze blockers] real §5 Ed25519 verification, static quota
   enforcement, approval binding. Single logical POP assumed (cross-POP out of MVP).

## Freeze outcome

`-draft` dropped across `messages.ts` + spec → **`v1.0.0`** (committed). The shared
package `@contextualai/hugin-agent/protocol` is the single import for both
codebases (preferred over codegen — no generator drift).

**Sequencing:** mock-relay `hugind` development (daemon skeleton, WSS dial-out,
Claude adapter, non-auth job/stream/cancel paths) is underway. The **production
auth path** is unblocked now that `tenant_id` / `server_origin` formats and the
canonical transcript are frozen (F1–F5), so pairing/handshake builds against the
F4 vectors without rework.
