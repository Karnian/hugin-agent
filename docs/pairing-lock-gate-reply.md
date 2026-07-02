# Lock-gate result (daemon side, Claude + Codex final pass): 2 pins, then LOCKED

**Verdict: the ceremony is final — no structural change requested. Two spec-text
pins are missing (both flagged Codex-MAJOR as TS↔Python interop gaps); add P1
and P2 below and the lock stands. Daemon-side implementation starts as soon as
these land.** Fidelity was verified against the repo, not just the text: Codex
re-derived the §8 bytes from vendored `pairing.ts`, matched every vector
label/failure-mode against §4/§8, and reproduced the Python selftest 84/84.
A1–A4 + A6: fully incorporated. A5: one gap (P1).

## P1 (MAJOR) — define the attempt-cap burn CAS

§9 requires `attempts < cap` and says invalid PoP increments `attempts` while
`state='issued'`, but never defines the `issued → burned` transition itself.
Pin normatively:

- **What counts:** a `/pair/complete` that **matched the secret_hash** and did
  not become the winner or an idempotent same-winner retry — i.e. secret-bound
  semantic failures (invalid PoP, test-key, low-order key) **while
  `state='issued'` only**. Gate failures before record lookup (body size,
  non-canonical b64u, unknown secret) never count; post-`pending` different-key
  completions never count (already pinned).
- **The transition:** increment + conditional burn is **one linearizable
  statement** — e.g.
  `UPDATE pairings SET attempts = attempts + 1,
   state = CASE WHEN attempts + 1 >= cap THEN 'burned' ELSE state END
   WHERE secret_hash = ? AND state = 'issued'`.
  The cap-reaching failure increments and burns atomically; no separate
  read-then-burn.

## P2 (MAJOR) — pin the wire shapes of the two unauthenticated endpoints

Exact JSON + HTTP codes, mirrored in daemon tests. Proposal (accept or amend,
but pin ONE):

| Case | Response |
|---|---|
| `/pair/complete` — winner AND every idempotent same-winner retry (whether the pairing is `pending` or already `active`) | `202 {"status":"pending","fingerprint":"<43-char b64u>","poll_token":"<b64u>"}` — complete never reveals state; the daemon learns `active` from status |
| `/pair/complete` — any semantic failure | `400 {"error":"pairing_failed"}` (single class, A3) |
| `/pair/status` — valid token | `200 {"status":"pending"}` \| `200 {"status":"active","agent_id":"…","key_id":"…","tenant_id":"…"}` \| `200 {"status":"rejected"}` |
| `/pair/status` — unknown/expired/foreign token | `404 {"error":"invalid_or_expired"}` (uniform) |
| transport | `413 body_too_large`, `429 rate_limited` (distinct OK, as locked) |

## P3 (MINOR) — `/pair` mint is also a bearer-secret response

§12's `Cache-Control: no-store` + redaction currently covers only
`complete/status`; the authenticated `/pair` mint response carries the `hpk1`
token (the secret). Add it to the same rule.

## P4 (NIT) — wording

§4 "pop_signature 86 chars" → "86 **unpadded base64url** chars, verified by the
vendored **strict** verifier" (length-only checks are not conformant).

## Informational (no action required to lock)

"Never extends TTL" (§5) creates one availability corner: a daemon that stays
down longer than the pending TTL *after* the user confirmed gets a born-expired
poll_token on re-complete and can never fetch its credentials — safe
(fail-closed) but ends in a re-pair. Our CLI will surface it as "re-pair this
device". If C2 wants to close it, allowing post-`active` same-winner re-complete
to mint a token with a fresh short TTL would do it; C2's choice.

— With P1 + P2 folded in (P3/P4 trivial), **LOCK STANDS**. We begin the daemon
work: token decode + frozen-origin validation, PoP via `pairing.ts`,
fingerprint display, status polling, mock pairing-server + e2e migration, and
the `auth-pairing-spec §3` text swap.
