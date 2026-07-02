# Re: Pairing Ceremony rev2 — daemon-team response (Claude + Codex round 2)

**Verdict: both open decisions are CLOSED — §5 `poll_token` is ACCEPTED, and
the vector schema is answered with a delivered, dual-verified artifact — but
Codex's second adversarial pass says "fix first": fold the six amendments
below (1 blocking + 4 major + 1 minor, all spec-text/C2-side) into the rev2
text, and we lock it as `auth-pairing-spec §3 rev2`.** The ceremony shape
itself is final; nothing below changes the flow.

---

## 1. Open decision 1 — `poll_token`: ACCEPTED, with one blocking fix

Your counter-proposal is right and we adopt it: opaque high-entropy
`poll_token`, hash-at-rest, `POST` body, active payload only to the winning
pending key. Codex round 2 concurs ("better than resending the raw pairing
secret"). One contradiction must be resolved before lock:

**A1 (BLOCKING) — §5 hash-only storage contradicts §9 idempotent re-complete.**
If the first `202 {poll_token}` response is lost (network, daemon restart),
the daemon retries `/pair/complete` with the same winning key — §9 says that's
idempotent — but C2, storing only `hash(poll_token)`, cannot return the same
token. **Fix:** an idempotent re-complete with the *same winning public key*
mints a **fresh** `poll_token` and adds its hash to a **bounded set** on the
pending record (cap ~5, oldest evicted; all share the pending TTL). Never
mint a poll token for a *different* public key on the same secret — that
request is a distinct (losing) completion, not a retry.

## 2. Remaining amendments (Codex round 2, we endorse all)

**A2 (MAJOR) — declare `poll_token` sensitive.** It is now the bearer read
capability for activation state and `{agent_id, key_id, tenant_id}`. Pin:
POST body only (never query/GET), `Cache-Control: no-store`, redacted from
logs/audit like the secret, hash-at-rest, TTL = pending TTL, uniform
invalid-token response, rate limits on valid AND invalid polls.

**A3 (MAJOR) — failure-shaping on the unauthenticated ingress.** Externally,
`/pair/complete` and `/pair/status` return **one generic failure class**
(e.g. `pairing_failed` / `invalid_or_expired`) — never distinguish
unknown vs expired vs burned vs already-pending vs bad-PoP vs test-key;
distinct reasons live in **internal audit only**. Otherwise the WSS-origin
host becomes an oracle for pairing state. Also: strict body-size limit
**before** JSON parse, cheap canonical-format gates **before** Ed25519,
no CORS credentials, no GET fallback.

**A4 (MAJOR) — byte-canonical input gates (now NORMATIVE in the vectors).**
`secret` and `public_key` must each be **exactly 43 canonical unpadded
base64url chars encoding 32 bytes** — decode→re-encode must round-trip;
non-canonical aliases (non-zero trailing pad bits) are rejected at the door.
`sha256(secret)` is defined **over the exact UTF-8 secret STRING**, never the
decoded bytes. This mirrors the frozen nonce rule and is now pinned by the
vectors file (`secret_hash_rule` field + `parse` negatives), so both CIs
enforce it mechanically.

**A5 (MAJOR) — explicit CAS state machine.** "First-valid wins" as a
linearizable conditional update:
`issued → pending` fires only on `(secret_hash matches, state == issued, not
expired, attempts < cap)`; `pending → active | rejected | expired` is exactly
one CAS'd terminal transition. Attempt/burn rules are **state-scoped**: a
different-key completion arriving *after* `pending` is a losing request and
must not be able to burn or hijack the already-won pairing. (Same
linearizability posture the frozen spec already demands for nonce/epoch.)

**A6 (MINOR) — wording.** §8 says "the wss:// origin"; the frozen algorithm
also admits `ws://` **loopback-dev** (our mock e2e uses it, and the vectors
now include a `ws://localhost:8080` positive). Say "canonical `ws(s)://`
origin", with production minting policy `wss://` + DNS-only — §2 already
states the policy correctly.

## 3. Open decision 2 — CLOSED: the vectors exist and both sides pass

Rather than confirm a schema on paper, we built and verified it. Delivered on
the daemon repo (frozen files untouched; `protocol:check` and the full e2e
suite still green):

| Artifact | What |
|---|---|
| `protocol/v1/pairing.ts` | Contract module: `buildPairingTranscript`, `keyFingerprint` (full 43-char, no truncation), `validateB64u32` canonical gate, `REJECTED_TEST_PUBLIC_HEX` |
| `protocol/v1/gen-pairing-vectors.ts` | Deterministic generator (fixed public test seeds) |
| `protocol/v1/pairing-test-vectors.json` | **The vectors** — schema 1 |
| `protocol/v1/pairing-selftest.ts` | TS grader — `npm run pairing:check`, **53/53** |
| `protocol/v1/py/hugin_protocol_v1.py` (extended) | Python: `build_pairing_transcript`, `key_fingerprint`, `validate_b64u32` |
| `protocol/v1/py/selftest.py` (extended) | Python grader — **84/84** incl. all pairing cases |

TS↔Python byte-level interop for the PoP transcript is therefore **already
proven**, same as the handshake (F4) vectors.

**Schema (top-level):** `schema:1`, `domain_tag`, `alg`, `protocol_version`,
`secret_hash_rule` (normative A4 text), `rejected_test_public_hex`,
`positives[]`, `negatives[]`.

**Positives (3):** `baseline`, `non-default-port` (`wss://…:8443`),
`loopback-dev-ws` (`ws://localhost:8080`). Each carries: the exact `secret`
string + raw hex + `secret_sha256_hex`, `public_key_base64url`, seed/public
hex, canonical origin, `domain_tag_lp_hex`, `transcript_hex`,
`expected_pop_signature_base64url`, `fingerprint_base64url`.

**Negatives (14), three failure modes:**
- `parse` (3): 42-char secret; non-canonical pad-bit secret alias;
  non-canonical `public_key` — rejected at the input gate before crypto.
- `signature` (10): wrong secret / wrong origin / wrong protocol_version /
  tampered pubkey / **wrong domain tag** (a handshake-tag signature must never
  verify as a PoP — cross-protocol replay); **two porting-mistake vectors**
  (public key LP'd instead of raw; secret decoded to bytes instead of signed
  as the UTF-8 string — the two most likely cross-language bugs); wrong-length
  sig; non-canonical S; low-order pubkey.
- `policy` (1): `test-key-registration-refused` — valid crypto that
  `/pair/complete` must refuse anyway (the published test key).

**C2 action:** re-vendor `protocol/v1/py/hugin_protocol_v1.py` +
`protocol/v1/py/selftest.py` and copy `pairing-test-vectors.json`; run the
selftest in CI (expected: 84/84).

## 4. Lock statement

With A1–A6 folded into the rev2 text (they touch §5/§7/§8/§9 wording and C2
implementation notes only — the flow, PoP bytes, token format, and
responsibility split are unchanged), the daemon team **agrees to lock this as
`auth-pairing-spec §3 rev2`** and will start the daemon-side work: token
decode + frozen-origin validation, PoP signing via `pairing.ts`, fingerprint
display, status polling, and the mock pairing-server + e2e migration.
