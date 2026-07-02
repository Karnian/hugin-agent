# Re: Pairing Ceremony Agreement — daemon-team review (Claude + Codex, adversarial)

**Verdict: the ceremony DIRECTION is accepted — browser-initiated, PoP-bound,
with activation. The current TEXT is rejected.** Two independent reviews
(Claude cross-checked against the frozen contract; Codex adversarial with
file:line citations) converged on six blocking defects. All are fixable without
touching the frozen v1.0.0 wire; the revised terms below are our counter-text.
Codex's one-line verdict: *"Reject as-is. The proposal conflicts with frozen
v1.0.0 origin and `hello` semantics, and the browser-initiated flow is not
secure unless activation is mandatory and fully specified."*

---

## 1. Blocking defects (must fix; both reviewers unless noted)

**B1 — §6 origin algorithm contradicts the frozen contract.** Frozen
`canonicalizeServerOrigin` (protocol/v1/origin.ts:8,46) **rejects**
non-canonical input; it never normalizes. Your examples
(`WSS://Example.COM:443/ → wss://example.com`) directly contradict the frozen
F4 negatives `origin-uppercase-host` and `origin-explicit-default-port`
(test-vectors.json), which both sides' CI already gates on. → **Fix:** there is
no new algorithm. C2 **mints** the origin already-canonical; the daemon
validates with the frozen algorithm and **fails closed** on non-canonical input
("re-copy the token"). No normalizing vectors are added; the existing F4
origin cases stand.

**B2 — §6 scheme/IP rules conflict with frozen v1.** Frozen v1 allows
`ws://` for **loopback dev** (origin.ts:24 — our mock-relay e2e depends on it)
and rejects **all non-loopback IP literals** (origin.ts:33 — production is
DNS-only). Your `wss://[2001:db8::1]` example is **invalid under v1**. →
**Fix:** separate *algorithm* from *policy*. The shared algorithm stays the
frozen one (ws-loopback allowed, DNS-only otherwise). "Production tokens are
`wss://` + DNS host only" is a C2 **minting policy** on top — we agree with
that policy.

**B3 — §8 `tenant_id` in `hello` is impossible.** Frozen `Hello` is
`z.strictObject` with **no `tenant_id` field** (messages.ts:277); an unknown
key is parse-rejected (selftest enforces this). `tenant_id` is off-wire by
design — bound via the signed transcript, reconstructed by the verifier from
the pairing record (auth-pairing-spec §5). Adding the field = v2 wire change.
→ **Fix:** strike the sentence. Nothing is lost: a tenant mismatch already
fails the signature.

**B4 — activation must be REQUIRED, and its mechanics are unspecified.**
(Codex: "activation cannot be optional"; PoP-only is rejected.) The proposal
itself concedes PoP doesn't stop a stolen-token attacker registering their own
key — and B5 below removes the token-integrity defense you were counting on.
Also, as written step 6 is unimplementable: with a pending key, the
`/pair/complete` HTTP response returns **before** the user confirms, so there
is no channel to deliver `{agent_id, key_id, tenant_id}`. → **Fix:**
activation is mandatory (drop the PoP-only branch), and the flow is:
`POST …/pair/complete` → `202 {status:"pending", fingerprint}`; daemon then
polls `GET …/pair/status?secret_hash=…` (or long-poll) until
`{status:"active", agent_id, key_id, tenant_id}` / `rejected` / `expired`.
Pending keys have their own TTL (strawman 10 min). The daemon CLI prints the
fingerprint and tells the user to compare + confirm in the browser.

**B5 — the `hpk1` token is NOT an "integrity-checked envelope"** *(Codex-only
catch — we endorse it).* `base64url(json)` has no MAC or signature; anyone who
can alter the pasted command can swap `origin` while keeping `secret`. The
daemon would then send the bearer secret (and a PoP over the attacker's
origin) to the attacker's endpoint, who can still complete against real C2
with **their own** key. A MAC can't fix this — the daemon has no pre-shared
key to verify it with. → **Fix:** strike the claim "binding origin+secret in
one token is what defeats swap-the-URL". The token's origin binding defends
against *accidental drift* only; **the mandatory fingerprint confirmation (B4)
is the control against active substitution** — which is exactly why it can't
be optional.

**B6 — step 4's URL is impossible** *(Codex-only catch).* You can't
`POST https://…` to a `wss://` origin, and `server_origin` is frozen as
`ws(s)://`. The current daemon already separates the HTTPS pairing base from
the WSS relay URL (src/auth/connect.ts:47,52). → **Fix:** the token carries
the **single canonical `wss://` origin** (the one signed in PoP and every
handshake); pairing endpoints are derived **deterministically**: swap scheme
`wss→https` (`ws→http` for loopback dev), keep host and port. So
`wss://relay.example.com` → `https://relay.example.com/api/v1/hugin-agents/pair/complete`
and `…/pair/status`.

## 2. Major fixes

**M1 — PoP transcript bytes, pinned (answers your §10.3).** We accept the tag
and field order; the unresolved choices are resolved as:

```
pairing_transcript =
    LP("hugin-pair-pop-v1")        # domain tag
  ‖ LP(secret)                     # the 43-char base64url secret STRING, UTF-8
                                   #   (not its hash, not decoded bytes — C2 has
                                   #    the plaintext at completion and can rebuild)
  ‖ raw32(public_key)              # raw 32 bytes, NO LP (mirrors nonce_raw)
  ‖ LP(canonical_server_origin)    # the wss:// origin from the token, frozen-canonical
  ‖ LP("1.0.0")                    # protocol_version
```

- `public_key` in the POST body: **unpadded base64url of the raw 32 bytes**
  (matches the daemon's existing pairing encoding).
- `pop_signature`: unpadded base64url, **exactly 86 chars**, strict Ed25519
  verify (non-canonical S, low-order/identity keys rejected) — same gate as the
  handshake.
- Vectors ship in a **new file** (`pairing-test-vectors.json`) — the frozen
  `test-vectors.json` is not touched. Required negatives: wrong secret, wrong
  origin, tampered public_key, wrong domain tag, non-canonical S, low-order
  key, wrong-length signature.

**M2 — fingerprint format, pinned.** `base64url(SHA-256(raw32 public_key))` —
**full 43 chars, no truncation**, displayed in 4-char groups on both sides
(browser and CLI identically). A truncated fingerprint invites prefix-collision
games for no UX gain; 43 chars compared visually in groups is fine for a
once-per-device ceremony.

**M3 — token hygiene** *(daemon-side, ours).* `hugin-agent connect` reads the
token from a **hidden stdin prompt** by default (argv form allowed but warned —
shell history + `ps` leak a bearer secret). Token bounded ≤1024 bytes; `v`
field means protocol version `"1.0.0"` (the `hpk1.` prefix is the envelope
version); secrets never logged.

**M4 — per-secret attempt cap.** Invalid-PoP-doesn't-consume is right, but add
a per-pending-pairing attempt counter (strawman: 10 failures ⇒ burn the code)
— per-IP limits alone don't stop distributed hammering.

## 3. Answers to §10

| # | Decision | Answer |
|---|---|---|
| 1 | CLI shape | **Single token accepted** (+ stdin prompt, M3). We will migrate `connect --server` / device-code / mock pairing-server / e2e AA–AE to this ceremony — one ceremony everywhere, no legacy path. |
| 2 | Activation | **REQUIRE. Non-negotiable** (B4/B5) — PoP-only is rejected by both reviewers. With polling mechanics + pending TTL + CLI fingerprint display as specified in B4. |
| 3 | PoP bytes | Tag + order agreed; ambiguities resolved per **M1**. Vectors (new file) are a precondition to implementation on both sides. |
| 4 | Token envelope | `hpk1.` + JSON accepted **as a UX wrapper only** — the integrity claim is withdrawn (B5). Bound length + `v` semantics per M3. CBOR not needed. |
| 5 | Origin vectors | **Proposed algorithm rejected** (B1/B2). Frozen `canonicalizeServerOrigin` is the single shared algorithm (Python port already exists and passes F4); wss-only/DNS-only is C2 minting policy; no new origin vectors. |

## 4. Daemon-side work we accept (so it's costed, not implied)

Rewrite `src/auth/connect.ts` + `src/connect.ts` (token decode → PoP → poll),
extend `mock-relay/pairing-server.ts` to the new ceremony, update e2e AA–AE,
revise `docs/auth-pairing-spec.md` §3, add the PoP transcript module + shared
`pairing-test-vectors.json`. None of this touches the frozen wire — pairing is
off-wire, so **no v2 bump** is needed anywhere in this agreement.

## 5. What we explicitly endorse

Browser-initiated direction (no pre-provisioned URL, identity bound from the
authenticated session), PoP with a domain-separated tag, pending-key +
fingerprint activation, `sha256(secret)`-only storage, first-valid-completion
wins, invalid-PoP non-consumption, transactional device caps, audit events.
With §1–§2 applied, we're ready to lock this as
`docs/auth-pairing-spec.md` §3 rev2 and start the daemon-side implementation.
