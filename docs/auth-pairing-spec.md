# Hugin Agent — Auth & Pairing Security Spec (v1.0, companion to frozen wire v1.0.0)

Companion to the [wire protocol](../protocol/README.md). This is the **security
surface** the cloud team reviews independently. It gates the **production auth
path** (not mock-relay development).

> Status: **frozen companion to wire v1.0.0** (cloud diff-review: FREEZE-OK). The
> pairing ceremony is **rev2 (LOCKED, §3/§5c)** — browser-initiated + PoP + a
> mandatory fingerprint activation, agreed with the Python C2 team; it is
> **off-wire** (no v1.0.0 change). The remaining ⚙️ items are post-freeze
> operational parameters (rotation grace, pairing TTLs/device limits, audit
> schema), not wire/transcript shape.

## 1. Scope & threat model

**In scope:** device pairing, the device keypair, the `auth.challenge → hello`
handshake, canonical signing bytes, nonce/replay handling, connection fencing,
key rotation/revocation, lost-device flow.

**Out of scope (MVP):** enterprise SSO/E2EE, self-hosted relay, multi-machine
coordination. Provider tokens (Anthropic/OpenAI) are **out of band** — see §9.

**Adversaries & required properties:**

| Threat | Defense |
|--------|---------|
| Passive eavesdropper | TLS (mandatory) on the WSS link. |
| Replay of a captured `hello` | Single-use nonce + TTL; nonce bound into the signed transcript. |
| MITM / relay impersonation | `server_origin` + `tenant_id` bound into the transcript; TLS cert validation. |
| Agent impersonation | Possession proof of the device private key (Ed25519). |
| Stale/duplicate connection | `connection_epoch` fences older sessions. |
| Algorithm downgrade | `alg` fixed to `ed25519`; no negotiation. |
| Stolen device | Revocation by `key_id`; re-pair required. |

## 2. Identities & keys

**Identity hierarchy:** `tenant_id > user_id > agent_id (one device/daemon) >
engines[]`. One user may own many agents (one per machine); a single machine
running both claude and codex is **one** `agent_id` with multiple
`capabilities.engines`. `connection_epoch`/lease are scoped **per `agent_id`**, so
one device reconnecting never fences another device of the same user.

| Item | Where | Notes |
|------|-------|-------|
| `tenant_id` | server | Grammar `1*128(ALPHA / DIGIT / "-" / "_" / ".")` (≤128 ASCII). Bound into the transcript so a signature can't cross tenants. **Stable for the key's lifetime**; no silent cross-tenant rebind — moving a device to another tenant requires re-pairing (§3). |
| `user_id` | server | The human who paired the device. Lives in the **pairing record** + pairing response + audit events only; **NOT on the wire** and **NOT in the signed transcript** (the transcript binds `tenant_id`; `agent_id` already represents the (user, device) pair). |
| `agent_id` | server-minted at pairing | **Per-device** (one daemon/machine). Opaque, bound to a (tenant, user). Same charset as the wire `AuthId` (`^[A-Za-z0-9._-]{1,128}$`). |
| device keypair | generated locally (Ed25519) | Private key in the **OS keychain** (`@napi-rs/keyring`); never leaves the host, never sent to the cloud. |
| `key_id` | server-assigned per registered public key | Selects which device key signed a `hello`; enables rotation. |

A host may hold multiple `key_id`s during rotation (§7) — so `key_id` is 1:N. The
pairing record maps `agent_id → (tenant_id, user_id, key_id[])`.

> **Cloud enforcement (normative).** `user_id` is off-wire and the transcript
> binds only `tenant_id`, so the relay MUST enforce active `(tenant_id, agent_id)`
> uniqueness, MUST NOT reuse an `agent_id` across users within a tenant, and MUST
> resolve `user_id` **only** from the pairing record. Without this, the off-wire
> `user_id` model becomes a cloud authorization bug (cloud diff-review, Locked #2).

## 3. Pairing (first run) — rev2 (browser-initiated, PoP-bound)

**rev2 supersedes the earlier daemon-initiated device-code flow.** Pairing is
**browser-initiated**: the user mints a token in an authenticated C2 session and
pastes it into the daemon, which proves possession of a fresh device key and is
activated by a human fingerprint check. The token carries the C2 endpoint, so
the daemon needs no pre-provisioned URL (multi-tenant / on-prem friendly). Agreed
across a three-round Claude+Codex cross-review on both sides; see the review
trail in `docs/pairing-ceremony-*-reply.md`.

Pairing runs over **HTTPS, before any WSS handshake** (§4). It is **off-wire** —
none of it touches the frozen v1.0.0 message shapes; the contract code is
[`protocol/v1/pairing.ts`](../protocol/v1/pairing.ts) (+ the Python reference
`protocol/v1/py/`), and the byte layout is normative in **§5c**.

### 3.1 Ceremony flow

```
User (browser, authenticated)      Daemon (hugin-agent connect)          C2
  │ Connectors → "Connect"                                                │
  │ ───────────────────────────────────────────  POST /pair ────────────▶│ mint hpk1 token (§3.2); store
  │ ◀── copy-ready `hugin-agent connect` command (token) ─────────────────┤ sha256(secret), expected_origin,
  │                                                                       │ token+pending expiries, (tenant_id,
  │ paste ──▶ [ daemon reads token via hidden stdin ]                     │ created_by_user_id), state=issued
  │            decode → validate origin (frozen algo §5, fail closed)     │
  │            scheme-swap to HTTPS pairing base (§3.6)                    │
  │            POST …/pair/complete {secret, public_key, pop_signature} ──▶│ verify + CAS (§3.3/§3.4)
  │          ◀─ 202 {status:"pending", fingerprint, poll_token} ──────────┤
  │ daemon prints fingerprint; user compares in browser  ◀─ (human, oob)  │
  │ Confirm (same authed user) ─────────────────────────  activation txn ▶│ mint agent_id/key_id from the STORED
  │                                                                       │ winning key; enforce device cap
  │            POST …/pair/status {poll_token} (poll) ───────────────────▶│ → active
  │          ◀─ 200 {status:"active", agent_id, key_id, tenant_id} ───────┤
  │            persist non-secret config; dial WSS /connect (§4)          │
```

### 3.2 Pairing token (`hpk1` — UX wrapper only, **no integrity claim**)

`hpk1.<base64url(json)>`, `json = { v:"1.0.0", origin:"ws(s)://…", secret:"<43-char b64url>", exp:<unix> }`, bounded **≤1024 bytes**.

- The token is a paste convenience, **not an authenticated envelope**: anyone who
  can alter the pasted command can edit `origin`. Its origin binding defends
  **accidental drift only**; the mandatory fingerprint confirmation (§3.4) is the
  control against active substitution.
- `secret` is a 256-bit value as **43 canonical unpadded base64url chars**
  (§5c gate). C2 stores only `sha256(secret)` — computed over the exact UTF-8
  **string** (§5c), never the decoded bytes.
- `origin` is already-canonical (`canonicalizeServerOrigin(origin) === origin`,
  §5). Minting policy: production origins are **`wss://` + DNS host only**
  (no IP literals); `ws://` loopback is dev-only (the frozen algorithm admits it).
  C2 asserts its public origin is canonical at boot/mint.

### 3.3 `/pair/complete` — PoP + canonical gates + CAS (fail-closed)

Body `{ secret, public_key, pop_signature }`. Checks run **cheap → expensive** so
the endpoint never does crypto for a malformed request:

1. **Body-size limit before JSON parse**; normalize framework validation errors
   so a parse/schema failure is not a detailed public oracle (§3.6).
2. **Canonical gates** (`validateB64u32`, §5c): `secret` and `public_key` are each
   exactly 43 canonical unpadded base64url chars → 32 bytes (decode→re-encode must
   round-trip; pad-bit aliases rejected); `pop_signature` is 86 unpadded base64url
   chars, verified by the strict verifier (not a length-only check).
3. **Refuse the published test key** (`REJECTED_TEST_PUBLIC_HEX`); reject
   low-order / non-canonical public keys.
4. Rebuild the pairing transcript (§5c, `buildPairingTranscript`) and **strict
   Ed25519-verify** the PoP against the submitted `public_key`.
5. **CAS** `issued → pending` (§3.4), storing `winning_public_key`, its
   fingerprint (bytes defined in §5c), and the first `poll_token` hash.

Response `202 { status:"pending", fingerprint, poll_token }`; every semantic
failure is one generic external class `400 { error:"pairing_failed" }` (distinct
reasons → internal audit only). Transport errors may stay distinct
(`413 body_too_large`, `429 rate_limited`). An invalid PoP **never consumes** the
secret; it counts toward the attempt cap only while `state='issued'` (§3.4).

### 3.4 State machine (linearizable CAS) + activation

`issued → pending → active | rejected | expired | burned`. Every transition is a
single linearizable conditional update (same posture §6 requires for nonce/epoch):

- **First valid completion:** `… WHERE secret_hash=? AND state='issued' AND not
  expired AND attempts<cap RETURNING …` → set `pending`, `winning_public_key`,
  first token hash. First **valid** completion wins.
- **Attempt cap / burn (one statement):** a completion that matched `secret_hash`
  but did not win (invalid PoP, refused test key, low-order key) **while
  `state='issued'`** increments and conditionally burns atomically —
  `UPDATE … SET attempts=attempts+1, state=CASE WHEN attempts+1>=cap THEN 'burned'
  ELSE state END WHERE secret_hash=? AND state='issued'`. Gate failures before
  record lookup (size, non-canonical, unknown secret) never count.
- **Post-`pending` different key:** generic failure — no attempt increment, no
  state change (cannot burn or hijack a won pairing).
- **Activation (mandatory, browser-authenticated):** the pending key holds until
  the **same `(tenant_id, created_by_user_id)`** that issued `/pair` confirms the
  **server-stored** fingerprint in the browser (CSRF-protected; never trust a
  client-submitted fingerprint; never activate by secret alone). Confirm →
  activation txn registers credentials **from the stored `winning_public_key`
  only** (no request may substitute a key here), enforces **≤10 devices/user
  transactionally in this txn**, marks `active`. Reject or pending-TTL expiry
  **burns** the secret.
- **Two clocks:** token expiry (short) and pending-activation TTL (~10 min).

### 3.5 `/pair/status` — opaque `poll_token`

`POST { poll_token }` (never GET/query). `poll_token` is a **bearer read
capability** and is treated like the secret: hash-at-rest, `Cache-Control:
no-store`, redacted from logs/audit, TTL = pending TTL, rate-limited on valid
**and** invalid polls, uniform invalid-token response. Responses:

| Case | Response |
|------|----------|
| valid, not yet confirmed | `200 { status:"pending" }` |
| valid, confirmed | `200 { status:"active", agent_id, key_id, tenant_id }` |
| valid, rejected | `200 { status:"rejected" }` |
| unknown / expired / foreign token | `404 { error:"invalid_or_expired" }` |

Active credentials are returned only for the **stored winning key's** tokens.

**Idempotent re-complete (lost `202` recovery).** A same-winning-key retry of
`/pair/complete` (PoP re-verified) mints a **fresh** `poll_token` into a bounded
child set `pairing_poll_tokens(pairing_id, poll_token_hash UNIQUE, issued_at,
expires_at)` (cap ~5, oldest evicted, parent row locked while minting). It always
returns `202 {status:"pending", …}` (state is learned via `/pair/status`).
Allowed while `pending`, **and after `active`** — a post-`active` same-winner
re-complete mints a fresh **short-TTL** token (stored winner only; no
`issued`/`pending` resurrection), so a briefly-offline confirmed device recovers
its ids without a full re-pair. **Not** allowed after `rejected`/`expired`
(→ `400 pairing_failed`; the daemon re-pairs). A different key on the same secret
is a losing completion → generic failure, no token, no state change.

### 3.6 Unauthenticated ingress + endpoint derivation

`/pair/complete` and `/pair/status` are served **unauthenticated on the canonical
origin host** (same direct ingress as `/connect`); the browser confirm/reject
lives on the authenticated gateway. Endpoints are derived from the token's
canonical origin by a **deterministic scheme-swap** keeping host+port:
`wss://host[:p]` → `https://host[:p]/api/v1/hugin-agents/pair/{complete,status}`
(loopback dev `ws://` → `http://`). The daemon-facing pairing host **MUST equal
the canonical origin host** — never derived from the request `Host`, a gateway,
or a browser host. No credentialed CORS; no GET fallback; `Cache-Control:
no-store` on complete/status (incl. errors) **and** on the `/pair` mint response
(it carries the bearer secret); secrets/tokens/signatures/bodies redacted from
logs and audit.

⚙️ Strawman values: token TTL (short), pending-activation TTL ~10 min, attempt
cap ~10, ≤10 devices/user, poll-token child-set cap ~5. See §11.

> Only the **public** key is registered. The cloud never receives the private
> key or any provider token.

## 4. Connection handshake

```
A = hugind        S = relay
A → S: (WSS/TLS dial-out)
S → A: auth.challenge { challenge_id, nonce, challenge_ttl_ms }
A → S: hello { agent_id, auth:{ key_id, alg:"ed25519", signature }, ... }
S → A: hello.accepted { connection_epoch, ... }   // or hello.rejected
```

Server steps before `hello.accepted`:
1. `key_id` → device public key; reject `agent_unknown` if missing/revoked.
2. nonce is unspent **and** within `challenge_ttl_ms`; else `expired_challenge`.
3. recompute the canonical transcript (§5), verify Ed25519 signature; else
   `bad_signature`.
4. mark nonce spent; assign a fresh `connection_epoch`; fence older connections.

## 5. Canonical signing bytes (normative)

The signature is over a **byte string**, not display text. Fields are
length-prefixed to prevent ambiguity/concatenation attacks, with a
domain-separation tag.

```
LP(x)      := uint32_be(byte_length(x)) || x          # x is UTF-8 unless noted
transcript := LP("hugin-agent/auth/v1")               # domain separation
            || LP(challenge_id)
            || nonce_raw                               # the 32 RAW bytes (decode base64url), NOT the text
            || LP(agent_id)
            || LP(key_id)                              # which device key — defeats key substitution
            || LP(protocol_version)
            || LP("ed25519")
            || LP(tenant_id)
            || LP(server_origin)                       # e.g. "wss://relay.example.com"

signature  := base64url( Ed25519_sign(device_private_key, transcript) )
```

Rules:
- Integers are **big-endian uint32**. `byte_length` is over raw bytes.
- `nonce_raw` is the decoded 32 bytes (not the base64url text) — both sides
  decode before hashing.
- `server_origin` is the **canonical** WSS origin the agent dialed; binding it
  defeats a relay that forwards a challenge it didn't issue. Both sides use the
  same canonical form (see "server_origin canonicalization" below): the agent
  signs its canonical origin and the verifier reconstructs the canonical origin
  from the pairing-bound server URL, **rejecting** any mismatch.
- `server_origin` and `tenant_id` are **NOT carried in `hello`** (not on the
  wire): the verifier reconstructs `server_origin` from trusted connection
  metadata and `tenant_id` from the pairing record (`agent_id`+`key_id` → record).
  If either is not reconstructable, **reject** — never trust agent-supplied values.
- `protocol_version` in the transcript MUST equal the exact `hello.protocol_version`
  value; the verifier MUST NOT verify under a different (e.g. `negotiated_version`)
  value — a mismatch is `bad_signature`. `negotiated_version` is not signed.
- All base64url in this protocol is **unpadded** (alphabet `[A-Za-z0-9_-]`, no
  `=`); reject any value containing padding or non-alphabet characters.
- The server resolves `(tenant_id, agent_id, key_id)` → public key; the `key_id`
  in the transcript MUST equal the one in `hello.auth`.
- `server_time` / `challenge_ttl_ms` are **not signed** (advisory display/TTL
  hints). The authoritative nonce lifetime is enforced server-side via
  `challenge_id` lookup; the agent trusts only the signed nonce + its own
  monotonic clock.
- Any field mismatch ⇒ signature fails ⇒ `bad_signature`. No partial trust.

### Ed25519 verification (normative)
- Public key exactly 32 bytes; signature exactly 64 bytes (86 base64url chars,
  unpadded). Reject padding or non-alphabet characters.
- Verify per RFC 8032 with canonical-S enforcement (ZIP-215 style); reject
  non-canonical signatures, low-order / small-subgroup keys, and the identity.
- No batch verification (per-connection single verify).

### server_origin canonicalization (normative)

`server_origin` MUST be in canonical form on both sides; a verifier **rejects
non-canonical input** — it never silently normalizes. Canonical form:

- Scheme `wss://` only. `ws://` is permitted **only** for local-dev loopback
  hosts (`localhost`, `127.0.0.0/8`, `[::1]`); never in production.
- **DNS hostname only in production — reject bare IPv4/IPv6 literals** (the
  loopback hosts above are the sole exception, for local dev).
- Lowercase host **even after IDNA**: an IDN host MUST already be ASCII punycode
  (`xn--…`); a raw non-ASCII host is non-canonical → rejected.
- **Omit default ports** (`:443` for `wss`, `:80` for `ws`); an explicit default
  port is non-canonical. **Reject port `0`.**
- IPv6 uses bracket form `[…]` (loopback dev only). **Reject zone-ids** (`%…`)
  and any percent-encoded authority.
- **No** userinfo, path, query, or fragment; **no trailing dot** on the host.
- Canonical stored form has **no trailing slash**: `wss://relay.example.com`
  (not `wss://relay.example.com/`).

Reference vectors (a canonical positive + representative rejections — uppercase
host, explicit default port, trailing dot, raw IDN, invalid DNS label) ship in
[`protocol/v1/test-vectors.json`](../protocol/v1/test-vectors.json) (§5d of the
v1.6 work brief) so a Go/Rust verifier can confirm byte-identical behavior.

## 5b. Canonical result digest (normative)

`result_digest` (in `PendingResult` and `job.result.ack`) is:

```
result_digest := base64url( SHA-256( JCS(job.result minus id, ts) ) )
```

i.e. RFC 8785 (JSON Canonicalization Scheme) over the `job.result` message with
the per-send envelope fields `id` and `ts` removed (they differ each send and
must not affect identity). Both sides compute the same canonical bytes, so a
resent result yields an identical digest and `job.result.ack` confirms the
**payload**, not merely the id.

## 5c. Pairing PoP transcript (normative) — off-wire, rev2

The pairing proof-of-possession (§3.3) signs a **distinct** byte string from the
handshake transcript (§5). The domain tag differs, so a pairing PoP can never be
replayed as a `hello` signature or vice-versa. Contract code:
[`protocol/v1/pairing.ts`](../protocol/v1/pairing.ts) (`buildPairingTranscript`);
Python reference `protocol/v1/py/hugin_protocol_v1.py`. This is **off-wire**
(HTTPS pairing, not a v1.0.0 message) and does not affect `PROTOCOL_VERSION`.

```
LP(x)               := uint32_be(byte_length(x)) || x       # x is UTF-8 unless noted
pairing_transcript  := LP("hugin-pair-pop-v1")              # domain tag — DISTINCT from §5
                    || LP(secret)                           # the 43-char base64url secret STRING (UTF-8), NOT hash, NOT decoded
                    || public_raw                           # the 32 RAW public-key bytes, NO length prefix (mirrors nonce_raw in §5)
                    || LP(canonical_server_origin)          # the ws(s):// origin from the token (canonical, §5)
                    || LP("1.0.0")                           # protocol_version

pop_signature       := base64url( Ed25519_sign(device_private_key, pairing_transcript) )
```

Rules:
- **`secret`** is signed as the UTF-8 **string** (the exact 43-char canonical
  base64url text), never its hash and never the decoded 32 bytes. `sha256(secret)`
  used for storage/lookup is likewise over that string.
- **`public_raw`** is inserted as the raw 32 bytes with **no** length prefix
  (same treatment as `nonce_raw` in §5). The wire-body `public_key` is the
  unpadded base64url of these bytes.
- **`canonical_server_origin`** is the token's origin in canonical form (§5); the
  verifier uses the origin it stored at mint, never a daemon-supplied value.
- **Canonical base64url gate (`validateB64u32`).** `secret` and `public_key` are
  each exactly 43 unpadded base64url chars encoding 32 bytes, and decode→re-encode
  MUST round-trip (non-zero trailing pad bits ⇒ rejected) — so no two strings
  alias one value. `pop_signature` is 86 unpadded base64url chars (64 bytes),
  strict-verified per the §5 "Ed25519 verification" rules (canonical S, reject
  low-order/identity keys).
- **Published test key.** `/pair/complete` MUST refuse to register
  `REJECTED_TEST_PUBLIC_HEX` (the vectors' fixed public test seed is public;
  registering it would let anyone impersonate the device).

**Key fingerprint (normative).** The fingerprint the daemon prints and the
browser displays for the activation check (§3.4) is:

```
fingerprint := base64url( SHA-256( public_raw ) )    # over the RAW 32 key bytes
```

the **full 43-char unpadded base64url** value — **no truncation**. It hashes the
raw 32-byte key, **not** the base64url text of the key. Contract code:
`keyFingerprint` in [`protocol/v1/pairing.ts`](../protocol/v1/pairing.ts) (and the
Python `key_fingerprint`). The daemon and C2 MUST compute byte-identical strings —
a mismatch defeats the human check, which is the sole control against active token
substitution (§3.2). Grouping the display into blocks (e.g. 4-char groups) is
presentation-only; the canonical value is the ungrouped 43-char string, and each
positive vector in `pairing-test-vectors.json` carries its `fingerprint_base64url`.

Reference vectors (positives incl. a non-default port and an `ws://` loopback-dev
origin; negatives incl. wrong secret/origin/version, a handshake-tag cross-replay,
LP'd-pubkey and decoded-secret porting mistakes, non-canonical S, low-order key,
and the test-key policy case) ship in
[`protocol/v1/pairing-test-vectors.json`](../protocol/v1/pairing-test-vectors.json)
— verified by `npm run pairing:check` (TS) and the Python `selftest.py`, proving
byte-identical TS↔Python construction.

## 6. Nonce & replay

- 32 cryptographically-random bytes, base64url on the wire (**exactly 43 chars,
  unpadded, canonical**; reject `=` padding, non-alphabet characters, and
  non-canonical encodings — re-encoding the decoded 32 bytes must reproduce the
  string, so non-zero trailing pad bits are rejected).
- `challenge_ttl_ms` default **60_000** (advisory display/TTL hint; the
  authoritative nonce lifetime is enforced server-side via `challenge_id` lookup,
  not the signed transcript — see §5).
- **Globally single-use** across the relay deployment: the server records spent
  nonces until TTL expiry and rejects reuse.
- **Linearizability (normative).** The POP MUST linearize three operations:
  1. **nonce consume** — an atomic check-unspent→mark-spent (compare-and-set); a
     nonce is accepted at most once.
  2. **`connection_epoch` issuance** — strictly monotonic **per `agent_id`**, so a
     newer `hello` always fences older sessions of that device.
  3. **lease ownership** — at most one owner outside the rotation-overlap window,
     enforced by CAS / fencing tokens.
  Acceptable stores: a strongly-consistent SQL DB, etcd, Consul, ZooKeeper,
  FoundationDB, or DynamoDB **conditional writes**. **NOT acceptable:** an
  eventually-consistent cache, per-region Redis, or pod-local memory — each permits
  cross-region replay or double-ownership within the TTL.
- Re-pairing mints a new `agent_id` and **may reset that agent's epoch namespace**
  (epochs are per-`agent_id`). **Cross-POP** consistency is an enterprise concern,
  **out of MVP scope** ⚙️ — MVP assumes a single logical POP.

## 7. Key rotation

1. Daemon generates a new keypair, registers the new public key over the
   **already-authenticated** connection, receives a new `key_id`.
2. Both `key_id`s are valid during a grace window ⚙️.
3. Daemon switches signing to the new key; the server retires the old `key_id`
   after the window.

## 8. Revocation & lost device

- User revokes a device (CLI/dashboard) → server marks `key_id` (and optionally
  `agent_id`) revoked; subsequent `hello` with it → `hello.rejected{unauthorized}`.
- A live connection whose key is revoked is fenced immediately.
- The daemon, on `unauthorized`, stops and requires re-pairing (§3).
- ⚙️ audit trail (who paired/revoked, when, from where).

## 9. Provider tokens (out of band)

Anthropic/OpenAI tokens authenticate the **local CLI** to its provider. They are
**never** part of this protocol, never sent to the cloud, never stored by the
relay. The daemon does not read or forward them; it only spawns the CLI, which
manages its own auth.

But "out of band" is necessary, not sufficient — the spawned CLI runs with local
authority, and a server-controlled prompt could try to exfiltrate creds. So the
isolation model is **normative**, not advisory: scrub the child environment to
an allowlist, deny `~/.ssh` and cloud-credential paths, run under the isolated
permission config (per the [approval spike](../spikes/approval-prompt-tool/README.md)),
and enforce the assignment's network policy. This keeps the cloud blast-radius
free of provider creds even under a hostile prompt.

## 10. Security properties (summary)

- **Confidentiality/integrity in transit:** TLS.
- **Authentication:** Ed25519 possession proof; server verifies against the
  pairing-registered public key.
- **Replay-resistance:** single-use, TTL-bounded nonce bound into the transcript.
- **Origin/tenant binding:** `server_origin` + `tenant_id` in the transcript.
- **No downgrade:** fixed `alg`, fixed transcript layout, versioned protocol.
- **Compromise recovery:** per-`key_id` rotation and revocation.

## 11. Status of open questions

### Resolved in v1.6 (now normative above)

1. ✅ **`tenant_id` / `server_origin` formats.** `tenant_id` = `1*128(ALPHA /
   DIGIT / "-" / "_" / ".")` (≤128 ASCII), stable for the key lifetime, issued in
   the pairing response (§2/§3); `server_origin` = canonical lowercase `wss://`
   origin per §5 "server_origin canonicalization" (DNS-only, default ports
   omitted, no path/query, reconstructed by the verifier — not on the wire).
2. ✅ **Nonce / epoch / lease consistency model.** Linearizability made normative
   (§6): atomic nonce-consume, per-`agent_id` monotonic `connection_epoch`, and
   CAS/fenced lease ownership. Cross-POP remains out of MVP scope.
5. ✅ **`agent_id` granularity → per-device** (§2): one daemon/machine per
   `agent_id`, under a `user_id` 1:N layer; engines are listed in capabilities.
7. ✅ **Pairing ceremony → rev2 (browser-initiated, PoP-bound).** LOCKED after a
   three-round Claude+Codex cross-review on both sides (§3/§5c). Replaces the
   daemon-initiated device-code sketch: `hpk1` paste token, Ed25519 PoP at
   `/pair/complete`, mandatory browser fingerprint activation, opaque `poll_token`
   at `/pair/status`, linearizable CAS state machine. Off-wire (v1.0.0 unchanged);
   PoP vectors shipped (`pairing-test-vectors.json`).

### Post-freeze operational confirms (NOT freeze blockers — strawman values)

Operational parameters, not wire/transcript shape — they do **not** block the
`v1.0.0` freeze and are confirmed post-freeze (see PROPOSAL):

3. ⚙️ **Rotation grace window** + max concurrent `key_id`s per host. Strawman:
   24h overlap; ≤2 live `key_id`s per host.
4. ⚙️ **Pairing operational params (rev2, §3.6).** Strawman: `hpk1` token TTL
   short; pending-activation TTL ~10 min; attempt cap ~10 (then `burned`); ≤10
   devices/user; poll-token child-set cap ~5. Re-pairing always allowed (mints a
   fresh `agent_id`).
6. ⚙️ **Audit event schema** for pair/rotate/revoke. Strawman: `{ event,
   tenant_id, user_id, agent_id, key_id, actor, source_ip, ts }` (pairing adds
   init user, complete IP/UA, activation user, reject/expire/burn reason).
