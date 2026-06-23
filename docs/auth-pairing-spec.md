# Hugin Agent — Auth & Pairing Security Spec (v1.0, companion to frozen wire v1.0.0)

Companion to the [wire protocol](../protocol/README.md). This is the **security
surface** the cloud team reviews independently. It gates the **production auth
path** (not mock-relay development).

> Status: **frozen companion to wire v1.0.0** (cloud diff-review: FREEZE-OK). The
> remaining ⚙️ items are post-freeze operational parameters (rotation grace,
> pairing-code TTL/device limits, audit schema), not wire/transcript shape.

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

## 3. Pairing (first run)

```
hugin-agent connect --server <url>
```

1. Daemon generates an Ed25519 keypair; private key → OS keychain.
2. Daemon starts a device-code flow; user approves in a browser (server shows a
   user code, binds it to their tenant/user).
3. On approval the server **mints a per-device `agent_id`**, registers the device
   **public key**, and returns `agent_id` + `key_id` + `tenant_id` + `user_id`
   (the pairing record maps `agent_id → (tenant_id, user_id, key_id[])`).
4. Daemon persists `agent_id`/`key_id`/`tenant_id`/server URL in local config
   (non-secret); the private key stays in the keychain.

⚙️ pairing-code TTL, max devices per user, re-pair policy.

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

### Post-freeze operational confirms (NOT freeze blockers — strawman values)

Operational parameters, not wire/transcript shape — they do **not** block the
`v1.0.0` freeze and are confirmed post-freeze (see PROPOSAL):

3. ⚙️ **Rotation grace window** + max concurrent `key_id`s per host. Strawman:
   24h overlap; ≤2 live `key_id`s per host.
4. ⚙️ **Pairing-code TTL, device limits, re-pair UX.** Strawman: code TTL = 10
   min; ≤10 devices per user; re-pairing always allowed (mints a fresh `agent_id`).
6. ⚙️ **Audit event schema** for pair/rotate/revoke. Strawman: `{ event,
   tenant_id, user_id, agent_id, key_id, actor, source_ip, ts }`.
