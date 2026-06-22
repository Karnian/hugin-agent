# Hugin Agent — Auth & Pairing Security Spec (DRAFT v0.1)

Companion to the [wire protocol](../protocol/README.md). This is the **security
surface** the cloud team reviews independently. It gates the **production auth
path** (not mock-relay development).

> Status: strawman for review. Values marked ⚙️ need cloud-team agreement.

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

| Item | Where | Notes |
|------|-------|-------|
| `agent_id` | server-minted at pairing | Opaque, bound to a tenant + user. |
| device keypair | generated locally (Ed25519) | Private key in the **OS keychain** (`@napi-rs/keyring`); never leaves the host, never sent to the cloud. |
| `key_id` | server-assigned per registered public key | Selects which device key signed a `hello`; enables rotation. |
| `tenant_id` | server | Bound into the transcript so a signature can't cross tenants. |

A host may hold multiple `key_id`s during rotation (§7).

## 3. Pairing (first run)

```
hugin-agent connect --server <url>
```

1. Daemon generates an Ed25519 keypair; private key → OS keychain.
2. Daemon starts a device-code flow; user approves in a browser (server shows a
   user code, binds it to their tenant/user).
3. On approval the server **mints `agent_id`**, registers the device **public
   key**, and returns `agent_id` + `key_id` (+ `tenant_id`).
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
- `server_origin` is the exact WSS origin the agent dialed; binding it defeats a
  relay that forwards a challenge it didn't issue.
- Any field mismatch ⇒ signature fails ⇒ `bad_signature`. No partial trust.

## 6. Nonce & replay

- 32 cryptographically-random bytes, base64url on the wire (43 chars unpadded).
- `challenge_ttl_ms` default **60_000** ⚙️.
- **Globally single-use** across the relay deployment: the server records spent
  nonces until TTL expiry and rejects reuse.
- ⚙️ Cross-POP nonce consistency for a multi-region relay (cloud-side; an
  eventually-consistent store would permit cross-region replay within the TTL).

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
manages its own auth. This keeps the cloud blast-radius free of provider creds.

## 10. Security properties (summary)

- **Confidentiality/integrity in transit:** TLS.
- **Authentication:** Ed25519 possession proof; server verifies against the
  pairing-registered public key.
- **Replay-resistance:** single-use, TTL-bounded nonce bound into the transcript.
- **Origin/tenant binding:** `server_origin` + `tenant_id` in the transcript.
- **No downgrade:** fixed `alg`, fixed transcript layout, versioned protocol.
- **Compromise recovery:** per-`key_id` rotation and revocation.

## 11. Open questions (cloud-team agreement)

1. ⚙️ Exact `tenant_id`/`server_origin` formats and where the agent learns them
   (pairing response vs config).
2. ⚙️ Nonce store consistency model + multi-region behavior.
3. ⚙️ Rotation grace window; max concurrent `key_id`s per host.
4. ⚙️ Pairing-code TTL, device limits, re-pair UX.
5. ⚙️ Whether `agent_id` is per-device or per-host-with-many-keys.
6. ⚙️ Audit event schema for pair/rotate/revoke.
