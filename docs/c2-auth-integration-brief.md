# C2 (Python relay) — hugind Auth Integration Brief

**Purpose:** everything a session working on the **Python C2 (cloud
orchestrator/relay)** needs to implement authentication + connection handling
for Hugin Agent daemons — self-contained, no prior context needed.

---

## 1. Context (one paragraph)

**Hugin Agent (`hugind`)** is an outbound-only bridge daemon installed on user
machines behind NAT/firewalls. It **dials out** to C2 over a single WSS
connection (TLS 443 — traverses NAT like ordinary HTTPS), authenticates with an
Ed25519 device key, receives job commands, runs a local coding CLI headlessly,
and streams results back. **C2 never dials in; no inbound port exists on the
daemon side.** The wire protocol is **FROZEN at `v1.0.0`** — any wire-visible
change (message shapes, transcript layout, enums) requires a major bump plus
cross sign-off. The daemon side (pairing CLI, keychain signer, handshake,
job lifecycle) is fully built and tested; this brief covers what **C2 must
implement** to accept those daemons.

Daemon repo (source of truth): `/Users/k/Desktop/sub_project/hugin-agent`

## 2. Contract distribution — vendor 3 files, no runtime coupling

There is **no git/npm dependency between the codebases**. The runtime coupling
is only "daemon dials C2's URL and authenticates." The contract ships as files
you copy **once** into the C2 repo (the protocol is frozen, so they don't
drift):

| Vendor this | What it is |
|---|---|
| `protocol/v1/py/hugin_protocol_v1.py` | **Python reference verifier** — transcript builder, `server_origin` canonicalization, nonce/id/version grammars, strict Ed25519 verify. Already written and conformant. |
| `protocol/v1/py/selftest.py` | Conformance grader — run it in C2's CI. |
| `protocol/v1/test-vectors.json` | Frozen cross-language vectors (F4). Selftest input. |

`selftest.py` currently passes **36/36** (transcript byte-match, deterministic
signature match, strict-verify positives; 18 negative rejections). Keep it
green in CI — it is the protocol-conformance gate. Do **not** modify the
vendored files; if something seems wrong, flag it against the daemon repo
instead.

Note on secrecy: everything above is safe to publish (Kerckhoffs). The vectors'
Ed25519 seed (`0102…1f20`) is a deliberately **public test constant** used only
for grading implementations. Real security lives in per-device private keys
(generated at pairing, kept in the device's OS keychain, never on the wire or
in any repo) — see §6 for the one guard this implies.

## 3. What C2 must implement — the auth surface

### 3a. Pairing endpoint (HTTP, once per device)

Device-code flow (reference implementation:
`mock-relay/pairing-server.ts` in the daemon repo):

1. Daemon calls the pairing endpoint → C2 issues a short-lived user code.
2. The **user logs into their account in a browser** and approves the code —
   this is where user identity binds to the device.
3. Daemon submits its Ed25519 **public** key → C2 mints `agent_id`, persists
   the **pairing record** `agent_id → (tenant_id, user_id, key_id[], public_key)`,
   and returns `agent_id` + `key_id` + `tenant_id` (+ `user_id`) to the daemon.

Rules (normative, from `docs/auth-pairing-spec.md`):

- Identity hierarchy: `tenant_id > user_id > agent_id (one device) > engines[]`.
  One user may pair many devices; each gets its own `agent_id` + key.
- `user_id` is **off-wire**. C2 resolves it **only** from the pairing record —
  never accept a user claim from a connection or message (doing so is an
  authorization bug).
- `agent_id` must match the `AuthId` grammar `^[A-Za-z0-9._-]{1,128}$`
  (it enters the signed transcript).
- **Refuse to register the public test key** — the module exports it as
  `REJECTED_TEST_PUBLIC_HEX` (`79b5…9664`). Its seed is public; registering it
  would let anyone with the repo impersonate that device.
- Strawman ops params (confirmable later): pairing-code TTL a few minutes,
  ≤10 devices per user, re-pairing always allowed (mints a fresh `agent_id`).

### 3b. WSS handshake verification (every connection)

Mirror the sequence of `verifyHello()` in `mock-relay/server.ts` (the daemon
repo's reference relay). On an accepted WSS connection:

1. **Send `auth.challenge`** — `challenge_id` (AuthId) + `nonce`: fresh,
   **single-use**, 43-char unpadded base64url (= 32 raw bytes). Generate per
   connection; never reuse.
2. **Receive `hello`** — carries `agent_id`, `key_id`, `protocol_version`,
   `tenant_id`, `signature`, capabilities.
3. **Field gates before crypto** (all provided by the vendored module):
   `validate_auth_id` on ids, `validate_protocol_version` **and** require
   `== "1.0.0"`, `validate_tenant_id`, `decode_nonce`, and match the challenge
   you issued. Look up the pairing record by `agent_id` + `key_id` — unknown →
   reject.
4. **Reconstruct `server_origin` yourself** via
   `canonicalize_server_origin(<the URL this endpoint is served at>)` — it is
   **not on the wire**; it binds the signature to *your* endpoint (MITM/re-host
   defense). Production form is `wss://` + lowercase DNS name, no default port,
   no path.
5. **Verify:** `build_transcript(...)` over
   (challenge_id, nonce_raw, agent_id, key_id, protocol_version, tenant_id,
   server_origin) → `verify_transcript(registered_public_key, transcript,
   signature)`.
6. Failure → send the protocol error (`bad_signature` / `unauthorized`) and
   close. Success → **atomically consume the nonce**, bump the agent's
   `connection_epoch`, send `hello.accepted {connection_epoch}`. The connection
   is now live: heartbeats + the whole job lifecycle flow over this one socket.

### 3c. Storage guarantees (linearizable — PostgreSQL is fine)

These were committed to at protocol freeze (freeze record `docs/PROPOSAL.md`):

- **Nonce**: single-use, atomic consume (no replay window under concurrency).
- **`connection_epoch`**: per-`agent_id` monotonic — a new accepted connection
  fences the old one. One device reconnecting must never fence another device
  of the same user (epochs are per-agent, not per-user).
- **Leases**: CAS/fenced ownership on every attempt-scoped message.
- **Stream log**: durable, keyed by `(attempt_id, seq)` / `(attempt_id,
  event_id)`, ack-after-commit; result durability before ack.

## 4. Runtime model — per-user individual daemons

- C2 holds a **connection registry** `agent_id → live socket`. "Run a job for
  user U" = look up U's agents from pairing records → pick a connected one →
  send `job.assign` down that socket.
- A daemon that is offline is unreachable (outbound-only ⇒ no push channel):
  **queue** jobs until it reconnects; the protocol's resume path
  (`seq`/`event_id` dedupe, at-least-once) assumes exactly this.
- v1 assumes a **single logical POP** (one C2 endpoint holding all sockets);
  cross-POP routing is explicitly out of scope.

## 5. Suggested Python stack

- `websockets` (or FastAPI/Starlette WebSocket) for the WSS endpoint.
- `cryptography >= 42` — the vendored verifier uses it; OpenSSL-backed strict
  Ed25519 (rejects non-canonical S, low-order/identity keys).
- PostgreSQL for pairing records, nonce consumption, epochs, leases, stream log.
- All byte-level work (transcript, origin, grammars, verify) is already inside
  the vendored module — C2 code should never hand-roll those.

## 6. Security invariants (do not weaken)

1. **Fail-closed**: unknown agent/key, stale nonce, any verify failure ⇒ reject
   and close. Never "accept and log".
2. **No user claims from the wire** — `user_id` comes from the pairing record
   only (§3a).
3. **Nonce single-use + transcript binding** make captured signatures
   worthless: the signature covers challenge_id, nonce, both ids,
   protocol_version, tenant_id, and *your* server_origin.
4. **Reject `REJECTED_TEST_PUBLIC_HEX` at pairing** (§3a).
5. Secrets inventory: C2 never holds device private keys; its own secrets are
   the TLS key and user-auth session infrastructure.

## 7. Acceptance criteria

1. Vendored `selftest.py` green in C2's CI (36/36).
2. **Positive e2e**: a real `hugind` pairs (`hugin-agent connect`), then
   handshakes and receives `hello.accepted`.
3. **Negatives**: tampered transcript field → `bad_signature`; replayed nonce →
   rejected; test public key registration → refused; second connection for the
   same agent fences the first (epoch).
4. The daemon repo's mock relay (`mock-relay/server.ts`) is the behavioral
   reference throughout — when in doubt, match it.

## 8. Beyond auth (separate work item)

The job-lifecycle layer needs the full message schema: port
`protocol/v1/messages.ts` (23 zod message shapes, strict objects, bounds) to
pydantic. Source of truth is that file plus `protocol/README.md`; the digest
rule (RFC 8785 JCS `result_digest`) is in `protocol/v1/digest.ts`. Auth (this
brief) is independently shippable first.
