# Daemon-side rev2 pairing — implementation plan

**Goal:** replace the built daemon-initiated **device-code** pairing with the
**LOCKED rev2 ceremony** (browser-initiated `hpk1` paste token + Ed25519 PoP +
mandatory fingerprint activation + `poll_token` status), on both the daemon
client and the mock relay, with e2e coverage. **Off-wire only** — the frozen
v1.0.0 handshake (`§4`/`§5`) and all its code are untouched.

Authorities (do not re-litigate): [`docs/auth-pairing-spec.md`](auth-pairing-spec.md)
§3 (ceremony) + §5c (PoP/fingerprint bytes); contract code
[`protocol/v1/pairing.ts`](../protocol/v1/pairing.ts) + vectors
[`protocol/v1/pairing-test-vectors.json`](../protocol/v1/pairing-test-vectors.json).

## 0. Contract already fixed (no work — consume it)

- `buildPairingTranscript`, `keyFingerprint`, `validateB64u32`,
  `REJECTED_TEST_PUBLIC_HEX`, `PAIRING_SECRET_RE` — in `protocol/v1/pairing.ts`.
- Ed25519 seed→key + `signTranscript`/`verifyTranscript` — `protocol/v1/ed25519.ts`.
- `canonicalizeServerOrigin` — `protocol/v1/origin.ts` (reject-not-normalize).
- Wire request/response shapes, endpoint derivation, state machine — spec §3.

## 1. What changes (files)

| File | Change |
|------|--------|
| `src/auth/connect.ts` | **Rewrite** the flow: token decode → origin validate → scheme-swap → `POST /pair/complete` (PoP) → poll `POST /pair/status` → persist. |
| `src/auth/pairing-token.ts` *(new)* | `hpk1` token decode + validation (small, unit-testable, pure). |
| `src/connect.ts` | CLI: read token via **hidden stdin** (default), print the fingerprint + "confirm in browser" guidance; keep `--config`; retire `--server` (or keep as a hidden dev alias — see §5 Q1). |
| `mock-relay/pairing-server.ts` | **Rewrite** to the rev2 endpoints + CAS state machine + a `mint()` test helper + a `confirm()`/`reject()` activation hook. |
| `scripts/e2e.ts` | **Replace** the AE pairing scenario with the rev2 ceremony scenarios (AE1…AE9 — see §4); keep AA–AD (handshake verify) untouched. |
| `src/auth/config-file.ts` | Likely unchanged (persisted fields identical). Confirm no schema change. |
| `README.md` | Update the `npm run connect -- --server <url>` lines → the rev2 token/paste flow (Q1 removes `--server`). |
| `docs/hugind-CHANGELOG.md` | Add the daemon-side rev2 entry (the QUEUED note in Track C becomes DONE). |

## 2. Work units + dependency graph (for Athena parallelization)

The wire contract between client and server is **fully pinned by spec §3**, so
the two sides can be built **in parallel** and only meet at the e2e join.

```
        ┌─────────────────────────────┐
        │ U0  contract (DONE, §0)      │
        └───────────────┬─────────────┘
              ┌──────────┴──────────┐
              ▼                     ▼
   ┌────────────────────┐  ┌────────────────────────┐
   │ U1  daemon client  │  │ U2  mock pairing server │   ← PARALLEL (independent files)
   │  connect.ts        │  │  pairing-server.ts      │
   │  pairing-token.ts  │  │  (CAS, PoP verify,      │
   │  connect CLI       │  │   mint/confirm helpers) │
   └─────────┬──────────┘  └───────────┬────────────┘
             └──────────┬──────────────┘
                        ▼
             ┌────────────────────────┐
             │ U3  e2e scenarios      │   ← JOIN (needs U1+U2 surfaces)
             │  scripts/e2e.ts        │
             └────────────────────────┘
```

- **U1 ∥ U2** run concurrently (disjoint files; both code to spec §3).
- **U3** starts once U1+U2 land (it drives the real client against the real mock).
- Athena assignment: one worker owns U1, one owns U2, both handed the same spec
  §3 + `pairing.ts` surface; a third does U3 after the barrier. A shared
  "interface contract" note (below) prevents drift at the join.

### Interface contract (the U1/U2 handshake, from spec §3 — both workers pin this)

- **Endpoints** (derived by scheme-swap): `POST {https-base}/api/v1/hugin-agents/pair/complete`, `POST {https-base}/api/v1/hugin-agents/pair/status`. Mock listens on `http://127.0.0.1:<port>`; the token's `origin` is a `ws://127.0.0.1:<port>` loopback-dev origin (frozen algo admits it), so scheme-swap → `http://…` hits the mock.
- **`/pair/complete` req**: `{ secret:string, public_key:string(43 b64u), pop_signature:string(86 b64u) }`.
- **`/pair/complete` res**: `202 { status:"pending", fingerprint:string(43), poll_token:string }` | `400 { error:"pairing_failed" }` | `413`/`429` transport.
- **`/pair/status` req**: `{ poll_token:string }`.
- **`/pair/status` res**: `200 {status:"pending"}` | `200 {status:"active", agent_id, key_id, tenant_id}` | `200 {status:"rejected"}` | `404 {error:"invalid_or_expired"}`. **Note: `active` returns only ids — NOT the relay URL.** The persisted `serverUrl` is the **canonical token origin** (the client already has it; §3.4 of spec derives it once and reuses it at handshake).
- **Token**: `hpk1.<base64url(json)>`, `json={v:"1.0.0", origin, secret, exp}`.
- **PoP bytes**: `buildPairingTranscript({secret, publicRaw, server_origin, protocol_version:"1.0.0"})` signed with the device seed; verified with `verifyTranscript(publicRaw, transcript, pop_signature)`.
- **Fingerprint**: `keyFingerprint(publicRaw)` — full 43-char. The **client computes it locally** from its own key, **asserts** the `202` response's `fingerprint` equals it (else fail closed), and **displays the local value** — the server value is a sanity cross-check, never the source of truth.

### Pinned client API (U3 depends on this — U1 MUST match it exactly)

```ts
interface ConnectOptions {
  token: string;                 // the pasted hpk1 token (REPLACES serverUrl)
  agentVersion?: string;
  seedStore?: SeedStore;         // default keychain; e2e injects memorySeedStore()
  configPath?: string;
  fetchImpl?: typeof fetch;
  sleepImpl?: (ms: number) => Promise<void>;
  nowImpl?: () => number;
  onFingerprint?: (fp: string) => void;   // CLI prints the LOCAL fingerprint + guidance
  pollIntervalMs?: number;       // default 2000
  pollDeadlineMs?: number;       // default 600_000 (~pending TTL); bounded loop, never infinite
}
// PairingResult unchanged: { agentId, keyId, tenantId, userId?, serverUrl, configPath }
// serverUrl := the canonical token origin (persisted for the daemon to dial).
```

`serverUrl`/`onUserCode` are **removed** from the options. e2e calls
`connect({ token, seedStore: memorySeedStore(), sleepImpl: () => Promise.resolve(),
nowImpl: <advancing stub> })`.

## 3. Unit specs

### U1 — daemon client (`src/auth/connect.ts` + `pairing-token.ts` + `src/connect.ts`)

1. **`pairing-token.ts`**: `parsePairingToken(raw, now): {origin, secret, exp}` —
   **bound the raw input first** (≤1024 bytes) BEFORE any decode; require exactly
   one `hpk1.` prefix + a single payload segment; the payload must be valid
   unpadded base64url (reject padding / non-alphabet wrapper text); base64url-decode
   → JSON; zod-validate `{v:"1.0.0", origin:string, secret:PAIRING_SECRET_RE, exp:int}`;
   reject expired (`exp*1000 < now`, injected clock). Pure, no I/O.
2. **`connect.ts`** new flow (keep `newDeviceKey`, `SeedStore`, `writePairingConfig`,
   seed-scrub `finally`):
   - `parsePairingToken(token)` → `origin`.
   - `canonicalizeServerOrigin(origin)`; **fail closed** on `null` ("re-copy the token").
   - Derive HTTPS pairing base by scheme-swap (`wss→https`, `ws→http`, keep host+port).
   - Build PoP: `buildPairingTranscript({secret, publicRaw: dk.publicRaw, server_origin: canonicalOrigin, protocol_version: PROTOCOL_VERSION})`; sign with `signTranscript(privateKey, transcript)` (derive from `dk.seed`).
   - `POST /pair/complete {secret, public_key: b64u(dk.publicRaw), pop_signature}`. On non-202 → throw a redacted error (never log secret/token/sig).
   - Parse `202 {fingerprint, poll_token}`. **Compute `fp = keyFingerprint(dk.publicRaw)` locally; assert `response.fingerprint === fp`** (else fail closed — the server disagrees on the key). Emit the **local** `fp` via `onFingerprint(fp)` (CLI prints it + "confirm in your browser").
   - **Poll loop** (`pollIntervalMs` default 2000, `pollDeadlineMs` default 600_000 — a **bounded** loop via `nowImpl`, never infinite): `POST /pair/status {poll_token}` until `active` / `rejected` / deadline. On `404` → attempt one **idempotent re-complete** (same key, re-sign) → resume polling with the fresh `poll_token`; on a second `404`, or `rejected`, or deadline → throw "re-pair this device" guidance.
   - On `active`: validate ids (`AuthId`), `seedStore.set(key_id, dk.seed)`, `writePairingConfig`, return `PairingResult`.
   - Keep all existing test seams (`fetchImpl`, `sleepImpl`, `nowImpl`, `seedStore`, `configPath`).
3. **`src/connect.ts` CLI**: read the token from **hidden stdin** (TTY echo off) by
   default; accept `--config`; print the **locally-computed** fingerprint (via
   `onFingerprint`) prominently with "Confirm this fingerprint in your browser to
   finish." Bounded token read (≤1024). **Remove `--server`** entirely (Q1) and
   rewrite `USAGE`. Also update `README.md` (the `npm run connect -- --server <url>`
   lines → the token/paste flow) so user docs match (Codex NIT).

**Invariants U1 must hold:** seed/private key never sent (only `public_key` +
`pop_signature`); non-canonical origin ⇒ fail closed; token/secret never logged;
in-memory seed scrubbed on every exit path.

### U2 — mock pairing server (`mock-relay/pairing-server.ts`)

Rewrite to a small but faithful rev2 mock (single tenant, in-memory), exposing a
**test-driver API** the e2e calls:

- **`mint(opts): string`** — issue an `hpk1` token: pick a canonical `ws://127.0.0.1:<port>` origin, generate a 43-char secret, store `sha256(secret)` + `expected_origin` + expiries + `(tenant_id, created_by_user_id)` + `state:"issued"`; return the token string. (Stands in for the browser `/pair` mint.)
- **`POST /pair/complete`**: cheap→expensive per spec §3.3 — body-size gate; `validateB64u32(secret)` + `validateB64u32(public_key)`; `pop_signature` 86-char; refuse `REJECTED_TEST_PUBLIC_HEX` + low-order (via `verifyTranscript` strictness); rebuild transcript with the **stored** origin; `verifyTranscript`. CAS `issued→pending` storing `winning_public_key` + `keyFingerprint` + first `poll_token` hash. Return `202 {status,fingerprint,poll_token}`. All semantic failures → `400 {error:"pairing_failed"}`. Attempt-cap burn as one guarded update. Invalid PoP never consumes.
- **`confirm()` / `reject()`** — test hooks standing in for the browser activation: `confirm()` runs the activation transition (mint `agent_id`/`key_id` from the **stored winner**, enforce device cap, `pending→active`); `reject()` → `pending→rejected` + burn.
- **Deterministic activation for AE6 (no timer).** Support `confirmAfterStatusPolls: N` — the server returns `pending` for the first N `/pair/status` responses and flips to `active` **after the Nth response is committed** (a counter, not a wall-clock timer), so the client provably observes `pending` before `active` with zero race.
- **`POST /pair/status`**: `poll_token` hash lookup → `pending`/`active{ids}`/`rejected` / `404`. Active ids only for the winning key's tokens.
- **Idempotent re-complete**: same-winner re-`complete` (while `pending` or after `active`) mints a fresh `poll_token` into the bounded child set; different key → `400`. Post-active mints a fresh short-TTL token.
- Keep `requestBodies` + `registeredPublicKeys` audit arrays so the seed-off-wire test still works.

**Invariants U2 must hold:** single generic external failure class (no state
oracle); winner-binding in complete-CAS + activation; `sha256(secret)` over the
UTF-8 string; wire unchanged.

### U3 — e2e scenarios (`scripts/e2e.ts`, replace AE)

Drive the real `connect()` against the real `MockPairingServer`. Scenarios:

- **AE1 happy path**: `mint()` → `connect()` (auto-`confirm()` after the client reaches pending — via a scripted hook or a short timer) → assert persisted `agent_id`/`key_id`/`tenant_id`/canonical `serverUrl` + config file.
- **AE2 seed off-wire**: assert the seed never appears in `requestBodies`; the public key + a PoP signature do; exactly one key registered.
- **AE3 fingerprint match**: the fingerprint the client surfaced == `keyFingerprint(pub)` == the server-stored fingerprint.
- **AE4 origin fail-closed**: a token whose `origin` is non-canonical (e.g. `wss://Relay.example.com:443`) → `connect()` rejects before any POST (no request recorded).
- **AE5 test-key / bad PoP refused**: a `/pair/complete` with `REJECTED_TEST_PUBLIC_HEX` or a tampered PoP → `400 pairing_failed` (drive the server directly or via a crafted client).
- **AE6 status pending→active**: with `confirmAfterStatusPolls: N`, the client provably sees `pending` for N polls, then `active` (deterministic, no timer).
- **AE7 idempotent re-complete (MANDATORY)**: server invalidates/evicts the first `poll_token` (→ `404`); the client's 404-recovery re-completes with the **same key** and recovers ids from the fresh token. Cover both while-`pending` and **post-`active`** (short-TTL) recovery.
- **AE8 winner-binding (server-direct, MANDATORY)**: a **different** public key re-completing the same secret → `400 pairing_failed`, no state change; the stored winner's ids are unaffected.
- **AE9 attempt-cap burn (server-direct, MANDATORY)**: N invalid-PoP completions (matching secret, `state='issued'`) → `burned`; subsequent valid completion → `400`.

Keep the fake-engine/CI-safe posture; no real network, no keychain (use
`memorySeedStore()`). **Scope note:** these AE scenarios cover pairing only — the
token origin points at the HTTP pairing mock, so the persisted `serverUrl` is not
wired to a live `MockRelay` WSS unless the two mocks share one ingress; do **not**
claim post-pair dial coverage from AE (the existing handshake scenarios cover dial).

## 4. Verification gates (every unit + final)

`npm run typecheck` · `npm run protocol:check` (23) · `npm run pairing:check`
(53) · `python3 protocol/v1/py/selftest.py` (84) · `npm run e2e` (all). The
handshake vectors + Python verifier MUST stay green (proves no wire drift).

## 5. Open choices — RESOLVED (Codex plan-review concurred)

- **Q1 — `--server` retirement → REMOVE entirely.** No hidden dev alias. One
  ceremony; e2e injects the token via `connect({token})`.
- **Q2 — activation simulation → scripted `confirmAfterStatusPolls: N`** in the
  mock (counter-driven, returns `pending` for N status responses then flips to
  `active` after the Nth is committed). No timer, no race.
- **Q3 — poll seams → `sleepImpl`/`nowImpl` PLUS explicit `pollIntervalMs`/
  `pollDeadlineMs`** options with defaults (2000 / 600_000); the loop is bounded
  by `nowImpl` reaching the deadline, so tests can never spin forever.

## 6. Workflow (how this plan gets executed)

1. **Plan cross-review** — Codex adversarially reviews THIS plan; fold findings.
2. **Parallel impl (Athena)** — U1 ∥ U2 by two Codex workers against the interface
   contract (§2), then U3 after the barrier. Athena loops each unit to
   compiling + its slice of tests.
3. **Claude review** — review the full diff against spec §3/§5c + the invariants
   in §3; run all gates (§4). Loop: Codex fixes → Claude re-reviews → until clean.
4. **Commit** — one descriptive commit; update `hugind-CHANGELOG.md` (add the
   daemon-side rev2 entry — the QUEUED note becomes DONE) + this repo's memory.
