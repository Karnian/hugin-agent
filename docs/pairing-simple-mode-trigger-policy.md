# Simple Pairing Mode — Trigger Policy (Decision)

**Status:** FINALIZED (Codex-reviewed, changes folded in) · **Issue:** #1
(`HUGIN_SIMPLE_PAIRING` dev support) · **Scope:** daemon (`hugin-agent`) only.
C2 changes are a separate repo.

---

## 1. Context

`connect` today ([src/auth/connect.ts](../src/auth/connect.ts)) is 100% **rev2**:
hpk1 token (hidden stdin) → Ed25519 **PoP** signature → `POST /pair/complete` (202
`{pending, fingerprint, poll_token}`) → poll `/pair/status` → browser confirm →
persist. Security rests on **PoP + `server_origin` binding + fingerprint confirm**.

Issue #1 adds a **dev-only "simple" mode** that runs *alongside* rev2:

- Input: `device_code` (a **bearer** credential, rev1-level) + daemon-supplied
  `--url` origin.
- `POST /pair/complete {device_code, public_key}` → **200 `{agent_id, key_id,
  tenant_id}`** immediately. **No PoP, no poll, no confirm.**
- C2 does not verify origin in simple mode (**provisional** WSS handshake); the
  daemon controls the dial origin via `--url`.

Motivation: when C2's advertised origin (`HUGIN_PUBLIC_WSS_ORIGIN`) differs from
the address that is actually reachable (Tailscale, k8s ingress), let the daemon
name the connect origin directly.

---

## 2. Decision

> **Mode is determined by LOCAL OPERATOR INPUT, NOT by the server's `capability`
> response.** Simple mode requires an explicit daemon-side dev gate
> (`HUGIN_SIMPLE_PAIRING`) **and** `--url`. The `capability` response is used only
> as a fail-fast cross-check — never as the trigger that decides whether PoP is
> sent.

### Trigger rules

1. **Simple mode ⇔ `HUGIN_SIMPLE_PAIRING` enabled AND `--url` present.**
   - **Dev gate first.** Simple mode activates only when the daemon env
     `HUGIN_SIMPLE_PAIRING` is truthy (`1`/`true`). If `--url` is present but the
     gate is **not** set → **hard reject before any stdin read or network probe**
     (`simple pairing is disabled; set HUGIN_SIMPLE_PAIRING=1 for dev, or omit
     --url for rev2`). A production build that never sets the gate cannot enter
     simple mode at all.
   - Read `device_code` from **hidden stdin** (never argv — it is a bearer secret;
     reuse the existing hidden-token reader).
   - Validate `--url` with the frozen `canonicalizeServerOrigin`
     ([protocol/v1/origin.ts](../protocol/v1/origin.ts)); non-canonical → **hard
     reject** (same guard rev2 applies to the token origin).
   - **Mixed-mode guard.** After the *same* line-ending strip the hidden-stdin
     reader already applies, also trim leading/trailing ASCII whitespace, then if
     the payload starts with `hpk1.` → **hard reject** (operator pasted a rev2
     token into a simple invocation; must not be forwarded as a `device_code`).
   - Probe `GET {--url→https}/api/v1/hugin-agents/capability`. Accept **only** the
     exact documented simple-mode marker (fail-closed; see §6) — anything else,
     including a truthy-but-unrecognized shape → **hard error**
     (`this relay does not support simple pairing`). This is the cross-check.
   - `POST {--url→https}/api/v1/hugin-agents/pair/complete {device_code,
     public_key}`. Response MUST be **exactly HTTP 200** with a **strict**
     `{agent_id, key_id, tenant_id}` body validated against the existing `AuthId`
     / tenant grammars. **No `seedStore.set` and no config write happen until that
     parse succeeds.** A rev2-shaped body (202 / `pending` / `poll_token`) → refuse
     with a clear error; never reinterpret it.
   - Only then: persist `serverUrl = canonicalize(--url)`, store the device seed
     under the returned `key_id`, and run the **existing** WSS `/connect`
     handshake. Scrub the in-memory seed on every exit path (as rev2 already does).

2. **rev2 mode ⇔ `--url` absent (unchanged, NO probe — normative).**
   - hpk1 token from hidden stdin; origin from the token; existing PoP + poll flow,
     **byte-for-byte unchanged**.
   - rev2 does **not** probe `/capability`. (Rejected the earlier "optional symmetry
     probe": it would break AE1–AE9 — the rev2 mock has no `/capability` — and hand
     an unauthenticated endpoint a rev2 DoS lever. rev2 stays no-probe.)

3. **The `capability` flag never auto-switches the flow.** It can only *reject* a
   mismatch. A rev2 invocation (no gate, no `device_code`, no `--url`) structurally
   cannot become simple.

---

## 3. Rationale

- **Downgrade resistance (primary).** `GET /capability` is unauthenticated and
  MITM-able. If the daemon decided "skip PoP" from that flag, a network attacker
  could advertise the simple marker and strip PoP + origin binding on a
  *production* pairing. Keying the mode off local input closes this: simple mode
  requires the `HUGIN_SIMPLE_PAIRING` gate + a `device_code` + `--url` the attacker
  cannot inject into the operator's invocation, and a token-based rev2 run has no
  `device_code` to fall back to.
- **Explicit dev gate (defense-in-depth).** Requiring the daemon env gate — not
  just `--url` — means a stray or socially-engineered `--url` on a production
  invocation hard-rejects instead of silently entering the weaker bearer flow, and
  a hardened build can omit the gate entirely.
- **Explicit operator intent.** Simple mode is a deliberate dev choice; requiring
  the gate + `--url` + `device_code` makes it opt-in and visible, not implicit in a
  server response.
- **Fail-fast on mismatch.** The capability cross-check turns
  rev2-daemon↔simple-C2 (and the reverse) into a clear early error instead of a
  confusing `/pair/complete` rejection (the issue also asks C2 to refuse
  reinterpreting `secret`↔`device_code`).

---

## 4. Wire-freeze impact

**None.** Only the pairing **HTTP** exchange gains a branch. The WSS `/connect`
handshake (challenge → hello → transcript → signature) is **unchanged**, so the
frozen `v1.0.0` wire contract is untouched. The "provisional" origin relaxation
lives entirely on the C2 side; the daemon still signs the same handshake
transcript with the device key. `Config.serverUrl` already accepts a ws(s)://
origin ([src/config.ts](../src/config.ts)) — **no config-schema change**.

---

## 5. Acceptance criteria (for implementation)

- rev2 path **byte-for-byte unchanged**; existing e2e **AE1–AE9 stay green** with
  no new `/capability` dependency.
- **Dev gate:** `--url` without `HUGIN_SIMPLE_PAIRING` → hard reject before stdin
  read / probe. `HUGIN_SIMPLE_PAIRING` set but no `--url` → still plain rev2.
- **Simple happy path:** gate + `--url` + `device_code` (stdin) → strict 200 →
  persist `serverUrl = canonical(--url)`, seed under `key_id` → WSS handshake
  reaches `hello.accepted` (an **integrated** pair-then-handshake test, not just
  the pairing HTTP mock).
- **Rejections (each a distinct, clear error, and each with a test):**
  - `--url` present without the dev gate,
  - non-canonical `--url`,
  - `capability` does not advertise the exact simple marker (incl. truthy-but-wrong
    shape),
  - `hpk1.`-prefixed payload under `--url` (incl. leading-whitespace paste),
  - `/pair/complete` returning non-200, a rev2-shaped 202/`pending` body, or a 200
    with a malformed / invalid-grammar `{agent_id,key_id,tenant_id}` → refuse,
    **no seed stored**, don't reinterpret.
- `device_code` never appears on argv (stdin only); device seed scrubbed on every
  exit path.
- rev2 handshake origin verification remains **exact** (no relaxation leaks into
  rev2).
- New mock endpoints in the reference relay: `GET /capability` + a strict 200
  `/pair/complete`; e2e covering the happy path + all rejections above; extend
  `npm run mock-pairing` with a simple mode.
- `npm run build` / typecheck / the full test + `protocol:check` suites green.

---

## 6. Resolved decisions & remaining C2 dependency

- **rev2 probing:** DECIDED — rev2 is no-probe (see §2 rule 2).
- **Dev gate:** DECIDED — daemon env `HUGIN_SIMPLE_PAIRING` (truthy `1`/`true`) is
  required in addition to `--url`.
- **`capability` schema:** the daemon accepts **one exact documented value**,
  fail-closed (no truthy/loose acceptance). The concrete field name/shape
  (`simple_pairing: true` bool vs `pairing_mode: "simple"` enum) must be pinned to
  match the C2 repo before this ships; until confirmed, implement the daemon to a
  single named constant and flag the exact string in the PR for C2 sign-off.

---

## Review history

- **Codex cross-review (2026-07-03):** verdict **APPROVE-WITH-CHANGES**. Core
  downgrade-resistance and wire-freeze arguments confirmed sound. Folded in:
  explicit daemon dev gate (blocking #1), removed the optional rev2 capability
  probe / made rev2 no-probe normative (blocking #2), strict-200 validation before
  seed storage + rejection tests (blocking #3), pinned capability schema fail-closed
  (#4), hardened the `hpk1.` mixed-mode guard for whitespace/line-endings (#5), and
  made the WSS acceptance criterion an integrated pair-then-handshake test (#6).
