# hugind — Next-Work Brief (new-session handoff)

**Purpose:** everything a fresh session needs to continue Hugin Agent **after the
MVP** — no prior context. The wire protocol is **frozen (`v1.0.0`)** and the
`hugind` daemon MVP (P0–P5) is **built + tested vs a mock relay** on `main`. What
remains is **cross-cutting** (no MVP phases left): production auth, the real
approval bridge, and cloud integration. Self-contained; mirrors the format of the
now-closed `docs/v1.6-work-brief.md`.

---

## 1. What Hugin Agent is

An **outbound-only local bridge daemon** (`hugind`). It installs on a user's
machine behind NAT/firewall, **dials out** over WSS to a cloud orchestrator,
receives commands, runs the local **Claude Code / Codex CLI headlessly**, and
streams normalized results back. No inbound port is ever opened. The wire
protocol is a **shared contract** — `hugind` and the cloud relay import the same
zod SSOT.

## 2. Current state (`main`, tag `v1.0.0`)

- **Wire protocol `v1.0.0` — FROZEN** (cloud FREEZE-OK). `protocol/v1/` zod SSOT +
  spec + F4 cross-language test vectors. `PROTOCOL_VERSION === "1.0.0"`.
- **`hugind` MVP — built + tested vs `mock-relay/`** (phases P0–P5, see
  `docs/hugind-mvp-plan.md` + `docs/hugind-CHANGELOG.md`). Green:
  `npm run typecheck` + `npm run protocol:check` + `npm run e2e` (68 checks,
  scenarios A–Z) + `npm run e2e:claude` (real `claude` 2.1.170, allow/read-only path).
- Every phase was **Codex-cross-reviewed to clean** (loop build→review→fix→review).
- Commit chain on `main`: `b264b2e` v1.6 → `0ed2e83` freeze v1.0.0 → `5d2ed3f` P0 →
  `beb1963` P1 → `d4d9ef3` P2a → `facb940` P2b → `6acb497` P3 → `31de72f` P4 →
  `0796344` P5. Local repo, **no git remote** yet.

### Repo / module map

```
protocol/v1/   FROZEN wire SSOT: messages.ts (zod), transcript.ts (canonical
               signing bytes), digest.ts (RFC 8785 JCS result_digest), origin.ts
               (server_origin canonicalization + tenant_id), gen-vectors.ts +
               test-vectors.json (F4), selftest.ts (protocol:check)
src/
  config.ts    zod daemon config (env-driven); log.ts; util/ids.ts
  conn/        client.ts (WSS + inbound queue), framing.ts (single choke point),
               handshake.ts (Signer seam + devSigner STUB), heartbeat.ts,
               reconnect.ts, outbound.ts (message builders — stamp lease_id)
  jobs/        registry.ts, lease.ts, manager.ts (orchestration: assign/stream/
               ack/result/approval/cancel/revoke/lease.granted/resume)
  engine/      types.ts (Engine + EngineRun incl. onApprovalRequest/resolveApproval),
               claude.ts (ClaudeEngine — real spawn), isolate.ts (isolation +
               login self-check), normalize.ts (stream-json→EventKind), fake-engine.ts
  workspace/   worktree.ts (validate + git worktree, path-injection safe)
  store/       eventlog.ts (SQLite: attempts/events/results, ack GC, resume queries)
  daemon.ts    lifecycle: dial→handshake→job pump→reconnect (DAEMON-LEVEL registry)
  index.ts     entrypoint (env config; wires ClaudeEngine + startup self-check)
mock-relay/    scriptable relay for e2e (no cloud); scripts/e2e.ts (+ e2e-claude.ts)
service/       launchd + systemd skeletons + install README
docs/          hugind-mvp-plan.md, auth-pairing-spec.md, PROPOSAL.md (freeze record),
               hugind-CHANGELOG.md, THIS brief
```

## 3. Locked decisions / invariants (do NOT relitigate)

- **Protocol is FROZEN at `v1.0.0`.** No wire-visible change (message shapes,
  enums, transcript layout, digest rule) without a **major bump (v2) + cloud
  sign-off**. New work must fit the existing wire.
- **`agent_id` = per-device**; `user_id` is off-wire (pairing record only). The
  signed transcript binds `tenant_id` only. EventKind core is frozen
  (`vendor.<engine>.*` for extensions).
- **Fail-closed** stays: with no usable approval gate, the daemon rejects gated
  jobs (`sandbox != read_only` OR `approval_policy != never`). Only `read_only` +
  `never` runs ungated. Never weaken this without the real gate proven.
- **Isolation finding (empirical, 3 real-CLI probes):** on a macOS host whose
  Claude login is **keychain-backed at the default config path**, BOTH
  `config-dir` and `home-swap` isolation **drop the login**; `--settings` MERGES
  (host allow-list survives). See `src/engine/isolate.ts` header. The unblock is
  **env-based CLI auth** (`ANTHROPIC_API_KEY` — always honored in `-p` mode — or
  `CLAUDE_CODE_OAUTH_TOKEN`) injected into the isolated child env.

## 4. The work — three tracks

### Track A — Production auth (biggest; freeze-unblocked, highest value)

Replace the dev stub signer with a real device-key signer + pairing. **Security
surface spec: `docs/auth-pairing-spec.md`** (canonical bytes §5, pairing §3, keys
§2/§7/§8). The seams are already built:

- **Signer seam:** `src/conn/handshake.ts` — `devSigner()` (ephemeral Ed25519,
  clearly marked DEV-ONLY) implements the `Signer` interface and signs
  `buildTranscript(...)` from `protocol/v1/transcript.ts`. Swap it for a real
  signer; **the transcript bytes + `performHandshake` caller do not change.**
- **What to build:**
  1. `src/auth/keystore.ts` — Ed25519 device keypair in the **OS keychain**
     (`@napi-rs/keyring` per auth-spec §2); private key never leaves the host.
     Signing: `crypto.sign(null, transcript, privateKey)` → base64url. (Mirror the
     Ed25519 mechanics in `protocol/v1/gen-vectors.ts` `deriveKeypairFromSeed`.)
  2. `keychainSigner(keyId)` returning `Signer` — wire it into `index.ts` in place
     of `devSigner`.
  3. `hugin-agent connect --server <url>` pairing CLI (auth-spec §3): generate
     keypair → device-code flow → server mints `agent_id`, registers the **public**
     key, returns `agent_id`/`key_id`/`tenant_id` → persist to config (non-secret);
     private key stays in the keychain.
  4. **Mock relay must VERIFY** (it currently accepts any signature): add real
     Ed25519 verification over the reconstructed transcript against a registered
     public key, so an e2e proves the real signer end-to-end (positive + a
     tampered-transcript negative). Reuse `protocol/v1/test-vectors.json` as the
     transcript/signature reference.
- **Done when:** a real keychain signer passes a mock-relay handshake that
  **verifies the signature**; a tampered field → `bad_signature`; pairing persists
  `agent_id`/`key_id`/`tenant_id`; `npm run e2e` still green; Codex CLEAN.
- Defer rotation/revocation (§7/§8) to a follow-up unless asked.

### Track B — Real MCP approval bridge (unblocks the live deny→blocked gate)

The wire round-trip + manager logic + fail-closed are done + tested with the fake
engine. Missing: wire the **real** claude permission prompt to `onApprovalRequest`.

- **Seam:** `src/engine/types.ts` `EngineRun.onApprovalRequest?/resolveApproval?`
  (optional; FakeEngine implements them; the manager forwards `approval.request`
  and routes `approval.response`). `mock-relay` auto-responds allow/deny.
- **What to build:** `src/engine/permission.ts` — an MCP server (reuse
  `spikes/approval-prompt-tool/mcp-server.ts` as the prototype) passed to claude
  via `--mcp-config` + `--permission-prompt-tool`. On a tool prompt it CACHES the
  original input, fires `onApprovalRequest`, blocks on `resolveApproval`, and
  returns `{behavior:"allow", updatedInput:<cached>}` / `{behavior:"deny", message}`.
  Wire it into `ClaudeEngine.run` (`src/engine/claude.ts`).
- **Solve isolation first (invariant §3):** inject env-auth
  (`ANTHROPIC_API_KEY`/`CLAUDE_CODE_OAUTH_TOKEN`) into the isolated child so
  `{isolation gate fires + logged in}` on a real host. Then flip `gateAvailable`
  from the hardcoded `false` in `src/index.ts` to the startup self-check result
  (the self-check should probe that a forced tool actually routes through the
  prompt, not just that login survives — Codex P3 note).
- **Done when:** on a suitable host, a real write job with `deny` → the tool is
  blocked (nothing written) and with `allow` → it runs; the startup self-check
  gates `gateAvailable`; fake-engine `e2e` still green; Codex CLEAN.

### Track C — Cloud integration

- Publish the shared package `@contextualai/hugin-agent/protocol` (v1.0.0) — it's
  the single import for both `hugind` and the cloud relay (no codegen drift).
- Send `docs/PROPOSAL.md` (freeze record) + `protocol/v1/test-vectors.json` +
  this repo to the cloud team; run `hugind` against the **real** relay in place of
  `mock-relay/`. Cloud-side commitments (their §D): linearizable nonce/epoch/lease
  store, durable stream log keyed by `(attempt_id, seq)`/`(attempt_id, event_id)`
  with ack-after-commit, quotas, approval binding.
- Add a git **remote** + push `main` + tag `v1.0.0` when ready.

## 5. Working method (proven — follow it)

Same loop that produced P0–P5: **build a small unit → `npm run typecheck` +
`npm run e2e` (+ `protocol:check` if protocol touched) → Codex cross-review of the
diff via the `agent-olympus:ask` agent → fix → re-review, LOOP TO ZERO ISSUES →
commit.** Extend `scripts/e2e.ts` with new lettered scenarios (A–Z used; continue
AA, AB…) and keep the fake-engine path CI-safe (real-CLI is the opt-in
`e2e:claude`). Consolidate per-feature into one descriptive commit (the repo's
auto-commit hook makes `ao-wip` commits; `git reset --soft <prev> && git commit`
to tidy).

## 6. Verify

```
npm install
npm run typecheck        # clean
npm run protocol:check   # 23 messages + F4 vectors (must stay green — protocol is frozen)
npm run e2e              # daemon ⇄ mock relay, fake engine (CI-safe)
npm run e2e:claude       # real-CLI adapter (needs claude installed + logged in)
```

## 7. Reference

- `docs/auth-pairing-spec.md` — the security surface (Track A authority).
- `docs/hugind-mvp-plan.md` — the P0–P5 design decisions + §5 the seams.
- `docs/hugind-CHANGELOG.md` — phase → commit map.
- `spikes/approval-prompt-tool/` — the permission-prompt-tool findings (Track B).
- `src/engine/isolate.ts` header — the isolation constraint + env-auth unblock.
- `protocol/v1/{transcript,digest,origin}.ts` + `test-vectors.json` — frozen
  contract code shared with the relay.
