# hugind — build log

The daemon, built against the frozen wire protocol `v1.0.0` + a mock relay, phase
by phase ([hugind-mvp-plan.md](hugind-mvp-plan.md) §6). Each phase gated on
`npm run typecheck` + `npm run e2e` + a Codex cross-review (looped to zero issues).

## Track C — Python C2 integration (pairing ceremony rev2 + reference verifier)
Vendors the frozen auth/handshake contract to the Python C2 without requiring it
to import the TS package: `protocol/v1/py/` is a Python reference verifier for the
frozen `v1.0.0` handshake transcript/signature, matching the TS vectors and
canonicalization rules. `protocol/v1/pairing.ts` adds the rev2 pairing PoP
contract helpers (`buildPairingTranscript`, `keyFingerprint`, `validateB64u32`,
`REJECTED_TEST_PUBLIC_HEX`), with `protocol/v1/gen-pairing-vectors.ts`,
`protocol/v1/pairing-selftest.ts`, and `protocol/v1/pairing-test-vectors.json`
pinning the cross-language ceremony bytes. The LOCKED rev2 pairing ceremony is
browser-initiated: an authenticated C2 session mints an `hpk1.<base64url(json)>`
paste token, the daemon validates the frozen canonical origin, scheme-swaps
`wss`→`https`, posts `/pair/complete` with `{secret, public_key, pop_signature}`,
then polls `/pair/status`; activation is mandatory browser fingerprint
confirmation over the server-stored winning public key. The C2 contract is
linearizable CAS (`issued`→`pending`→`active|rejected|expired|burned`), refuses
bad b64u32/low-order/test keys before strict Ed25519 PoP, preserves a single
generic unauth-ingress failure class, and supports bounded same-winner
idempotent re-complete including the post-active short-TTL recovery corner. The
wire is unchanged (`v1.0.0` frozen; pairing PoP is off-wire). Verification:
`npm run pairing:check` green (TS 53/53), `protocol/v1/py/selftest.py` green
(Python 84/84), and `npm run protocol:check` + `npm run e2e` still green. The
daemon-side rev2 implementation (`src/auth/connect.ts` rewrite, mock
pairing-server migration, e2e coverage) is QUEUED, not yet built; the committed
daemon still uses the old daemon-initiated device-code pairing. Cross-reviewed
(Claude + Codex, 3 rounds each side) → LOCKED.

## Track B — real MCP approval bridge (permission-prompt-tool → onApprovalRequest)
Wires Claude Code's `--permission-prompt-tool` to the daemon's remote-approval seam
(brief §4B). `src/engine/permission.ts` — an `ApprovalBridge` (daemon-side
UNIX-socket server, NO TCP port, so the no-inbound-port invariant holds) + the
stdio MCP permission subprocess claude spawns via `--mcp-config`: on a tool prompt
it caches the input, relays over the socket, BLOCKS for the decision, and returns
`{behavior:allow,updatedInput}` / `{behavior:deny,message}` — fail-closed (a broken
channel ⇒ deny). `ClaudeEngine.run` starts the bridge, writes the mcp-config, and
spawns claude with `--strict-mcp-config --permission-prompt-tool
mcp__hugin__permission_prompt --permission-mode default`; `onApprovalRequest` /
`resolveApproval` delegate to the bridge (the P3 manager round-trip is unchanged).
`isolate.ts` scrubs the child env to an allowlist (auth-spec §9 — no full-env
leak, no stray `CLAUDE_CONFIG_DIR`), injects env-auth
(`ANTHROPIC_API_KEY`/`CLAUDE_CODE_OAUTH_TOKEN`) into the isolated child (the
isolation-finding unblock), and adds `selfCheckGate` — a startup probe that asks
claude to WRITE a sentinel, DENIES it, and requires the prompt to fire AND the
write to be BLOCKED AND claude to exit (login surviving / a prompt firing alone are
not sufficient). Two fail-open holes are closed: read_only jobs are ENFORCED at the
engine (`--disallowedTools Write/Edit/…/Bash`), so a read_only job can't write/exec
even under a permissive host config; and `index.ts` marks `gateAvailable` LIVE only
under the ISOLATED empty-allow config (where every tool uniformly prompts) — the
host-fallback / `none` path fails closed, so a gated job never runs where a host
allow-list could pre-approve Bash. The claude-facing request/response shape is the
community/de-facto contract (Anthropic hasn't published it — CC 2.1.170); the
daemon-side bridge is fully unit-tested. Wire unchanged (`v1.0.0` frozen; Track B
touches no protocol file). CI-safe e2e (no real claude/env-auth): AH (bridge
round-trip via an MCP-client stand-in) / AI1–6 (arg + mcp-config wiring + read_only
`--disallowedTools`) / AJ1–3 (`selfCheckGate`: fired+blocked→live, deny-ignored→off,
pre-approved→off) / AK (env-auth injection). The LIVE deny→blocked gate is guarded
in `e2e:claude` — it needs env-auth or a clean login (this host has neither, per
the isolation finding). Codex cross-reviewed (4 rounds) → CLEAN.

## Track A — production auth (device-key signer + pairing + relay verify)
Real Ed25519 device key replaces the dev stub signer, security surface per
[auth-pairing-spec.md](auth-pairing-spec.md). `protocol/v1/ed25519.ts` — shared
seed→key + `signTranscript`/`verifyTranscript`, extracted from `gen-vectors.ts` so
the signer, relay verifier, F4 vectors, and selftest can't drift (vectors stay
byte-identical). `src/auth/keystore.ts` holds the 32-byte seed in the OS keychain
(`@napi-rs/keyring`, lazy-imported) and `keychainSigner(keyId)` signs the SAME
frozen transcript — the `performHandshake` caller is unchanged (only the key
source is). `hugin-agent connect` device-code pairing
(`src/auth/{connect,config-file,paths}.ts` + `src/connect.ts`) mints
`agent_id`/`key_id`/`tenant_id`, registers the PUBLIC key, and persists non-secret
config; the private key never leaves the host. The mock relay now VERIFIES the
possession proof (`verifyHello`, reconstructing the transcript per auth-spec §5 —
`tenant_id`/`server_origin` off-wire from the pairing record) instead of accepting
any signature; a duplicate `hello` post-auth is ignored. Handshake hardening
(`conn/client.ts`): a `hello.accepted` that arrives BEFORE the signed `hello` is
discarded (`armForAccept`), so a premature/replayed accept can't complete the
handshake. `index.ts` loads the pairing config + keychain signer, fail-closed when
unpaired. Wire unchanged (`v1.0.0` frozen); `protocol:check` green (F4 vectors
byte-identical). e2e AA (verify accepts a real signer) / AB (tampered transcript →
`bad_signature`, not accepted) / AC1–8 (`verifyHello` vs committed F4 vectors +
record validation) / AD (OS-keychain round-trip, guarded) / AE (pairing persists
config + seed off-wire) / AF (duplicate post-auth `hello` ignored) / AG (premature
`hello.accepted` discarded). Codex cross-reviewed (4 rounds) → CLEAN.

## P5 — packaging + completeness
Graceful drain (`agent.draining` on `stop()`); mock-relay `onJobStatus`/`onDraining`/
`stallHandshake` hooks; `service/` skeleton (launchd + systemd + install README);
README updated from "pre-MVP spikes" to the built MVP. e2e Z (graceful drain).

## P4 — reconnect resume + lease rotation (`31de72f`)
Daemon-level registry (live runs survive reconnects); durable-store resume
(`resume_from`/`resend_result` re-stamped to the current lease, `ack_pending`/
`abandon`); `lease.granted` rotation overlap. Codex 4 rounds → CLEAN. e2e U/V/W/X/Y.

## P3 — approval bridge + fail-closed (`6acb497`)
`approval.request`/`response` round-trip (auto-deny timeout, lease-checked);
fail-closed when the gate is unavailable (`sandbox != read_only` or
`approval_policy != never`). Fake-engine path; real MCP bridge deferred. e2e P/R/S/T.

## P2b — real Claude adapter (`facb940`)
`ClaudeEngine`: spawn `claude -p --output-format stream-json` in a git worktree,
normalize → events, process-group cancel. Real-CLI validated (`e2e:claude`).
Isolation finding: config-dir/home-swap drop the macOS keychain login.

## P2a — job execution core (`d4d9ef3`)
SQLite event log, idempotency (registry ?? durable store), digest-ack GC,
backpressure, lease validate/fence. Codex 5→3→1→0. e2e D/E/F/G/H/I/J/K/L.

## P1 — transport + non-auth handshake (`beb1963`)
WSS dial-out, single-choke framing, handshake (dev signer over the real
transcript), heartbeat, backoff reconnect, monotonic epoch gate. e2e A/B/C/Q.

## P0 — scaffolding (`5d2ed3f`)
Deps (ws, better-sqlite3); `buildTranscript` → `transcript.ts`; `digest.ts`
(RFC 8785 JCS); `config.ts`/`log.ts`/`util/ids.ts`.
