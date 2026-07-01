# hugind — build log

The daemon, built against the frozen wire protocol `v1.0.0` + a mock relay, phase
by phase ([hugind-mvp-plan.md](hugind-mvp-plan.md) §6). Each phase gated on
`npm run typecheck` + `npm run e2e` + a Codex cross-review (looped to zero issues).

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
