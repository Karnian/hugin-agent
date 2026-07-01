# hugind — build log

The daemon, built against the frozen wire protocol `v1.0.0` + a mock relay, phase
by phase ([hugind-mvp-plan.md](hugind-mvp-plan.md) §6). Each phase gated on
`npm run typecheck` + `npm run e2e` + a Codex cross-review (looped to zero issues).

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
