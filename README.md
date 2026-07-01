# Hugin Agent

> Outbound-only local bridge daemon that runs your headless **Claude Code / Codex CLI**
> on behalf of a cloud orchestrator — without opening any inbound ports.

Your laptop sits behind NAT and a firewall. `hugind` dials **out** to the
orchestrator over WSS, receives commands, runs the local coding CLI headlessly,
and streams normalized results back. Same outbound-only pattern as a GitHub
Actions self-hosted runner or Claude Code Remote Control. **No inbound port is
ever opened.**

---

## Status

- **Wire protocol `v1.0.0` — FROZEN** ([`protocol/`](protocol/README.md)). zod SSOT
  + spec + F4 cross-language test vectors. Cloud diff-review: **FREEZE-OK**.
- **`hugind` MVP — built vs a mock relay** (phases P0–P5, see
  [`docs/hugind-mvp-plan.md`](docs/hugind-mvp-plan.md)). Transport, non-auth
  handshake, reconnect, the full job lifecycle, git-worktree isolation, and
  reconnect resume + lease rotation are implemented and tested (`npm run e2e`).
  The **real Claude adapter** streams a job end-to-end on the real CLI
  (`npm run e2e:claude`, allow / read-only path). The **approval round-trip +
  fail-closed policy** are implemented and tested at the manager/protocol level
  with a fake engine — the **live Claude permission bridge is deferred**, so the
  daemon currently **fails closed** on write/exec jobs (see below).
- **Deferred** (each explicitly scoped): production auth (dev stub signer →
  OS-keychain Ed25519 + device-code pairing); the real MCP permission bridge for
  the live approval gate (needs env-based CLI auth under isolation — see
  [`src/engine/isolate.ts`](src/engine/isolate.ts)); P5 service packaging is a
  skeleton under [`service/`](service/README.md).

## Architecture

```
protocol/v1/   frozen wire SSOT (messages, transcript, digest, origin) — shared with the relay
src/
  conn/        WSS client, single-choke-point framing, handshake, heartbeat, reconnect
  jobs/        registry (idempotent), lease, manager (orchestration, approvals, resume)
  engine/      Engine interface; ClaudeEngine (spawn stream-json), isolate, normalize; fake engine
  workspace/   git-worktree isolation (allowlist + realpath + path-injection safe)
  store/       SQLite event log (seq persist-before-send, ack GC, digest-ack, backpressure)
  daemon.ts    lifecycle: dial → handshake → job pump → reconnect (daemon-level registry)
mock-relay/    a scriptable relay for e2e (no cloud needed)
```

Principles: outbound-only · at-least-once + idempotent (`seq`/`event_id` dedupe) ·
lease fencing on every attempt-scoped message · digest-acked completion ·
persist-before-send durability · fail-closed on ungated write/exec.

## Run

```bash
npm install
npm run typecheck        # type-check protocol + daemon
npm run protocol:check   # validate every protocol message + F4 vectors
npm run e2e              # daemon ⇄ mock relay, fake engine (CI-safe, no cloud/claude)
npm run e2e:claude       # real-CLI adapter check (needs `claude` installed + logged in)
npm run hugind           # run the daemon (config via env — see below)
npm run mock-relay       # a standalone mock relay
```

## Configure (env — [`src/config.ts`](src/config.ts))

`HUGIND_SERVER_URL` + `HUGIND_AGENT_ID` are required; the rest default. To run it
supervised (launchd / systemd), see [`service/`](service/README.md).

```bash
HUGIND_SERVER_URL=wss://relay.example.com \
HUGIND_AGENT_ID=my-laptop \
HUGIND_PROJECT_ROOTS=/Users/you/code \
npm run hugind
```

## Also here

| Path | What |
|------|------|
| [`docs/hugind-mvp-plan.md`](docs/hugind-mvp-plan.md) | The build plan (P0–P5) + design decisions |
| [`docs/auth-pairing-spec.md`](docs/auth-pairing-spec.md) | Security surface: canonical signing bytes, pairing, keys |
| [`docs/PROPOSAL.md`](docs/PROPOSAL.md) | Cloud freeze record (v1.6 → v1.0.0) |
| [`spikes/approval-prompt-tool/`](spikes/approval-prompt-tool/README.md) | The approval-mechanism spike (permission-prompt-tool findings) |

## License

Apache-2.0 (proposed).
