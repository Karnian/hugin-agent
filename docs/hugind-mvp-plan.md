# hugind — MVP Implementation Plan (non-auth, vs mock relay)

**Status:** plan v2 — Codex cross-review B1–B13 incorporated. Ready to build.
**Scope gate:** work-brief §7.3 build. **Production auth is out of scope** (waits
on F1–F5 / cloud confirm of v1.6 → v1.0.0). MVP runs against a **mock relay** with
a **non-auth stubbed handshake**.

## 1. Goal

A `hugind` daemon that dials **out** over WSS (no inbound port), completes a
non-auth handshake (`auth.challenge` → `hello` w/ stub signature →
`hello.accepted`, tracking `connection_epoch`), accepts a `job.assign`, runs the
**Claude CLI headlessly** under **permission isolation** + **git-worktree
isolation**, streams normalized `stream.event`s (seq, persisted before send,
cumulatively acked), bridges the **approval** round-trip, handles **cancel**
(process-group kill) and a digest-acked terminal **result**, and survives
reconnect (heartbeat + backoff + resume). All wire types import the frozen
`protocol/v1` SSOT — daemon and mock relay share it.

## 2. Non-goals (MVP)

Real Ed25519 signing / pairing / rotation; Codex engine adapter; concurrency
tuning / quotas / credit windows; launchd/systemd installer (skeleton + README
only); cross-POP.

## 3. Stack & dependencies

- Node + TS (ESM, zod 4) — same toolchain as `protocol/`.
- **`ws`** (+ `@types/ws`) — WS client (daemon) and server (mock relay); one
  framing path. Enforce `maxPayload = LIMITS.MAX_FRAME_BYTES` on both ends.
- **`better-sqlite3`** (+ `@types/better-sqlite3`) — event log. *Codex (a): chosen
  over experimental `node:sqlite` — synchronous + stable on the durability path.*
  Native build; acceptable.
- **`@modelcontextprotocol/sdk`** — already present; the spike's `mcp-server.ts`
  pattern becomes the real permission bridge.

## 4. Module layout

```
protocol/v1/
  transcript.ts        # NEW: buildTranscript()/lp() MOVED here from gen-vectors.ts
                       #   (Codex B9 — production handshake must not import a test
                       #   generator). gen-vectors.ts + the daemon both import this.
                       #   Non-wire refactor: no message/PROTOCOL_VERSION change.
src/
  index.ts             # entrypoint: load config → construct daemon → start
  config.ts            # zod-validated config (server URL, agent_id, roots, limits, isolation mode)
  log.ts               # structured json-line logger (stderr)
  daemon.ts            # lifecycle: connect→run→drain→stop; owns epoch + registry
  conn/
    framing.ts         # SINGLE inbound choke point: size-check → JSON.parse → parseMessage → validateInbound
    outbound.ts        # outbound builders that STAMP lease_id + validate seq monotonicity (no caller discipline)
    client.ts          # WSS dial-out (ws, maxPayload); send()/on(message); epoch monotonic gate
    handshake.ts       # challenge→hello(stub sig via transcript.ts)→accepted; capture connection_epoch
    heartbeat.ts       # periodic heartbeat; suspect/dead counters (never self-reassign)
    reconnect.ts       # exponential backoff redial (transport only; resume lives in P4)
  jobs/
    registry.ts        # attempt_id → live job; idempotent on duplicate assign; capacity caps
    lifecycle.ts       # accept/reject; status transitions; terminal result (+digest)
    lease.ts           # current lease_id/attempt; validate+fence (P2); rotation overlap window (P4)
  engine/
    claude.ts          # spawn `claude -p --output-format stream-json --verbose` (stdin "ignore", detached)
    isolate.ts         # permission-isolated config (HOME swap default) + auth preservation + startup self-check
    permission.ts      # MCP bridge: prompt-tool CALL → cache input → approval.request → await → {behavior,...}
    normalize.ts       # claude stream-json line → core EventKind stream.event payload
    fake-engine.ts     # test double: streams events, simulates prompt CALLs, cancel, hang (CI gate)
  workspace/
    worktree.ts        # realpath repo_root (allowlist + symlink guard); git worktree add/remove
  store/
    eventlog.ts        # SQLite: attempts, events(seq), results, ack cursor; backpressure counts; GC; resume queries
  util/
    digest.ts          # base64url(SHA-256(JCS(job.result minus id,ts))) — RFC 8785 JCS, not JSON.stringify
    ids.ts             # message id / agent_run_id generation
mock-relay/
  server.ts            # WSS server: challenge, accept hello, drive jobs, ack, cancel, digest-ack
  scenario.ts          # scripted e2e scenarios (incl. duplicate-assign, mid-stream drop)
scripts/
  e2e.ts               # boot mock relay + daemon (fake engine), run scenarios, assert, exit code
```

`tsconfig` `include` += `src`, `mock-relay`, `scripts`. npm scripts: `hugind`,
`mock-relay`, `e2e`, `e2e:claude` (opt-in real CLI).

## 5. Key design decisions

### 5.1 Transport invariants (single choke point) — B2, epoch, validateInbound
- **Frame size:** set `ws` `maxPayload = LIMITS.MAX_FRAME_BYTES` AND re-check
  byte length in `framing.ts` **before** `JSON.parse` (reject oversized → close /
  `nack payload_too_large`). Never parse to discover size.
- **Every inbound frame** flows through `framing.ts`: size → `parseMessage`
  (zod) → `validateInbound(DIRECTION+phase)`. No other inbound parse path exists.
- **`connection_epoch` monotonic:** `conn/client.ts` accepts `hello.accepted`
  only if `new_epoch > current_epoch`; older sockets are closed/ignored. Owned in
  one place (daemon holds the current epoch).

### 5.2 Non-auth handshake, forward-compatible — B9
`handshake.ts` builds `hello` via a `signTranscript(challenge)` hook. MVP hook
returns a stub 86-char signature + dev `key_id`; mock relay accepts any. The
transcript bytes come from the **moved** `protocol/v1/transcript.ts`
`buildTranscript()` — the same module the real signer and the test vectors use, so
stub-now and real-later agree byte-for-byte. Dropping in the Ed25519 signer later
changes only the hook body.

### 5.3 Durability, ordering, backpressure, GC — B3, B7
- `seq` per-attempt monotonic from 1; **persist event to SQLite before** `ws.send`
  (synchronous better-sqlite3 write on the critical path). Reject inbound `seq:0`
  (schema already does; add a test).
- **Cumulative ack:** advance an ack cursor on `stream.ack`; **GC** stream events
  only once `ack_seq` covers them; keep a `pending_result` until
  `job.result.ack.result_digest` matches, then GC.
- **Backpressure (all three LIMITS caps):** `store/eventlog.ts` tracks per-attempt
  unacked bytes + events; `conn/client.ts` tracks per-connection unacked bytes.
  On any cap → pause reading the engine stdout; resume after acks drain.

### 5.4 Lease — B1 (core in P2, rotation in P4)
- **P2:** every attempt-scoped message carries `lease_id` (stamped by
  `conn/outbound.ts`); validate inbound lease against the current generation;
  fence revoked/unknown/stale (`stale_lease`); on lost/revoked lease → **local
  fence** = process-group kill.
- **P4:** `lease.granted` rotation — accept BOTH old and new `lease_id` until
  `new_lease_effective_at + LIMITS.LEASE_ROTATION_OVERLAP_MS`, then nack old as
  `stale_lease`.

### 5.5 Idempotency — B4
`registry.ts` is keyed by `attempt_id`. A duplicate `job.assign` (at-least-once
delivery) MUST NOT spawn a second worktree/CLI — return the existing state and
re-confirm current `job.accept`/`job.result`. e2e covers back-to-back identical
assigns.

### 5.6 Permission isolation + auth preservation — B5 (spike's open tension)
- **Default = proven HOME swap** (spike confirmed it cuts the host
  `allow(*)`+`dontAsk`). Isolated `HOME/.claude/settings.json` =
  `{permissions:{allow:[],defaultMode:"default"}}`.
- **Auth preservation:** copy the host credential
  (`~/.claude/.credentials.json`) into the isolated dir when present; on macOS,
  detect keychain-backed login and skip copy.
- **`CLAUDE_CONFIG_DIR`** is offered as an opt-in, **promoted only after a startup
  probe confirms** it actually isolates (narrower than HOME swap).
- **Startup isolation self-check (security gate):** before the first
  `job.accept`, run a harmless real-CLI probe that must (a) show no inherited
  allow-list and (b) keep login; if it fails, the daemon refuses write/exec jobs
  (fails closed). Env scrubbed to an allowlist; `~/.ssh`/cloud-cred paths denied;
  assignment `network_policy` enforced (auth-spec §9).

### 5.7 Engine spawn — B6
`claude.ts` spawns with `stdio:["ignore","pipe","pipe"]` (prompt via `-p`, NOT
stdin — open stdin makes claude wait), `detached:true` (own process group for
cancel), flags: `-p`, `--output-format stream-json`, `--verbose`, `--mcp-config`,
`--permission-prompt-tool mcp__approval__permission_prompt`, `--permission-mode
default`. Timeout → SIGTERM then SIGKILL after `grace_ms`.

### 5.8 Approval bridge — B10, B11
Two distinct shapes:
- The **MCP tool** returns to Claude: `{behavior:"allow",updatedInput:<input>}` or
  `{behavior:"deny",message}`.
- The **relay** speaks: `approval.request` → `approval.response{decision}`.
`permission.ts` **caches the original tool input** on the prompt CALL, forwards an
`approval.request` over WSS, blocks on `approval.response`, then maps
`allow → {behavior:allow, updatedInput:<cached original>}` / `deny → {behavior:deny}`.
Restart between request and response → **fail closed** (deny).

### 5.9 Cancel — process group
`job.cancel` → `process.kill(-pid, "SIGTERM")`, then `SIGKILL` after `grace_ms`;
emit `job.status(cancelling→cancelled)` + terminal `job.result(cancelled)`.

### 5.10 Worktree — B (reject non-git)
`repo_root` realpath'd + allowlist-checked; reject symlink escape / out-of-root
`cwd`. Each attempt: `git worktree add` off `base_sha` under a daemon dir; removed
on terminal. **Non-git `repo_root` → `job.reject{root_not_allowlisted}`** (Codex
(b): no temp-copy fallback in MVP).

### 5.11 Digest — B8
`util/digest.ts` implements **RFC 8785 JCS** (sorted keys, canonical
number/string, no whitespace) over `job.result` minus `id`/`ts`, then
`base64url(SHA-256(...))`. NOT `JSON.stringify`. Ship a P0 self-check: a fixed
`job.result` → known digest + a determinism (reorder-keys → same digest) check.
Mock relay imports the same util, so both sides agree by construction.

## 6. Build phases (each gated: typecheck + e2e where testable + Codex review)

- **P0 scaffolding** *(independent)* — deps; move `buildTranscript`→
  `protocol/v1/transcript.ts` (keep `protocol:check` green); tsconfig include;
  scripts; `config.ts`, `log.ts`, `util/ids.ts`, `util/digest.ts` (+ JCS
  self-check). Gate: typecheck + protocol:check + digest self-check.
- **P1 transport + handshake** *(P0)* — `conn/*` incl. framing size-check + epoch
  gate + heartbeat + transport-only reconnect; minimal mock relay (challenge +
  accept + idle + drop). Gate: e2e "connect→handshake→heartbeat→relay drop→
  redial; oversized frame rejected; non-monotonic epoch ignored".
- **P2a job core (fake engine)** *(P1)* — `jobs/registry` (idempotent),
  `jobs/lifecycle`, `jobs/lease` (validate+fence), `store/eventlog` (seq persist,
  ack cursor, GC, backpressure caps), `util/digest` wired into results,
  `engine/fake-engine.ts` (streams events; extensible for prompts/cancel/hang).
  Mock relay assigns + acks. Gate: e2e "assign→accept→stream(persist,ack,GC)→
  result→digest-ack; duplicate assign idempotent; backpressure pauses".
- **P2b real engine** *(P2a)* — `engine/claude.ts`, `engine/isolate.ts` (+ startup
  self-check), `engine/normalize.ts`, `workspace/worktree.ts`. Gate: typecheck +
  opt-in `e2e:claude` (real CLI on a logged-in host) + fake-engine e2e still green.
- **P3 approval + cancel** *(P2)* — `engine/permission.ts` (MCP bridge, input
  cache, fail-closed), cancel via process group; fake engine emits prompt CALLs +
  honors SIGTERM. Gate: e2e "allow→proceeds, deny→blocked, cancel→killed".
- **P4 liveness + resume** *(P1–P2)* — reconnect resume from `active_jobs`/
  `pending_results` → consume `hello.accepted.resume[]` (resume_from / resend_result
  / ack_pending / abandon); lease rotation overlap. Gate: e2e "mid-stream drop →
  reconnect → resume_from + resend_result".
- **P5 mock-relay completeness + packaging** — full scenarios; `service/`
  skeleton + README; CHANGELOG/README updates. Gate: full e2e + Codex.

## 7. Verification
Per phase: `npm run typecheck` + `npm run e2e` (mock relay + fake engine) green;
`npm run protocol:check` stays green; Codex cross-review of the diff; advance only
when all clean. Real-CLI path is the opt-in `e2e:claude`.

## 8. Resolved decisions (Codex)
(a) **better-sqlite3** (not node:sqlite). (b) non-git repo_root → **reject**.
(c) isolation default **HOME swap**, CLAUDE_CONFIG_DIR promoted only after a
startup probe + self-check. (d) **fake-engine is the primary CI gate**; real CLI
opt-in. (e) lease **validate/fence in P2**, rotation overlap in P4.

## 9. Top risks → de-risk
1. **Isolation default bypass** → default to proven HOME swap + startup self-check
   that fails closed before any write/exec job.
2. **Scattered invariants** → enforce at choke points: `framing.ts` (inbound
   parse+size+validate), `conn/outbound.ts` (stamp lease_id + seq monotonic).
3. **Duplicate assign** → registry idempotent by `attempt_id`; e2e double-assign.
4. **JCS digest mismatch → pending_result limbo** → real RFC 8785 JCS in P0 with a
   known-vector self-check.
