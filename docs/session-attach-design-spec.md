# Session Attach & Resume — Design Spec (v0.3 draft)

**Status:** draft · **Author:** Claude · **Cross-review:** Codex (NEEDS-CORRECTIONS → applied)
**Date:** 2026-07-05 · **Grounded in:** live PoC on this host (claude 2.1.201, codex-cli 0.140.0)

> v0.3: reconciled to v2-first per issue #6 three-way review.
>
> v0.2 changelog: Codex cross-review corrected the versioning (v1.1 → **v2**), Codex
> metadata (`base_instructions`, not `instructions`), the Claude session count
> (top-level vs nested subagent logs), the `ai-title` assumption, several CLI gotchas,
> and added missing protocol/security controls (opaque handles, request/turn IDs,
> pagination, cancel, error/accept-reject, ack/backpressure, per-session locks, audit).

## 1. Goal

Let the operator, through the C2, **see the daemon machine's existing `claude`/`codex`
CLI sessions** and **resume-converse** with any of them.

1. **Discovery** — enumerate local CLI sessions with metadata.
2. **Resume conversation** — pick a session, send a message; the daemon resumes it
   non-interactively and streams the response back.

**In scope:** the `claude`/`codex` **CLIs**; **resume** semantics; read-only-first.
**Out of scope (v1):** live-inject into a running interactive TUI; the Codex **desktop
app** (`app-server`, separate store).

## 2. Why this is new work

The daemon today is a **one-shot job dispatcher** (`job.assign` → fresh `claude -p` in an
isolated worktree → streamed result). It has **no session enumeration/attach**, and the
frozen protocol v1.0.0 has **no session messages**. Hence the empty C2 "running sessions"
list — the feature does not exist on the daemon, the protocol, or the C2.

## 3. Grounded findings (PoC, with Codex-verified corrections)

### 3.1 Session stores
| Engine | Path | Count (this host) | ID |
|---|---|---|---|
| claude | `~/.claude/projects/<enc-cwd>/<uuid>.jsonl` | **126 top-level** (+~1056 nested subagent logs — EXCLUDE) | filename = `sessionId` |
| codex | `~/.codex/sessions/<yr>/<mo>/<dd>/rollout-<ts>-<uuidv7>.jsonl` | 494 | `session_meta.payload.id` |

- **Claude:** enumerate **top-level session files only**; nested `**/subagents/*.jsonl`
  (and other nested logs) must be excluded — a recursive count sees ~1182 files.
  Metadata (`sessionId, cwd, gitBranch, version, timestamp`) is **not guaranteed on the
  first record** — initial records may be `last-prompt/mode/permission-mode/bridge-session`;
  cwd/version appear on later `attachment/user` records, so scan until found.
  An `ai-title` record exists but is **rarely present** (1/126 in the review scan; newer
  CLI only) — treat as optional; fall back to the first real user message.
- **Codex:** first record `type: session_meta`, `payload = {id, cwd, originator,
  cli_version, timestamp, **base_instructions**}` (NOT `instructions` — 494/494 use
  `base_instructions`). The first `response_item` is an injected `<permissions
  instructions>` preamble — skip it for the title.

Enumerating all 620 with a head-only read + mtime took **0.27 s**.

### 3.2 Resume mechanics (both PROVEN — recalled a stored codeword across calls)
- **claude:** `claude --resume <id> -p "<msg>" --output-format stream-json [--fork-session]`.
  Maps onto the existing `ClaudeEngine`; `--fork-session` continues under a NEW id
  (original untouched) — VERIFIED usable.
- **codex:** `codex exec resume <id> "<msg>" --json --skip-git-repo-check -o <FILE>`
  (the flag is `-o, --output-last-message <FILE>`). Verified: resume **rejects
  `-s/--sandbox`** (`error: unexpected argument '-s'`); outside a git repo it errors
  `Not inside a trusted directory and --skip-git-repo-check was not specified` → needs
  `--skip-git-repo-check`. UNVERIFIED / to re-check before build: that resume "inherits
  the session sandbox policy" (inferred), the exact stdin-blocking condition (codex help
  says stdin is read only when `PROMPT` is `-`), and **non-interactive fork** — `codex
  exec resume` exposes NO fork flag (there is a separate INTERACTIVE `codex fork`); do
  not assume Codex fork until proven.

## 4. Architecture (three layers)

### 4.1 Daemon
- **`SessionEnumerator`** (read-only): scan both stores (top-level only, excluding nested
  claude subagent logs), extract §5 metadata, **scope by policy (§7)**, return handles.
  Must be TOCTOU-safe (open+fstat, verify ownership, realpath containment) and never
  follow symlinks out of the allowlist.
- **`SessionManager` + engine registry**: today `JobManager` holds ONE `Engine` and only
  routes job messages (`src/jobs/manager.ts:47-51`, `src/daemon.ts:178-203`). Session
  work needs a registry (`claude`→`ClaudeEngine.resume`, `codex`→new `CodexEngine.resume`)
  and a per-session mutex so two turns can't resume the same session concurrently.
- **Resume engines**: `ClaudeEngine.resume` (add `--resume`, default `--fork-session`);
  new `CodexEngine.resume` (spawn `codex exec resume`, normalize its JSONL events to the
  daemon's stream shape, mirroring `engine/normalize.ts`).

### 4.2 Protocol — **v2-first** (corrected from v1.1)
Per repo policy (`protocol/v1/messages.ts:51`, `protocol/README.md:6-7`), a **new CORE
message type or capability field requires a MAJOR bump (v2)** — not a minor. Both
constraints are real: `Capabilities`/messages are `strictObject`s in a
`discriminatedUnion`, and inbound decode parses the schema BEFORE routing
(`src/conn/framing.ts:32-40`), so a v1.0 peer would reject any new frame or a
`capabilities.sessions` field outright.

Also note: the handshake *fields* for negotiation exist (`Hello.protocol_version` →
`HelloAccepted.negotiated_version`) but are currently sent as a **constant**
(`src/conn/handshake.ts:79,87`; `mock-relay/server.ts:283-290`), while the unused
`negotiateVersion()` helper already exists at `protocol/v1/index.ts:13`. Real
negotiation must be built; it cannot be assumed from the current constant.

**Chosen path: v2(A).** Add the messages below to a v2 union, add
`capabilities.sessions`, and implement **v1/v2 dual-support**: existing v1 daemons
keep connecting on the frozen wire and never receive `session.*`; `session.*` is sent
only after `hello.accepted.negotiated_version` resolves to v2 and the sessions
capability is present.

The wrapper idea is **not** a v1 vendor channel: framing rejects unknown `type`
before routing, so a v1 peer cannot safely receive an extension wrapper either. A
wrapper MAY still be a v2 envelope design if the team wants one v2 outer frame, but
option B is killed as a "v1 channel."

Proposed v2 messages, each with **`request_id`** correlation:
- `session.list.request` (s→a): `{ request_id, filter?: {engine?, cwd_prefix?, active_only?, updated_after?}, page?: {cursor?, limit} }`
- `session.list.response` (a→s): `{ request_id, sessions: SessionInfo[], next_cursor?, truncated }`
- `session.resume.request` (s→a): `{ request_id, handle, message, options?: {fork?, sandbox?, model?} }` — `handle` is an OPAQUE server-issued token (§5), NOT a raw session id.
- `session.resume.accept` / `session.resume.reject` (a→s): `{ request_id, turn_id | reason }`
- `session.event` (a→s): `{ turn_id, seq, event }` — streamed output.
- `session.ack` (s→a): `{ turn_id, ack_seq }` — TURN-SCOPED ack/backpressure; do **not** reuse attempt/lease-scoped `stream.ack` (`job_id/attempt_id/lease_id`).
- `session.turn.result` (a→s): `{ turn_id, status, final_message, new_session_handle? }` (fork → new handle).
- `session.message` (s→a): `{ request_id, handle, message }` — follow-up turns.
- `session.cancel` (s→a): `{ turn_id }` → process-group cancel (like the job cancel path).
- `session.error` (a→s): `{ request_id|turn_id, code, message }`.

Capability: `capabilities.sessions: { list, resume }` (v2), plus fixing the existing stub
with real `engines.<e>.{installed,version,logged_in}` detection.

### 4.3 C2 (server side — REQUIRED work)
Issue `session.list.request` (paginated), render the list, hold the opaque handles, drive
`session.resume`/`message`/`cancel`, render `session.event` + `turn.result`, surface
`session.error`.

## 5. Unified session metadata (SessionInfo) — corrected schema
```
handle        opaque token  # daemon-issued; binds {engine, session_id, cwd, path, mtime, agent/tenant}. C2 NEVER sends raw ids.
engine        "claude" | "codex"
cwd           string        # working dir (redacted/relative-to-root by default — §7)
git_branch    string|null   # claude only
cli_version   string|null   # claude "version" / codex "cli_version"
title         string        # claude: ai-title IF present else first user msg; codex: first real user turn (skip preamble)
created_at    iso           # first record with a timestamp
updated_at    iso           # file mtime
active        bool          # updated within window (+ optional live-process check)
msg_count     int           # approx (line count)
```
`session.list` is **METADATA-ONLY**: no prompt text, output text, or transcript bodies.
Titles derived from local logs must be short/redacted metadata. The **raw session_id
and absolute path stay daemon-side**, keyed by `handle`; a resume request carries the
handle, the daemon re-validates it (still in allowlist, unchanged ownership) before
spawning.

## 6. Message flow (MVP: re-resume per turn)
```
C2 → session.list.request {page:{limit:50}}
A  → session.list.response {sessions:[…handles…], next_cursor:"…"}
C2 → session.resume.request {request_id, handle:"h_…", message:"…", options:{fork:true, sandbox:"read_only"}}
A  → session.resume.accept {request_id, turn_id}
A  → session.event {turn_id, seq:1, event:<delta>} …           # ack/backpressure applies
C2 → session.ack {turn_id, ack_seq}                             # turn-scoped; not stream.ack
A  → session.turn.result {turn_id, status:"ok", final_message, new_session_handle?}
C2 → session.message {request_id, handle, message}             # next turn = re-resume under mutex
C2 → session.cancel {turn_id}                                  # optional
```

## 7. Security & isolation (expanded per review)
- **Opaque handles, not raw IDs.** Never accept an arbitrary session id/path from the C2;
  issue daemon-side handles bound to `{engine, session_id, cwd, path, mtime,
  agent/tenant}` and re-validate on use. C2 then re-issues its own opaque handle to
  the frontend; the frontend never receives daemon handles or raw ids.
- **Exposure scope = allowlist, fail-closed.** Enumerate only sessions whose `cwd` is
  under `projectRoots` (`HUGIND_PROJECT_ROOTS`); no allowlist → expose nothing. (The 620
  raw sessions include `/Users/k/Desktop/invest`, client work — must not leak by default.)
- **Redact by default.** Return `cwd` relative to its allowlisted root; titles/first
  prompts can contain secrets — offer redaction/opt-in.
- **C2 owns operator/tenant authorization.** Default policy is owner-only visibility,
  with any shared/operator ACL as a separate opt-in. The daemon cannot enforce operator
  ACLs: it holds only `agentId`/`tenantId`; `user_id` is C2-side pairing-record state
  (`src/config.ts`, `src/auth/config-file.ts`).
- **Exclude nested claude subagent logs** (`**/subagents/*.jsonl` etc.).
- **Filesystem safety.** Enforce file ownership, symlink/realpath checks, allowlist
  containment on the STORED cwd, TOCTOU-safe open/read.
- **Resume runs the real model** — default `sandbox: read_only`; gated turns require the
  Track B approval bridge (fail-closed when unavailable). Add cost/rate/time/output caps.
- **Do not inherit local policy.** A resumed CLI must NOT silently inherit host
  `dontAsk`, Claude settings, a Codex stored sandbox, or dangerous config — rebuild the
  isolation/approval envelope explicitly.
- **Don't clobber a live session** — fork by default where proven (claude `--fork-session`;
  Codex fork pending verification); return the new handle.
- **Retention/redaction is prerequisite C2 policy.** C2 must decide what session metadata,
  stream chunks, and audit records it stores or redacts before shipping; the daemon can
  only minimize what it sends.
- **Audit** every list/resume/cancel in C2 with remote actor, root scope, engine, handle,
  policy.

## 8. Phasing
1. **v2 negotiation spike:** dual support v1/v2; v1 unchanged; real
   `hello.accepted.negotiated_version`; `session.*` gated by v2 + capability.
2. **Read-only list spike:** redacted, metadata-only `session.list`; no streaming.
3. **C2 control-plane spike:** C2 handle/authz/audit store (owner-only default +
   opt-in ACL).
4. **Single-engine resume spike:** Claude resume streaming first, fork + read_only,
   per-session mutex, `session.ack`.
5. **Frontend spike:** separate concept/screen. The current C2 frontend model is
   agent-group/session-job; do not conflate those with local CLI sessions.

## 9. Open questions — answered (Codex-recommended)
1. **Versioning:** v2-first with v1/v2 dual support; v1 peers stay on the frozen wire
   and never receive `session.*`. A wrapper is only possible as a v2 envelope, not a
   v1 vendor channel.
2. **Exposure/authz:** daemon allowlist-scoped, fail-closed, redacted metadata only;
   C2 owner-only by default with separate opt-in ACL.
3. **Fork:** Claude fork first (`--fork-session`); Codex is continue-only until a
   noninteractive fork is proven, so C2 should treat it as `mutates_source=true`.
4. **List freshness:** poll-on-demand + cursor pagination; add `session.update`
   push later if the UI needs live lists.
5. **Turn state:** re-resume per turn for MVP, with a per-session mutex + `turn_id`;
   persistent attached processes are later work and don't match noninteractive CLI mechanics.
