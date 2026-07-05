# C2 (Python relay) — Session Attach & Resume Integration Brief

**Purpose:** everything a session working on the **Python C2 (cloud orchestrator/relay)**
needs to implement the **session discovery + resume-conversation** feature for Hugin Agent
daemons — self-contained, no prior context needed.

**Status:** **DESIGN DRAFT — NOTHING IS IMPLEMENTED YET on the daemon side.** Every "the
daemon does X" below is a *daemon-side requirement to be built*, not a live guarantee. The
message contracts are **proposals**; the transport/version mechanism (§3) is v2-first, the
ack shape (§6) is turn-scoped `session.ack`, and the error/handle contracts (§5.5, §7)
are **joint decisions** to settle before either side codes. Companion daemon-side spec:
`docs/session-attach-design-spec.md` (v0.3, Codex-reviewed).
**Brief v0.3** — reconciled to v2-first per issue #6 three-way review.

---

## 1. Context (one paragraph)

**Hugin Agent (`hugind`)** is an outbound-only bridge daemon on a user's machine that dials
out to C2 over one authenticated WSS connection (Ed25519 device key; see
`c2-auth-integration-brief.md`). Today it only runs one-shot jobs. This feature adds a new
capability: the daemon will **enumerate the machine's existing local `claude`/`codex` CLI
sessions** and **resume a chosen one with a new message**, streaming the reply back — so the
operator, through C2, can browse and continue the user's past AI CLI conversations. **C2's job
is the server half:** ask the daemon for its session list, render it, let the operator pick one
and send a message, and route the streamed reply. The daemon never dials in.

## 2. Division of responsibility (both sides are NEW work)

| Daemon (hugind) — to build | C2 (you) — this brief |
|---|---|
| Enumerate local claude/codex sessions (read-only) | Request the list; render it |
| Scope exposure to its allowlist + redact paths/titles | Authorize WHICH operator/tenant may see/act |
| Issue **opaque handles** (never raw session ids) | Store handles; pass them back on resume |
| Spawn `claude --resume` / `codex exec resume`, stream events | Drive resume/message/cancel; render the stream |
| Enforce read-only / fork / approval isolation | Surface accept/reject/errors; ack the stream |

## 3. Transport & versioning (JOINT DECISION — read carefully)

The wire protocol is **FROZEN at `v1.0.0`**. Every frame is a flat strict object in a
`discriminatedUnion("type", …)`, and the daemon parses the schema **before** routing — so a
peer that receives an **unknown `type` rejects it as `invalid_message`**. There is **no general
extension channel** in v1.0.0: the only vendor-extensible spot is `stream.event.event.kind`
(a data field), NOT a place to carry new control messages. Also, `capabilities.sessions` would
be rejected because v1 `Capabilities` is a strict object allowing only `engines` and
`project_roots`. Per repo policy a new core message type/field is a **MAJOR bump (v2)**.

**So `session.*` frames CANNOT ride frozen v1.0.0.** The recommended path is **(A)
Protocol v2**: both sides adopt v2 = the `session.*` types (§5) + a
`capabilities.sessions` field + **real version negotiation** (`Hello.protocol_version` →
`HelloAccepted.negotiated_version`; today both are sent as a constant and must be made real).

An explicit wrapper is viable only as a **v2 envelope** that both sides parse after v2
negotiation; it is not a v1 vendor channel. It can narrow the new surface to one outer
frame, but it is still v2 work. Either way the §5 contracts are identical, and
`session.*` is exchanged **only after capability negotiation confirms both sides speak it.**

## 4. Capability discovery

The daemon will advertise support in its `hello.capabilities` (extended schema):
```json
"capabilities": {
  "engines": { "claude": {"installed": true, "version": "2.1.201", "logged_in": true},
               "codex":  {"installed": true, "version": "0.140.0", "logged_in": true} },
  "project_roots": ["/Users/k/Desktop/sub_project"],
  "sessions": { "list": true, "resume": true }        // ← new; absent = unsupported
}
```
C2 must treat a MISSING `sessions` capability as "not supported" and hide the feature for that
agent. (Today the daemon sends a hardcoded capability stub that even reports `codex.installed:
false` and only instantiates a Claude engine — real engine detection + this field are part of
the build.)

## 5. Message contracts

Direction: **s→a** = C2→daemon, **a→s** = daemon→C2. Every request carries a C2-generated
`request_id`; every resume turn is tracked by a daemon-issued `turn_id`.

### 5.1 List sessions (paginated, deterministic)
```jsonc
// s→a
{ "type":"session.list.request", "request_id":"req-…",
  "filter": { "engine":"claude|codex|null", "cwd_prefix":"…?", "active_only":false,
              "updated_after":"iso?" },
  "page":   { "cursor":"…?", "limit":50 } }
// a→s
{ "type":"session.list.response", "request_id":"req-…",
  "sessions": [ SessionInfo, … ], "next_cursor":"…|null", "truncated":false }
```
Pagination is **deterministic**: stable sort = `updated_at` DESC, tie-broken by `handle`; the
`cursor` is an opaque token encoding that watermark. A cursor from a since-changed snapshot
returns `session.error {code:"cursor_invalid"}` → C2 re-lists from the top.

### 5.2 Resume (start a turn)
```jsonc
// s→a
{ "type":"session.resume.request", "request_id":"req-…",
  "handle":"h_…",                     // OPAQUE — from a prior list; NOT a raw id
  "message":"user text",
  "options": { "fork":true, "sandbox":"read_only", "model":null } }
// a→s  (one of)
{ "type":"session.resume.accept", "request_id":"req-…", "turn_id":"t-…", "effective_options":{…} }
{ "type":"session.resume.reject", "request_id":"req-…", "code":"…", "message":"…" }
```
**Fork is engine-specific:** Claude forks by default (`--fork-session`, original untouched).
**Codex has no proven non-interactive fork → Codex is CONTINUE-ONLY**; a Codex resume mutates
the original session in place (`mutates_source=true`, guarded by the per-session mutex,
idle-only). C2 should not offer a "fork" toggle for Codex, and the daemon echoes what it
actually did in `effective_options`.

### 5.3 Streamed reply + result
```jsonc
// a→s  (repeated; C2 MUST ack — §6)
{ "type":"session.event", "turn_id":"t-…", "seq":1, "event": { … normalized … } }
// a→s  (terminal)
{ "type":"session.turn.result", "turn_id":"t-…", "status":"ok|error|cancelled",
  "final_message":"…", "new_session_handle":"h_…|null" }   // set only when a fork created a new session
```

### 5.4 Follow-up / cancel
```jsonc
{ "type":"session.message", "request_id":"req-…", "handle":"h_…", "message":"…" }   // s→a
{ "type":"session.cancel",  "turn_id":"t-…" }                                        // s→a (process-group cancel)
```

### 5.5 Errors (proposed enum — finalize together)
```jsonc
{ "type":"session.error", "request_id":"…?", "turn_id":"…?", "code":"…", "message":"…" }
```
`code` ∈ { `handle_invalid`, `handle_expired`, `session_busy`, `engine_unavailable`,
`fork_unsupported`, `sandbox_unsupported`, `approval_unavailable`, `cursor_invalid`,
`policy_violation`, `timeout`, `engine_crashed`, `cancelled`, `internal` }.

## 6. Streaming, ack/backpressure, lifecycle

- `session.event` streams the reply incrementally and **must be acked** — the daemon applies
  backpressure and pauses when unacked bytes exceed a cap (as the job stream does today, which
  is attempt/lease-scoped with `event_id`). Use turn-scoped
  `session.ack {turn_id, ack_seq}`; do not reuse attempt/lease-scoped `stream.ack`.
  The daemon persists-before-send and resends unacked events after a reconnect.
- Turn lifecycle: `resume.request` → `accept`(turn_id) → `event*` → `turn.result`; a `reject`
  or `session.error` ends it with no `turn.result`.
- **One active turn per session** (per-session mutex). A second resume on a busy handle →
  `session.error {code:"session_busy"}`.

## 7. Opaque handles

- The daemon returns **opaque `handle` tokens**, NOT raw session ids or file paths. C2 stores
  and echoes daemon handles; it never constructs or guesses ids. C2 should re-issue its own
  opaque handle to the frontend instead of exposing daemon handles directly.
- A handle binds `{engine, session_id, cwd, path, mtime, tenant/agent}` daemon-side, must be
  **unforgeable (high-entropy)**, is **re-validated on use** (still in the allowlist, unchanged
  ownership), and may **expire/rotate/revoke**. A stale/expired/revoked handle →
  `session.error {code:"handle_invalid"|"handle_expired"}` → C2 re-lists.
- `fork` turns return a `new_session_handle`; C2 switches follow-ups to it.
- C2 must treat handles as bearer capabilities: bind them to the authorized tenant/operator,
  do not replay across tenants, and keep them out of shared logs.

## 8. Turn lifecycle edge cases (define behavior)
- **Daemon restart / reconnect mid-turn:** in-flight `turn_id` is lost; C2 sees the connection
  drop → should surface "interrupted" and re-list (handles may have changed).
- **Duplicate `request_id`:** daemon should be idempotent (return the same turn, not double-run).
- **Concurrent resume on one session:** second → `session_busy`.
- **Engine crash mid-turn:** `turn.result {status:"error"}` or `session.error{engine_crashed}`.
- **Cancel:** `session.cancel` → process-group kill → terminal `turn.result{status:"cancelled"}`.

## 9. SessionInfo (what C2 renders)
```jsonc
{ "handle":"h_…", "engine":"claude|codex",
  "cwd":"…",              // redacted / relative-to-root by default (§10)
  "git_branch":"…|null",  // claude only
  "cli_version":"…|null",
  "title":"…",            // short; may be empty (claude ai-title is rare; codex skips its preamble)
  "created_at":"iso", "updated_at":"iso",
  "active":true,          // recently written / live process
  "msg_count": 42 }
```
This payload is metadata-only: no prompt text, output text, or transcript bodies.

## 10. Security — daemon-side REQUIREMENTS (to build) + C2 responsibilities

**Daemon-side requirements (NOT yet implemented — do not rely on them until shipped):**
exposure scoped to `projectRoots` and **fail-closed** (no allowlist → empty list); `cwd`/`title`
redacted/minimized by default; nested claude subagent logs excluded; file ownership + symlink/
realpath + TOCTOU-safe reads; resume defaults `sandbox:read_only`; gated turns require the
approval bridge (rejected if unavailable); resumed CLIs must NOT inherit host `dontAsk`/Claude
settings/Codex stored sandbox; cost/time/output caps.

**C2 responsibilities:**
- **Authorize the actor.** The daemon has only agent/tenant identifiers, not C2 operators or
  `user_id` — C2 enforces WHO may list/resume which agent, and must not leak one tenant's
  handles/sessions to another. Default to owner-only, with shared/operator ACL as a separate
  opt-in.
- **Treat handles as capabilities** (bind to tenant, no cross-tenant replay, keep out of logs).
- **Audit** every list/resume/cancel (actor, agent, handle, engine, policy).
- **Never present the list as "all of the user's sessions"** — it is an allowlist-scoped,
  redacted view.
- **Sensitive content:** titles, first prompts, and streamed output can contain secrets — apply
  the same handling/redaction to your storage and logs.

## 11. MVP scope
1. **v2 negotiation spike:** dual support v1/v2; v1 unchanged; real
   `hello.accepted.negotiated_version`; `session.*` gated by v2 + capability.
2. **Read-only list spike:** redacted, metadata-only `session.list`; no streaming.
3. **C2 control-plane spike:** C2 handle/authz/audit store (owner-only default +
   opt-in ACL).
4. **Single-engine resume spike:** Claude resume streaming first, fork + read_only,
   per-session mutex, `session.ack`.
5. **Frontend spike:** separate concept/screen. Today's C2 frontend model is
   agent-group/session-job; do not conflate those with local CLI sessions.

## 12. Open questions for the C2 team
1. **Transport details:** direct v2 `session.*` schema, or a single v2 envelope wrapper?
2. **Ack storage:** exact resend/durability behavior for `session.ack {turn_id, ack_seq}`?
3. **Tenant/actor model:** how does C2 scope which operator sees which agent, and how are handles
   bound to a tenant?
4. **Redaction policy:** relative-to-root `cwd` + trimmed `title` enough, or stricter (hashed
   cwd, no title) by default?
5. **List freshness:** poll-on-demand (MVP) acceptable, or pushed `session.update` from day one?
6. **Codex UX:** continue-only (in-place, `mutates_source=true`) acceptable for Codex until
   fork is proven?
