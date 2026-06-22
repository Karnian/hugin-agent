# Spike: `--permission-prompt-tool` contract

**Goal:** empirically nail down the *undocumented* request/response shape of
Claude Code's headless permission-prompt mechanism, so we know whether the
protocol's `approval.request` / `approval.response` round-trip is actually
implementable. (`claude-code-guide` flagged this as "flag exists, spec
unpublished" — this spike replaces that uncertainty with observation.)

## Hypotheses

| ID | Hypothesis | How we test it |
|----|-----------|----------------|
| H1 | Headless `claude -p` delegates tool permission to an external MCP tool | Count calls to our mock `permission_prompt` |
| H2 | The delegation call includes `tool_name` + `input` | Capture raw arguments verbatim |
| H3 | Returning `{behavior: allow/deny}` actually gates execution | allow → file created; deny → file absent |
| H4 | The approval round-trip surfaces in `stream-json` output | Tally `type`s in the stream |

## Run

```bash
npm install        # once
npm run spike:approval
```

Requires `claude` installed **and logged in**. It makes real model calls in a
throwaway workspace under `out/` (gitignored). Two scenarios run back-to-back:
`HUGIN_SPIKE_DECISION=allow` then `=deny`.

## What to read afterward

- `out/<scenario>/captured.ndjson` — every `CALL`/`REPLY` our mock saw. **This
  is the real argument shape** (answers H2).
- `out/<scenario>/claude-stream.ndjson` — full stream-json from claude (H4).
- `out/<scenario>/workspace/spike.txt` — present only if the run wrote (H3).
- console verdict — H1/H2/H3 summarized.

## Why it matters for the protocol

If H1–H3 hold, `approval.request/response` maps cleanly onto
`--permission-prompt-tool`: the daemon's mock becomes the real bridge that
forwards the request over WSS and blocks on the remote `approval.response`.

If H1 fails (no delegation in headless mode), the approval gate must be
redesigned — e.g. pre-flight `--allowedTools`/`--disallowedTools` policy only,
with no interactive escalation. **Better to learn this now than mid-MVP.**

> Open follow-up regardless of result: the **local** approval gate (user
> presence for high-risk tools) is a daemon concern, not covered here.

## Observed results — first run (2026-06-23)

Ran in a Claude Desktop environment. Both scenarios: `permission_prompt` called
**0×**, file created even under `deny`. Investigation found the cause:

- The mock MCP server **was `connected`** (from `system/init`). The wiring works.
- But the host's global `~/.claude/settings.json` pre-allows every tool
  (`allow: ["Write(*)", "Bash(*)", ...]`) with `defaultMode: "dontAsk"`. With
  the tool already allow-listed, **no permission prompt ever occurs**, so
  `--permission-prompt-tool` is never invoked — even with `--permission-mode default`.

**What this proves**

1. ✅ The `--permission-prompt-tool` MCP channel connects and is reachable.
2. ⚠️ **Inherited host permission config silently disables the remote approval
   gate.** A daemon that spawns `claude` inheriting the user's `~/.claude`
   settings (allow-list + `dontAsk`) would run write/shell tools with **no
   approval at all**. This is a security finding, not just a test artifact.

**Design consequence for `hugind`**

The daemon MUST run engines with an **isolated, explicit permission config** —
do not inherit the user's settings. Start from an empty allow-list, force
`--permission-mode default` (or `plan`), and route every decision through the
prompt tool. Candidate mechanisms to validate in v2: isolated `CLAUDE_CONFIG_DIR`
(while preserving login), or an explicit `--settings` with `allow: []`.

## Observed results — second run (v2, isolated HOME)

v2 forces the `Bash` tool and isolates `HOME` to a throwaway dir whose
`.claude/settings.json` has `allow: []` + `permissionMode: default`. Result:

- ✅ **Permission isolation worked.** `system/init` reported
  `permissionMode: default` with no inherited allow-list — the host's
  `allow(*)` + `dontAsk` was successfully cut off.
- ✅ **MCP server reachable** (`tools/list` served).
- ❌ **But claude returned `"Not logged in · Please run /login"` (exit 1).**
  Isolating `HOME` also dropped the OAuth credential.

**Conclusion: permission isolation and auth preservation are in tension.** A
bare `HOME` swap buys you one or the other, not both. The prompt-tool channel is
proven reachable, but the actual allow→wrote / deny→blocked round-trip still
needs a host that (a) has no global `allow(*)` and (b) keeps login under the
isolated config. This is itself a `hugind` design input: the daemon must isolate
the engine's *permission* config while preserving its *auth*.

**v3 TODO (clean-host verification)**

- Run on a normally-logged-in host **without** a global `allow(*)` settings, OR
  selectively preserve the credential (copy `~/.claude/.credentials.json`, or
  share the keychain item) into the isolated `HOME`.
- Then assert: allow → `spike.txt == "hello"`, deny → no file, and capture the
  H2 argument shape from `captured.ndjson`.
- Determine whether `--settings` **replaces** vs **merges** the allow-list —
  this decides whether `hugind` can isolate permissions without a `HOME` swap
  at all.
