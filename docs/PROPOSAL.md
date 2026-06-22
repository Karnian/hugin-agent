# Wire Protocol v1.1 — Review Request (agent → cloud team)

**TL;DR:** the local-daemon side proposes a wire contract for the
`hugind ↔ orchestrator` WSS link. It's a strawman, not a decree — please review
the [Open questions](#what-we-need-you-to-agree-to) before we freeze v1. The
schema is executable and passes its own conformance check.

## Why this needs both sides

The protocol is a **shared contract**: a field only exists if *both* codebases
encode/decode it. Several additions (lease, seq/ack, result.ack, auth) impose
work on **your** side too, not just ours — so they can't be merged locally. This
document is the strawman that opens that agreement.

## What's in the box

| Artifact | What |
|----------|------|
| [`protocol/v1/messages.ts`](../protocol/v1/messages.ts) | **SSOT** — zod schema, 23 messages. `z.toJSONSchema(Message)` or codegen for your side. |
| [`protocol/README.md`](../protocol/README.md) | Spec: handshake, job/lease lifecycle, reliability, approval. |
| [`protocol/v1/selftest.ts`](../protocol/v1/selftest.ts) | `npm run protocol:check` → 23/23 valid + version negotiation. |
| [`CHANGELOG.md`](../CHANGELOG.md) | v1.0 → v1.1 deltas (from your first review). |

## Decisions we baked in (please confirm)

- **Outbound-only**, one JSON object per WSS frame.
- **At-least-once + idempotent** delivery; cumulative `stream.ack`.
- **Lease per attempt**; reconnect/reassign mint a new `attempt_id`.
- **Authenticated handshake**: `auth.challenge` (you) → signed `hello` (us),
  verified against the device key registered at pairing.
- **Acked terminal results** (`job.result` → `job.result.ack`).
- **Approval is allow/deny only** — the server cannot rewrite tool input.

## What we need you to agree to

The 8 [Open questions](../protocol/README.md#still-open-need-cloud-team-agreement-before-freeze)
in the spec. The ones on the critical path for correctness/security:

1. **Lease renewal cadence + reassignment grace** — prevents double execution.
2. **Ack granularity** — cumulative ack assumes your storage is in-order durable.
3. **Auth specifics** — signature alg(s), nonce lifetime/replay, key rotation.
4. **Multiplexing flow-control** — per-job window vs the coarse `capacity` hint.

### Status after v1.3 (both reviews folded in)

Most of the prior gaps are now in the schema (see [CHANGELOG 1.3](../CHANGELOG.md)):
lease fencing + rotation on all attempt messages, `connection_epoch`, removed
`session_id`, relative-duration authority (`*_ms`), result digests +
`resend_result`, remote-only `decided_by`, `policy_violation` rejection (no
silent clamp), and strict/safe-integer/direction-phase hardening.

**Remaining work is carved into a standalone
[auth/pairing security spec](auth-pairing-spec.md):**

- Canonical signing bytes (encoding, domain separation, tenant/server binding).
- Pairing/registration, `agent_id` minting, `key_id`, rotation, revocation,
  lost-device flow.

These gate the **production auth path** — not mock-relay development. After the
spec + v1.3 get one more cloud review, drop `-draft` → `v1.0.0`.

## How we keep the two sides in sync

Pick one and we'll set it up:
- **Shared package** — both import `@contextualai/hugin-agent/protocol`.
- **Codegen** — we publish `protocol.schema.json` (via `z.toJSONSchema`) and you
  generate types from it in CI.

Either way, `protocol_version` is negotiated at handshake (prerelease = exact
match), so once v1 is stable we can roll changes one side at a time.

## Implementation note from the approval spike

We verified the headless `--permission-prompt-tool` channel **connects**, but
found that a daemon inheriting the user's global `~/.claude` settings
(`allow(*)` + `dontAsk`) would **silently disable the approval gate**. The
daemon must isolate the engine's permission config while preserving auth — a
local concern, but it's *why* the contract keeps approval allow/deny-only with a
mandatory local gate. Details:
[`spikes/approval-prompt-tool`](../spikes/approval-prompt-tool/README.md).

## Status & next step

Schema type-checks and self-tests green. **Not frozen.** Once you've reviewed the
Open questions, we'll cut `protocol/v2` … `v1.0.0` (drop the `-draft`) and start
building `hugind` against it.
