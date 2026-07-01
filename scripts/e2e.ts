/**
 * hugind P1 end-to-end check.
 *
 *   npm run e2e
 *
 * Scenario A (live, over a real WSS socket to the mock relay): the daemon
 * connects, completes the non-auth handshake, heartbeats, and — when the relay
 * drops the connection — reconnects with a strictly-higher connection_epoch.
 *
 * Scenario B (deterministic, direct): the framing choke point rejects oversized
 * frames, wrong-direction messages, and pre-auth non-handshake messages; the
 * daemon's epoch gate is strictly monotonic.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import type { WebSocket } from "ws";
import { LIMITS, parseMessage } from "../protocol/v1/index";
import { loadConfig } from "../src/config";
import { Daemon } from "../src/daemon";
import { devSigner } from "../src/conn/handshake";
import { decodeInbound } from "../src/conn/framing";
import { RelayClient } from "../src/conn/client";
import { FakeEngine } from "../src/engine/fake-engine";
import type { Engine } from "../src/engine/types";
import { JobManager } from "../src/jobs/manager";
import { JobRegistry } from "../src/jobs/registry";
import { EventLog } from "../src/store/eventlog";
import { validateWorkspace } from "../src/workspace/worktree";
import { MockRelay } from "../mock-relay/server";

const SCRATCH = "/private/tmp/claude-501/-Users-k-Desktop-sub-project-hugin-agent/500bdae6-f9cf-45b3-9e5b-a2819e8bcd4b/scratchpad/e2e-worktree";

let failures = 0;
function check(label: string, cond: boolean): void {
  console.log(`${cond ? "✓" : "✗"} ${label}`);
  if (!cond) failures++;
}
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
async function waitUntil(pred: () => boolean, timeoutMs: number, stepMs = 50): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pred()) return true;
    await sleep(stepMs);
  }
  return pred();
}

async function scenarioA(): Promise<void> {
  let accepts = 0;
  let heartbeats = 0;
  const epochs: number[] = [];
  const relay = new MockRelay({
    heartbeatIntervalMs: 100, // short so the e2e observes heartbeats quickly
    onHeartbeat: () => heartbeats++,
    onAccept: (ctx) => {
      accepts++;
      epochs.push(ctx.epoch);
      if (accepts === 1) setTimeout(() => ctx.ws.close(), 150); // force one reconnect
    },
  });
  const port = await relay.start();
  const config = loadConfig({
    serverUrl: `ws://127.0.0.1:${port}`,
    agentId: "agent-e2e",
    tenantId: "dev-tenant",
    dbPath: ":memory:",
  });
  const daemon = new Daemon(config, devSigner(), new FakeEngine({ events: [] }));
  void daemon.start().catch((e) => console.error("daemon.start threw", e));

  const reconnected = await waitUntil(() => accepts >= 2, 8000);
  const beat = await waitUntil(() => heartbeats >= 1, 2000);
  daemon.stop();
  await relay.stop();
  await sleep(50);

  check("A1 daemon connects + completes handshake", accepts >= 1);
  check("A2 daemon reconnects after relay drop", reconnected && accepts >= 2);
  check(
    "A3 connection_epoch strictly increases across reconnect",
    epochs.length >= 2 && (epochs[1] ?? 0) > (epochs[0] ?? 0),
  );
  check("A4 daemon sends heartbeats (negotiated interval)", beat && heartbeats >= 1);
}

function scenarioB(): void {
  const opts = { receiver: "agent" as const, authed: true };

  // oversized frame → payload_too_large (size checked before parse)
  const oversized = "x".repeat(LIMITS.MAX_FRAME_BYTES + 1);
  const over = decodeInbound(oversized, opts);
  check("B1 framing rejects oversized frame", !over.ok && over.code === "payload_too_large");

  // a2s message received by an agent → bad_direction (agent.draining is a2s)
  const draining = JSON.stringify({
    id: "m", ts: "2026-06-25T00:00:00.000Z", type: "agent.draining", reason: "shutdown",
  });
  const dir = decodeInbound(draining, opts);
  check("B2 framing rejects a2s msg at agent (bad_direction)", !dir.ok && dir.code === "bad_direction");

  // s2a non-handshake message pre-auth → bad_state
  const ack = JSON.stringify({
    id: "m", ts: "2026-06-25T00:00:00.000Z", type: "stream.ack",
    job_id: "j", attempt_id: "a", lease_id: "l", ack_seq: 1,
  });
  const state = decodeInbound(ack, { receiver: "agent", authed: false });
  check("B3 framing rejects s2a non-handshake pre-auth (bad_state)", !state.ok && state.code === "bad_state");

  // garbage → invalid_message
  const bad = decodeInbound("{not json", opts);
  check("B4 framing rejects invalid JSON", !bad.ok && bad.code === "invalid_message");

  // epoch gate: strictly monotonic
  const d = new Daemon(
    loadConfig({ serverUrl: "wss://relay.example.com", agentId: "a", dbPath: ":memory:" }),
    devSigner(),
    new FakeEngine({ events: [] }),
  );
  check("B5 epoch gate accepts first epoch", d.acceptEpoch(5));
  check("B6 epoch gate rejects equal/older", !d.acceptEpoch(5) && !d.acceptEpoch(4));
  check("B7 epoch gate accepts higher", d.acceptEpoch(6));
}

/** Live test of the non-monotonic-epoch rejection: the relay forces a constant
 *  epoch, so the reconnect's `hello.accepted` repeats it and the daemon must close
 *  with 1008 (plan §5.1 / daemon.acceptEpoch). */
async function scenarioC(): Promise<void> {
  let accepts = 0;
  const closeCodes: number[] = [];
  const relay = new MockRelay({
    forceEpoch: 7,
    onAccept: (ctx) => {
      accepts++;
      ctx.ws.on("close", (code) => closeCodes.push(code));
      if (accepts === 1) setTimeout(() => ctx.ws.close(), 100); // drop conn1 → reconnect with same epoch
    },
  });
  const port = await relay.start();
  const daemon = new Daemon(
    loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-epoch", dbPath: ":memory:" }),
    devSigner(),
    new FakeEngine({ events: [] }),
  );
  void daemon.start().catch(() => {});
  const rejected = await waitUntil(() => closeCodes.includes(1008), 6000);
  daemon.stop();
  await relay.stop();
  await sleep(50);
  check("C1 daemon rejects non-monotonic connection_epoch (closes 1008)", rejected);
}

/** Deterministic test of the inbound-queue race fix: let `auth.challenge` land in
 *  the buffer BEFORE `waitFor` registers, then confirm `waitFor` finds it. */
async function scenarioQueueRace(): Promise<void> {
  const relay = new MockRelay();
  const port = await relay.start();
  const client = new RelayClient();
  await client.connect(`ws://127.0.0.1:${port}`);
  await sleep(200); // challenge is now buffered (no waiter was registered yet)
  let ok = false;
  try {
    const m = await client.waitFor((x) => x.type === "auth.challenge", 1000);
    ok = m.type === "auth.challenge";
  } catch {
    ok = false;
  }
  client.close();
  await relay.stop();
  check("Q1 inbound queue delivers a challenge buffered before waitFor", ok);
}

/** Full job flow: assign → accept → stream (persist + auto-ack + GC) → result →
 *  digest-ack → GC. D3 passing proves the daemon and relay compute the SAME
 *  result_digest (otherwise ackResult never matches and pending never clears). */
async function scenarioD(): Promise<void> {
  const streamKinds: string[] = [];
  let jobAccepts = 0;
  let resultSeen = false;
  const relay = new MockRelay({
    onJobAccept: () => {
      jobAccepts++;
    },
    onStreamEvent: (m) => {
      streamKinds.push(m.event.kind);
    },
    onResult: () => {
      resultSeen = true;
    },
    onAccept: (ctx) => relay.assign(ctx.ws, { job_id: "j1", attempt_id: "a1", lease_id: "L1", prompt: "hi" }),
  });
  const port = await relay.start();
  const engine = new FakeEngine({
    events: [
      { kind: "assistant_text", text: "hi" },
      { kind: "tool_use", name: "Bash" },
      { kind: "usage", tokens: 10 },
    ],
    outcome: { status: "success", exitCode: 0 },
  });
  const daemon = new Daemon(
    loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-d", dbPath: ":memory:" }),
    devSigner(),
    engine,
  );
  void daemon.start().catch(() => {});
  const gcd = await waitUntil(
    () =>
      resultSeen &&
      streamKinds.length === 3 &&
      daemon.pendingResultCount() === 0 &&
      daemon.activeAttemptCount() === 0,
    6000,
  );
  check("D1 job.accept received", jobAccepts >= 1);
  check("D2 all 3 stream events received (persisted + acked)", streamKinds.length === 3);
  check("D3 result digest-acked → GC (pending=0, attempts=0)", gcd && resultSeen);
  daemon.stop();
  await relay.stop();
  await sleep(50);
}

/** Idempotency: an identical `job.assign` sent twice re-confirms but must NOT
 *  spawn a second run (2 events from the 2-event script, not 4). */
async function scenarioE(): Promise<void> {
  const streamKinds: string[] = [];
  let jobAccepts = 0;
  const relay = new MockRelay({
    onJobAccept: () => {
      jobAccepts++;
    },
    onStreamEvent: (m) => {
      streamKinds.push(m.event.kind);
    },
    onAccept: (ctx) => {
      relay.assign(ctx.ws, { job_id: "j1", attempt_id: "dup", lease_id: "L1" });
      relay.assign(ctx.ws, { job_id: "j1", attempt_id: "dup", lease_id: "L1" });
    },
  });
  const port = await relay.start();
  const engine = new FakeEngine({ events: [{ kind: "assistant_text" }, { kind: "usage" }], outcome: { status: "success" } });
  const daemon = new Daemon(
    loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-e", dbPath: ":memory:" }),
    devSigner(),
    engine,
  );
  void daemon.start().catch(() => {});
  await waitUntil(() => jobAccepts >= 2, 4000);
  await sleep(300); // give any erroneous 2nd run time to emit
  check("E1 duplicate assign re-confirmed (>=2 job.accept)", jobAccepts >= 2);
  check("E2 duplicate did NOT spawn a 2nd run (2 events, not 4)", streamKinds.length === 2);
  check("E3 engine.run() called exactly once (direct idempotency proof)", engine.runCount === 1);
  daemon.stop();
  await relay.stop();
  await sleep(50);
}

function fakeAssign(job_id: string, attempt_id: string, lease_id: string) {
  const now = "2026-07-01T00:00:00.000Z";
  return {
    id: "m",
    ts: now,
    type: "job.assign",
    job_id,
    attempt_id,
    lease_id,
    lease_ttl_ms: 120_000,
    engine: "claude",
    workspace: { repo_root: "/tmp/repo" },
    prompt: "hi",
    sandbox: "read_only",
    approval_policy: "on_write",
    env_policy: { mode: "whitelist", allow: [] },
    network_policy: { mode: "off" },
    limits: { timeout_ms: 600_000, max_output_bytes: 5_000_000 },
    created_at: now,
    assignment_start_timeout_ms: 30_000,
  };
}

/** Cross-session idempotency (the P1 Codex flagged): the durable store already
 *  holds attempt "x" (accepted on a prior connection) but the registry is fresh
 *  after reconnect. A re-assign must re-confirm WITHOUT calling engine.run(); a
 *  re-assign with a different lease must be fenced (stale_lease). */
function scenarioG(): void {
  const store = new EventLog(":memory:");
  store.createAttempt({
    attempt_id: "x",
    job_id: "j",
    lease_id: "L1",
    agent_run_id: "run-old",
    status: "running",
    created_at: "2026-07-01T00:00:00.000Z",
  });
  const registry = new JobRegistry(2);
  const engine = new FakeEngine({ events: [{ kind: "assistant_text" }] });
  const sent: string[] = [];
  const manager = new JobManager(registry, store, engine, (m) => sent.push(m.type), {
    events: 1024,
    bytes: 8 << 20,
    conn: 32 << 20,
  });
  const a1 = parseMessage(fakeAssign("j", "x", "L1"));
  if (a1.type === "job.assign") manager.handleAssign(a1);
  check("G1 cross-session duplicate does NOT re-spawn the engine", engine.runCount === 0);
  check("G2 cross-session duplicate re-confirms (job.accept)", sent.includes("job.accept"));
  const a2 = parseMessage(fakeAssign("j", "x", "L2"));
  if (a2.type === "job.assign") manager.handleAssign(a2);
  check("G3 duplicate with mismatched lease is fenced (job.reject)", sent.includes("job.reject"));
  store.close();
}

/** Lease revoke fences the run: a hanging job is revoked mid-flight; the daemon
 *  must emit NO terminal result on the revoked lease and free the attempt. */
async function scenarioH(): Promise<void> {
  let resultSeen = false;
  let ctxRef: { job_id: string; attempt_id: string; lease_id: string } | null = null;
  let wsRef: WebSocket | null = null;
  const relay = new MockRelay({
    onResult: () => {
      resultSeen = true;
    },
    onStreamEvent: (m) => {
      ctxRef = { job_id: m.job_id, attempt_id: m.attempt_id, lease_id: m.lease_id };
    },
    onAccept: (ctx) => {
      wsRef = ctx.ws;
      relay.assign(ctx.ws, { job_id: "j1", attempt_id: "rev", lease_id: "L1" });
    },
  });
  const port = await relay.start();
  const engine = new FakeEngine({ events: [{ kind: "assistant_text" }], hang: true }); // never completes on its own
  const daemon = new Daemon(
    loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-h", dbPath: ":memory:" }),
    devSigner(),
    engine,
  );
  void daemon.start().catch(() => {});
  await waitUntil(() => ctxRef !== null, 4000); // running; first event observed
  if (wsRef && ctxRef) relay.revoke(wsRef, ctxRef);
  await sleep(300); // fence must stop it — no result should arrive
  check("H1 lease.revoke fences the run — no terminal result on revoked lease", resultSeen === false);
  check("H2 revoked attempt dropped (durable + capacity freed)", daemon.activeAttemptCount() === 0);
  daemon.stop();
  await relay.stop();
  await sleep(50);
}

/** EventLog unit: cumulative-ack GC and digest-matched result GC directly. */
function scenarioI(): void {
  const store = new EventLog(":memory:");
  store.createAttempt({ attempt_id: "u", job_id: "j", lease_id: "L1", agent_run_id: "r", status: "running", created_at: "2026-07-01T00:00:00.000Z" });
  store.appendEvent("u", 1, "u-1", 100, "{}");
  store.appendEvent("u", 2, "u-2", 100, "{}");
  store.appendEvent("u", 3, "u-3", 100, "{}");
  check("I1 unacked counters", store.unackedEvents("u") === 3 && store.unackedBytes("u") === 300 && store.connUnackedBytes() === 300);
  store.ackEvents("u", 2);
  check("I2 cumulative-ack GC deletes seq<=ack", store.unackedEvents("u") === 1 && store.unackedBytes("u") === 100);
  store.saveResult({ attempt_id: "u", job_id: "j", lease_id: "L1", final_status: "success", result_digest: "DIGEST", result_size: 10, payload: "{}", last_emitted_seq: 3 });
  check("I3 ackResult rejects wrong digest (result kept)", store.ackResult("u", "WRONG") === false && store.getResult("u") !== undefined);
  check("I4 ackResult accepts matching digest (result GC'd)", store.ackResult("u", "DIGEST") === true && store.getResult("u") === undefined);
  store.close();
}

/** Per-connection byte cap engages backpressure (the cap D/E/F never exercised). */
async function scenarioJ(): Promise<void> {
  const seqs: number[] = [];
  const relay = new MockRelay({
    autoAckStream: false,
    onStreamEvent: (m) => {
      seqs.push(m.seq);
    },
    onAccept: (ctx) => relay.assign(ctx.ws, { job_id: "j1", attempt_id: "cc", lease_id: "L1" }),
  });
  const port = await relay.start();
  const big = "x".repeat(2000);
  const engine = new FakeEngine({
    events: Array.from({ length: 10 }, () => ({ kind: "stdout_chunk", data: big })),
    outcome: { status: "success" },
  });
  const daemon = new Daemon(
    loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-j", dbPath: ":memory:", maxUnackedBytesPerConn: 3000 }),
    devSigner(),
    engine,
  );
  void daemon.start().catch(() => {});
  await waitUntil(() => seqs.length >= 1, 3000);
  await sleep(200);
  check("J1 per-connection byte cap engages backpressure (pauses early)", seqs.length >= 1 && seqs.length <= 3);
  daemon.stop();
  await relay.stop();
  await sleep(50);
}

/** Backpressure: with acks withheld and a per-attempt cap of 3, the daemon must
 *  pause after 3 unacked events and resume once an ack clears them. */
async function scenarioF(): Promise<void> {
  const seqs: number[] = [];
  let ackCtx: { job_id: string; attempt_id: string; lease_id: string } | null = null;
  let ackWs: WebSocket | null = null;
  const cap = 3;
  const relay = new MockRelay({
    autoAckStream: false,
    onStreamEvent: (m) => {
      seqs.push(m.seq);
      ackCtx = { job_id: m.job_id, attempt_id: m.attempt_id, lease_id: m.lease_id };
    },
    onAccept: (ctx) => {
      ackWs = ctx.ws;
      relay.assign(ctx.ws, { job_id: "j1", attempt_id: "bp", lease_id: "L1" });
    },
  });
  const port = await relay.start();
  const engine = new FakeEngine({
    events: Array.from({ length: 10 }, (_, i) => ({ kind: "stdout_chunk", n: i })),
    outcome: { status: "success" },
  });
  const daemon = new Daemon(
    loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-f", dbPath: ":memory:", maxUnackedEventsPerAttempt: cap }),
    devSigner(),
    engine,
  );
  void daemon.start().catch(() => {});
  await waitUntil(() => seqs.length >= cap, 3000);
  await sleep(200); // if not paused, more events would arrive here
  const pausedAt = seqs.length;
  check("F1 backpressure pauses at cap (unacked never exceeds cap)", pausedAt === cap);
  if (ackWs && ackCtx) relay.sendAck(ackWs, ackCtx, cap);
  const resumed = await waitUntil(() => seqs.length > pausedAt, 3000);
  check("F2 backpressure resumes after ack", resumed);
  daemon.stop();
  await relay.stop();
  await sleep(50);
}

function fakeRevoke(job_id: string, attempt_id: string, lease_id: string) {
  return { id: "m", ts: "2026-07-01T00:00:00.000Z", type: "lease.revoke", job_id, attempt_id, lease_id, reason: "revoked" };
}

/** Stale-callback race (async cancel, P2b/P3): revoke fences attempt "z" and
 *  clears its state; a re-assign with a NEW lease creates a fresh run under the
 *  same id BEFORE the old run's (deferred) onDone fires. The stale fenced onDone
 *  must NOT evict the replacement — identity-gated cleanup in onDone. */
async function scenarioL(): Promise<void> {
  const store = new EventLog(":memory:");
  const registry = new JobRegistry(4);
  const engine = new FakeEngine({ events: [{ kind: "assistant_text" }], hang: true, cancelAsync: true });
  const manager = new JobManager(registry, store, engine, () => {}, { events: 1024, bytes: 8 << 20, conn: 32 << 20 });

  const a1 = parseMessage(fakeAssign("j", "z", "L1"));
  if (a1.type === "job.assign") manager.handleAssign(a1);
  const oldState = registry.get("z");

  const rev = parseMessage(fakeRevoke("j", "z", "L1"));
  if (rev.type === "lease.revoke") manager.handleRevoke(rev); // fences; cancel() deferred

  const a2 = parseMessage(fakeAssign("j", "z", "L2"));
  if (a2.type === "job.assign") manager.handleAssign(a2); // fresh run, same id, new lease
  const newState = registry.get("z");
  check(
    "L1 re-assign after revoke creates a fresh live attempt",
    newState !== undefined && newState !== oldState && newState?.lease_id === "L2",
  );

  await sleep(30); // old fenced run's deferred onDone fires here
  check("L2 stale fenced onDone does not evict the re-assigned live attempt", registry.get("z") === newState);
  store.close();
}

/** job.result.ack MUST be lease-checked even after terminal cleanup removes the
 *  registry entry (the pending result's lease lives on the durable AttemptRow).
 *  A mismatched-lease ack must NOT GC the pending result; the correct lease must. */
function scenarioK(): void {
  const DIGEST = "A".repeat(43); // valid SHA-256 base64url length
  const store = new EventLog(":memory:");
  store.createAttempt({ attempt_id: "r", job_id: "j", lease_id: "L1", agent_run_id: "run", status: "completed", created_at: "2026-07-01T00:00:00.000Z" });
  store.saveResult({ attempt_id: "r", job_id: "j", lease_id: "L1", final_status: "success", result_digest: DIGEST, result_size: 1, payload: "{}", last_emitted_seq: 0 });
  const manager = new JobManager(new JobRegistry(2), store, new FakeEngine({ events: [] }), () => {}, {
    events: 1024,
    bytes: 8 << 20,
    conn: 32 << 20,
  });
  const wrong = parseMessage({ id: "m", ts: "2026-07-01T00:00:00.000Z", type: "job.result.ack", job_id: "j", attempt_id: "r", lease_id: "WRONG", result_digest: DIGEST });
  if (wrong.type === "job.result.ack") manager.handleResultAck(wrong);
  check("K1 result.ack with mismatched lease rejected (pending result kept)", store.getResult("r") !== undefined);
  const right = parseMessage({ id: "m", ts: "2026-07-01T00:00:00.000Z", type: "job.result.ack", job_id: "j", attempt_id: "r", lease_id: "L1", result_digest: DIGEST });
  if (right.type === "job.result.ack") manager.handleResultAck(right);
  check("K2 result.ack with correct lease GCs the pending result", store.getResult("r") === undefined);
  store.close();
}

function tryCode(fn: () => void): string | null {
  try {
    fn();
    return null;
  } catch (e) {
    return (e as { code?: string }).code ?? "throw";
  }
}

/** Worktree validation (P2b): path-injection-safe attempt segment + allowlist +
 *  git + cwd guards. Uses a throwaway git repo (no real claude needed). */
function scenarioM(): void {
  const base = join(SCRATCH, "wt");
  const repo = join(base, "repo");
  const notGit = join(base, "notgit");
  rmSync(base, { recursive: true, force: true });
  mkdirSync(repo, { recursive: true });
  mkdirSync(notGit, { recursive: true });
  const git = (...a: string[]) => execFileSync("git", ["-C", repo, ...a], { stdio: "pipe" });
  git("init", "-q");
  git("config", "user.email", "e2e@test.local");
  git("config", "user.name", "e2e");
  writeFileSync(join(repo, "f.txt"), "x\n");
  git("add", "-A");
  git("commit", "-qm", "init");

  const wtBase = resolve(base, "worktrees");
  const ok = validateWorkspace({ repoRoot: repo, allowlist: [repo], stateDir: base, attemptId: "a1" });
  check("M1 valid allowlisted git repo validates", ok.root === realpathSync(repo) && ok.wtDir === join(wtBase, "a1"));
  const inj = validateWorkspace({ repoRoot: repo, allowlist: [repo], stateDir: base, attemptId: "../../evil" });
  check(
    "M2 path-injection attempt_id stays contained under worktrees/",
    (inj.wtDir + sep).startsWith(wtBase + sep) && !inj.wtDir.includes(".."),
  );
  check("M3 non-allowlisted repo → root_not_allowlisted", tryCode(() => validateWorkspace({ repoRoot: repo, allowlist: [], stateDir: base, attemptId: "a1" })) === "root_not_allowlisted");
  check("M4 non-git repo → not_a_git_repo", tryCode(() => validateWorkspace({ repoRoot: notGit, allowlist: [notGit], stateDir: base, attemptId: "a1" })) === "not_a_git_repo");
  check("M5 cwd escaping repo_root → cwd_escape", tryCode(() => validateWorkspace({ repoRoot: repo, allowlist: [repo], stateDir: base, attemptId: "a1", cwd: "../notgit" })) === "cwd_escape");
  rmSync(base, { recursive: true, force: true });
}

/** A workspace-invalid job must be rejected (job.reject) BEFORE accept/spawn,
 *  via engine.validate — not surface as an error result mid-run. */
function scenarioN(): void {
  const store = new EventLog(":memory:");
  const registry = new JobRegistry(2);
  const sent: string[] = [];
  const rejectEngine: Engine = {
    run: () => {
      throw new Error("engine.run must not be called for a rejected workspace");
    },
    validate: () => ({ code: "root_not_allowlisted", message: "repo_root not on the allowlist" }),
  };
  const manager = new JobManager(registry, store, rejectEngine, (m) => sent.push(m.type), { events: 1024, bytes: 8 << 20, conn: 32 << 20 });
  const a = parseMessage(fakeAssign("j", "x", "L1"));
  if (a.type === "job.assign") manager.handleAssign(a);
  check("N1 workspace-invalid job → job.reject (not job.accept)", sent.includes("job.reject") && !sent.includes("job.accept"));
  check("N2 rejected job created no durable attempt", store.activeAttempts().length === 0);
  store.close();
}

/** Approval round-trip (P3): fake engine requests approval after its events; the
 *  relay auto-responds allow/deny; the daemon routes the decision back. */
async function approvalRun(decision: "allow" | "deny"): Promise<{ approvalReq: boolean; events: Array<Record<string, unknown>>; resultSeen: boolean }> {
  const events: Array<Record<string, unknown>> = [];
  let approvalReq = false;
  let resultSeen = false;
  const relay = new MockRelay({
    approvalDecision: decision,
    onApprovalRequest: () => {
      approvalReq = true;
    },
    onStreamEvent: (m) => events.push(m.event as Record<string, unknown>),
    onResult: () => {
      resultSeen = true;
    },
    onAccept: (ctx) => relay.assign(ctx.ws, { job_id: "j1", attempt_id: `appr-${decision}`, lease_id: "L1" }),
  });
  const port = await relay.start();
  const engine = new FakeEngine({
    events: [{ kind: "assistant_text", text: "plan" }],
    approval: { toolName: "Bash", input: "cmd", risk: "high", onAllow: [{ kind: "tool_result", allowed: true }], onDeny: [{ kind: "tool_result", denied: true }] },
    outcome: { status: "success" },
  });
  const daemon = new Daemon(loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: `agent-${decision}`, dbPath: ":memory:" }), devSigner(), engine);
  void daemon.start().catch(() => {});
  await waitUntil(() => resultSeen, 5000);
  daemon.stop();
  await relay.stop();
  await sleep(50);
  return { approvalReq, events, resultSeen };
}

async function scenarioP(): Promise<void> {
  const r = await approvalRun("allow");
  check("P1 approval.request forwarded to relay", r.approvalReq);
  check("P2 allow → onAllow tool_result emitted", r.events.some((e) => e.kind === "tool_result" && e.allowed === true));
  check("P3 job completed after approval", r.resultSeen);
}

async function scenarioR(): Promise<void> {
  const r = await approvalRun("deny");
  check("R1 approval.request forwarded", r.approvalReq);
  check("R2 deny → onDeny tool_result (blocked)", r.events.some((e) => e.kind === "tool_result" && e.denied === true));
  check("R3 no allow path taken on deny", !r.events.some((e) => e.allowed === true));
}

/** Approval timeout → auto-deny: the relay withholds its response; the daemon
 *  must auto-deny after approvalTimeoutMs and take the onDeny path. */
async function scenarioS(): Promise<void> {
  const events: Array<Record<string, unknown>> = [];
  let resultSeen = false;
  const relay = new MockRelay({
    autoApprove: false,
    onStreamEvent: (m) => events.push(m.event as Record<string, unknown>),
    onResult: () => {
      resultSeen = true;
    },
    onAccept: (ctx) => relay.assign(ctx.ws, { job_id: "j1", attempt_id: "appr-to", lease_id: "L1" }),
  });
  const port = await relay.start();
  const engine = new FakeEngine({
    events: [{ kind: "assistant_text" }],
    approval: { toolName: "Bash", input: "cmd", onAllow: [{ kind: "tool_result", allowed: true }], onDeny: [{ kind: "tool_result", denied: true }] },
    outcome: { status: "success" },
  });
  const daemon = new Daemon(
    loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-to", dbPath: ":memory:", approvalTimeoutMs: 200 }),
    devSigner(),
    engine,
  );
  void daemon.start().catch(() => {});
  const done = await waitUntil(() => resultSeen, 5000);
  daemon.stop();
  await relay.stop();
  await sleep(50);
  check("S1 approval timeout auto-denies (onDeny path, no relay response)", done && events.some((e) => e.denied === true));
  check("S2 no allow path on timeout", !events.some((e) => e.allowed === true));
}

/** Fail-closed: with the approval gate unavailable, a write/exec job is rejected
 *  (policy_violation); a read-only job is still accepted. */
async function scenarioT(): Promise<void> {
  const rejects: Array<{ attempt: string; code: string }> = [];
  const accepts: string[] = [];
  const relay = new MockRelay({
    onJobAccept: (m) => accepts.push(m.attempt_id),
    onJobReject: (m) => rejects.push({ attempt: m.attempt_id, code: m.code }),
    onAccept: (ctx) => {
      // gated by sandbox (write), by approval_policy (always), and truly-ungated
      relay.assign(ctx.ws, { job_id: "j1", attempt_id: "wr", lease_id: "L1", sandbox: "workspace_write", approval_policy: "never" });
      relay.assign(ctx.ws, { job_id: "j2", attempt_id: "ap", lease_id: "L1", sandbox: "read_only", approval_policy: "always" });
      relay.assign(ctx.ws, { job_id: "j3", attempt_id: "ok", lease_id: "L1", sandbox: "read_only", approval_policy: "never" });
    },
  });
  const port = await relay.start();
  const engine = new FakeEngine({ events: [{ kind: "assistant_text" }] });
  const daemon = new Daemon(
    loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-t", dbPath: ":memory:" }),
    devSigner(),
    engine,
    false, // gateAvailable = false
  );
  void daemon.start().catch(() => {});
  await waitUntil(() => rejects.length >= 2 && accepts.length >= 1, 5000);
  daemon.stop();
  await relay.stop();
  await sleep(50);
  check("T1 write/exec job rejected when gate unavailable (policy_violation)", rejects.some((r) => r.attempt === "wr" && r.code === "policy_violation"));
  check("T2 read_only+approval_policy!=never also rejected (gate needed)", rejects.some((r) => r.attempt === "ap" && r.code === "policy_violation"));
  check("T3 only read_only+never runs ungated (accepted)", accepts.includes("ok") && !accepts.includes("wr") && !accepts.includes("ap"));
}

/** Resume (P4): a non-terminal attempt's DURABLE events are resent on reconnect
 *  via resume_from — engine-independent (survives the connection drop). */
async function scenarioU(): Promise<void> {
  let conn = 0;
  const conn1: number[] = [];
  const conn2: number[] = [];
  const relay = new MockRelay({
    autoAckStream: false, // events stay durable (unacked)
    resumeFor: (hello) =>
      hello.active_jobs.map((j) => ({ job_id: j.job_id, attempt_id: j.attempt_id, action: "resume_from" as const, resume_after_seq: 0, lease_id: j.lease_id })),
    onStreamEvent: (m) => (conn === 1 ? conn1 : conn2).push(m.seq),
    onAccept: (ctx) => {
      conn++;
      if (conn === 1) {
        relay.assign(ctx.ws, { job_id: "j1", attempt_id: "res", lease_id: "L1" });
        setTimeout(() => ctx.ws.close(), 300);
      }
    },
  });
  const port = await relay.start();
  const engine = new FakeEngine({ events: [{ kind: "stdout_chunk" }, { kind: "stdout_chunk" }, { kind: "stdout_chunk" }], hang: true });
  const daemon = new Daemon(loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-u", dbPath: ":memory:" }), devSigner(), engine);
  void daemon.start().catch(() => {});
  const resumed = await waitUntil(() => conn2.length >= 3, 8000);
  daemon.stop();
  await relay.stop();
  await sleep(50);
  check("U1 conn1 streamed 3 durable (unacked) events", conn1.length === 3);
  check("U2 reconnect resume_from resent them from the durable store", resumed && conn2.length >= 3);
}

/** Resume (P4): a completed-but-unacked result is reported in hello.pending_results
 *  on reconnect and resent via resend_result. */
async function scenarioV(): Promise<void> {
  let conn = 0;
  let resultCount = 0;
  let pendingReported = 0;
  const relay = new MockRelay({
    autoAckResult: false, // result stays pending
    resumeFor: (hello) => {
      pendingReported = Math.max(pendingReported, hello.pending_results.length);
      return hello.pending_results.map((p) => ({ job_id: p.job_id, attempt_id: p.attempt_id, action: "resend_result" as const, lease_id: p.lease_id }));
    },
    onResult: () => {
      resultCount++;
    },
    onAccept: (ctx) => {
      conn++;
      if (conn === 1) {
        relay.assign(ctx.ws, { job_id: "j1", attempt_id: "pr", lease_id: "L1" });
        setTimeout(() => ctx.ws.close(), 300);
      }
    },
  });
  const port = await relay.start();
  const engine = new FakeEngine({ events: [{ kind: "assistant_text" }], outcome: { status: "success" } });
  const daemon = new Daemon(loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-v", dbPath: ":memory:" }), devSigner(), engine);
  void daemon.start().catch(() => {});
  const resent = await waitUntil(() => resultCount >= 2, 8000);
  daemon.stop();
  await relay.stop();
  await sleep(50);
  check("V1 unacked result reported in reconnect hello.pending_results", pendingReported >= 1);
  check("V2 resend_result resent the durable result", resent && resultCount >= 2);
}

/** Lease rotation overlap (P4, unit): after lease.granted (L1→L2), the OLD lease is
 *  accepted on inbound until the overlap window elapses, then rejected. */
async function scenarioW(): Promise<void> {
  let clock = 1000;
  const store = new EventLog(":memory:");
  const engine = new FakeEngine({ events: [{ kind: "stdout_chunk" }, { kind: "stdout_chunk" }], hang: true });
  const manager = new JobManager(new JobRegistry(2), store, engine, () => {}, { events: 1024, bytes: 8 << 20, conn: 32 << 20 }, true, 300_000, () => clock);
  const a = parseMessage(fakeAssign("j", "rot", "L1"));
  if (a.type === "job.assign") manager.handleAssign(a);
  await sleep(20); // let the 2 events persist
  check("W0 events persisted (2 unacked)", store.unackedEvents("rot") === 2);
  const lg = parseMessage({ id: "m", ts: "2026-07-01T00:00:00.000Z", type: "lease.granted", job_id: "j", attempt_id: "rot", lease_id: "L2", lease_ttl_ms: 120_000 });
  if (lg.type === "lease.granted") manager.handleLeaseGranted(lg);
  const ackOld = parseMessage({ id: "m", ts: "2026-07-01T00:00:00.000Z", type: "stream.ack", job_id: "j", attempt_id: "rot", lease_id: "L1", ack_seq: 1 });
  if (ackOld.type === "stream.ack") manager.handleStreamAck(ackOld);
  check("W1 OLD lease accepted during overlap (GC'd seq<=1)", store.unackedEvents("rot") === 1);
  const ackNew = parseMessage({ id: "m", ts: "2026-07-01T00:00:00.000Z", type: "stream.ack", job_id: "j", attempt_id: "rot", lease_id: "L2", ack_seq: 2 });
  if (ackNew.type === "stream.ack") manager.handleStreamAck(ackNew);
  check("W2 NEW lease accepted", store.unackedEvents("rot") === 0);
  clock += LIMITS.LEASE_ROTATION_OVERLAP_MS + 1;
  store.appendEvent("rot", 3, "rot-3", 10, "{}");
  const ackStale = parseMessage({ id: "m", ts: "2026-07-01T00:00:00.000Z", type: "stream.ack", job_id: "j", attempt_id: "rot", lease_id: "L1", ack_seq: 3 });
  if (ackStale.type === "stream.ack") manager.handleStreamAck(ackStale);
  check("W3 OLD lease rejected after the overlap window (no GC)", store.unackedEvents("rot") === 1);
  store.close();
}

function helloAccepted(resume: Array<Record<string, unknown>>) {
  return parseMessage({
    id: "m",
    ts: "2026-07-01T00:00:00.000Z",
    type: "hello.accepted",
    negotiated_version: "1.0.0",
    connection_epoch: 1,
    heartbeat_interval_ms: 15_000,
    resume,
  });
}

/** P4 Codex fixes (unit): rotation is durable; resume re-stamps the CURRENT lease
 *  (stale stored lease would be nacked); abandon fences + drops. */
async function scenarioX(): Promise<void> {
  const store = new EventLog(":memory:");
  const sent: Array<Record<string, unknown>> = [];
  const engine = new FakeEngine({ events: [{ kind: "stdout_chunk" }], hang: true });
  const manager = new JobManager(new JobRegistry(4), store, engine, (m) => sent.push(m as unknown as Record<string, unknown>), { events: 1024, bytes: 8 << 20, conn: 32 << 20 });

  const a = parseMessage(fakeAssign("j", "rs", "L1"));
  if (a.type === "job.assign") manager.handleAssign(a);
  await sleep(20); // event persisted under L1
  const lg = parseMessage({ id: "m", ts: "2026-07-01T00:00:00.000Z", type: "lease.granted", job_id: "j", attempt_id: "rs", lease_id: "L2", lease_ttl_ms: 120_000 });
  if (lg.type === "lease.granted") manager.handleLeaseGranted(lg);
  check("X0 lease rotation persisted to the store (attempt lease = L2)", store.getAttempt("rs")?.lease_id === "L2");

  sent.length = 0;
  const acc = helloAccepted([{ job_id: "j", attempt_id: "rs", action: "resume_from", resume_after_seq: 0, lease_id: "L2" }]);
  if (acc.type === "hello.accepted") manager.applyResume(acc.resume);
  const resent = sent.find((m) => m.type === "stream.event");
  check("X1 resume_from re-stamps the CURRENT lease (L2, not stored L1)", resent?.lease_id === "L2");

  // resend_result re-stamps lease + recomputes/persists digest
  const oldPayload = JSON.stringify({ id: "old", ts: "old", type: "job.result", job_id: "j", attempt_id: "rr", lease_id: "L1", final_status: "success", duration_ms: 1, stats: { event_count: 0, bytes: 0 } });
  store.createAttempt({ attempt_id: "rr", job_id: "j", lease_id: "L1", agent_run_id: "r", status: "completed", created_at: "2026-07-01T00:00:00.000Z" });
  store.saveResult({ attempt_id: "rr", job_id: "j", lease_id: "L1", final_status: "success", result_digest: "A".repeat(43), result_size: 10, payload: oldPayload, last_emitted_seq: 0 });
  sent.length = 0;
  const acc2 = helloAccepted([{ job_id: "j", attempt_id: "rr", action: "resend_result", lease_id: "L2" }]);
  if (acc2.type === "hello.accepted") manager.applyResume(acc2.resume);
  const resentResult = sent.find((m) => m.type === "job.result");
  check(
    "X2 resend_result re-stamps lease + persists a new digest",
    resentResult?.lease_id === "L2" && store.getResult("rr")?.lease_id === "L2" && store.getResult("rr")?.result_digest !== "A".repeat(43),
  );
  // The ack for the re-stamped result (L2 + new digest) must now be ACCEPTED and
  // GC the pending result — proves adoptLease updated attempts.lease_id, not just
  // the outgoing message (the exact gap Codex flagged).
  const newDigest = store.getResult("rr")?.result_digest ?? "";
  const rack = parseMessage({ id: "m", ts: "2026-07-01T00:00:00.000Z", type: "job.result.ack", job_id: "j", attempt_id: "rr", lease_id: "L2", result_digest: newDigest });
  if (rack.type === "job.result.ack") manager.handleResultAck(rack);
  check("X2b ack{L2, new digest} for the resent result is accepted → GC", store.getResult("rr") === undefined);

  // abandon fences + drops a live attempt
  const a3 = parseMessage(fakeAssign("j", "ab", "L1"));
  if (a3.type === "job.assign") manager.handleAssign(a3);
  await sleep(20);
  const acc3 = helloAccepted([{ job_id: "j", attempt_id: "ab", action: "abandon" }]);
  if (acc3.type === "hello.accepted") manager.applyResume(acc3.resume);
  check("X3 abandon drops the attempt (durable + registry)", store.getAttempt("ab") === undefined);
  store.close();
}

/** stop() during the pre-auth handshake window must stop the daemon cleanly (the
 *  in-flight client is closed via sessionClient — it isn't activeClient yet). */
async function scenarioY(): Promise<void> {
  const relay = new MockRelay({ stallHandshake: true });
  const port = await relay.start();
  const daemon = new Daemon(loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-y", dbPath: ":memory:" }), devSigner(), new FakeEngine({ events: [] }));
  const startPromise = daemon.start().catch(() => {});
  await sleep(300); // daemon is mid-handshake (awaiting hello.accepted)
  daemon.stop();
  const stopped = await Promise.race([startPromise.then(() => true), sleep(3000).then(() => false)]);
  await relay.stop();
  check("Y1 stop() during handshake stops the daemon cleanly (no hang)", stopped === true);
}

async function main(): Promise<void> {
  console.log("=== hugind P1+P2a e2e ===\n[scenario A: live handshake + heartbeat + reconnect]");
  await scenarioA();
  console.log("\n[scenario B: framing + epoch gate]");
  scenarioB();
  console.log("\n[scenario C: non-monotonic epoch rejection (live)]");
  await scenarioC();
  console.log("\n[scenario Q: inbound-queue race]");
  await scenarioQueueRace();
  console.log("\n[scenario D: full job flow → digest-ack → GC]");
  await scenarioD();
  console.log("\n[scenario E: duplicate-assign idempotency]");
  await scenarioE();
  console.log("\n[scenario F: stream backpressure]");
  await scenarioF();
  console.log("\n[scenario G: cross-session duplicate idempotency + lease fence]");
  scenarioG();
  console.log("\n[scenario H: lease.revoke local fence]");
  await scenarioH();
  console.log("\n[scenario I: EventLog GC + digest-ack (unit)]");
  scenarioI();
  console.log("\n[scenario J: per-connection byte-cap backpressure]");
  await scenarioJ();
  console.log("\n[scenario K: result.ack lease-check after terminal cleanup]");
  scenarioK();
  console.log("\n[scenario L: stale-callback race on async cancel + re-assign]");
  await scenarioL();
  console.log("\n[scenario M: worktree validation + path-injection safety]");
  scenarioM();
  console.log("\n[scenario N: workspace-invalid job → job.reject pre-accept]");
  scenarioN();
  console.log("\n[scenario P: approval round-trip — allow]");
  await scenarioP();
  console.log("\n[scenario R: approval round-trip — deny]");
  await scenarioR();
  console.log("\n[scenario S: approval timeout → auto-deny]");
  await scenarioS();
  console.log("\n[scenario T: fail-closed when the gate is unavailable]");
  await scenarioT();
  console.log("\n[scenario U: reconnect resume_from (durable events)]");
  await scenarioU();
  console.log("\n[scenario V: reconnect resend_result (durable result)]");
  await scenarioV();
  console.log("\n[scenario W: lease.granted rotation overlap]");
  await scenarioW();
  console.log("\n[scenario X: resume lease re-stamp + durable rotation + abandon fence]");
  await scenarioX();
  console.log("\n[scenario Y: stop() during the pre-auth handshake]");
  await scenarioY();
  console.log(`\n${failures === 0 ? `ALL E2E PASS` : `${failures} e2e failure(s)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
