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

import { execFileSync, spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { WebSocket } from "ws";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { LIMITS, PROTOCOL_VERSION, PROTOCOL_VERSION_V2, parseMessage, safeParseMessageV2, type MessageV2 } from "../protocol/v1/index";
import { canonicalizeServerOrigin } from "../protocol/v1/origin";
import { buildTranscript } from "../protocol/v1/transcript";
import { b64u, deriveKeypairFromSeed, signTranscript, verifyTranscript } from "../protocol/v1/ed25519";
import { buildPairingTranscript, keyFingerprint, REJECTED_TEST_PUBLIC_HEX, validateB64u32 } from "../protocol/v1/pairing";
import { loadConfig } from "../src/config";
import { loadConfigFromEnv } from "../src/index";
import { connect, connectSimple } from "../src/auth/connect";
import { readPairingConfig } from "../src/auth/config-file";
import { parsePairingToken, type ParsedPairingToken } from "../src/auth/pairing-token";
import { canonicalizeDevOrigin } from "../src/simple-pairing-dev";
import { Daemon, relayDialUrl } from "../src/daemon";
import { devSigner, performHandshake } from "../src/conn/handshake";
import { keychainSeedStore, keychainSigner, memorySeedStore, newDeviceKey, type SeedStore } from "../src/auth/keystore";
import { decodeInbound } from "../src/conn/framing";
import { RelayClient } from "../src/conn/client";
import { FakeEngine } from "../src/engine/fake-engine";
import { ClaudeEngine } from "../src/engine/claude";
import { detectEngineCapabilities, type EngineCapabilities } from "../src/engine/detect";
import { ApprovalBridge, permissionServerLaunch } from "../src/engine/permission";
import { buildIsolation, selfCheckGate } from "../src/engine/isolate";
import type { ApprovalRequest, Engine } from "../src/engine/types";
import { JobManager } from "../src/jobs/manager";
import { JobRegistry } from "../src/jobs/registry";
import { EventLog } from "../src/store/eventlog";
import { validateWorkspace } from "../src/workspace/worktree";
import { SessionEnumerator, type SessionEnumeratorOpts, type SessionInfo } from "../src/sessions/enumerator";
import {
  HISTORY_CONTENT_CAP,
  HISTORY_ENTRY_BYTE_MAX,
  HISTORY_PAGE_MAX,
  HISTORY_TOOL_IO_CAP,
  HistoryCursorError,
  buildHistoryEntries,
  readSessionHistory,
} from "../src/sessions/history";
import { SessionResumeManager } from "../src/sessions/resume-manager";
import { ClaudeResumeRunner, CodexResumeRunner, FakeResumeRunner } from "../src/sessions/resume";
import { MockRelay, verifyHello, type PairingRecord } from "../mock-relay/server";
import { MockPairingServer } from "../mock-relay/pairing-server";

const SCRATCH = join(tmpdir(), "hugind-e2e-worktree");
const TEST_ENGINE_CAPABILITIES: EngineCapabilities = { claude: { installed: true }, codex: { installed: false } };
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

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

function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

function canInspectProcessCommands(): boolean {
  if (process.platform === "win32") return false;
  try {
    const output = execFileSync("ps", ["-p", String(process.pid), "-o", "command="], { encoding: "utf8" }).trim();
    return output.length > 0;
  } catch {
    return false;
  }
}

interface LifecyclePidRecord {
  pid: number;
  startedAt: number;
  cmd: string;
}

function readLifecycleRecord(pidfile: string): LifecyclePidRecord | null {
  try {
    const raw = readFileSync(pidfile, "utf8").trim();
    if (!raw) return null;
    const legacyPid = Number(raw);
    if (Number.isInteger(legacyPid) && legacyPid > 0) return { pid: legacyPid, startedAt: 0, cmd: "" };
    const parsed = JSON.parse(raw) as Partial<LifecyclePidRecord>;
    const { pid, startedAt, cmd } = parsed;
    if (!Number.isInteger(pid) || typeof pid !== "number" || pid <= 0 || typeof startedAt !== "number" || typeof cmd !== "string") {
      return null;
    }
    return { pid, startedAt, cmd };
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    if (e instanceof SyntaxError) return null;
    throw e;
  }
}

function readLifecyclePid(pidfile: string): number | null {
  return readLifecycleRecord(pidfile)?.pid ?? null;
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

/** Graceful drain (P5): stop() sends agent.draining before disconnecting. */
async function scenarioZ(): Promise<void> {
  let accepted = false;
  let drained = false;
  const relay = new MockRelay({
    onAccept: () => {
      accepted = true;
    },
    onDraining: () => {
      drained = true;
    },
  });
  const port = await relay.start();
  const daemon = new Daemon(loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-z", dbPath: ":memory:" }), devSigner(), new FakeEngine({ events: [] }));
  void daemon.start().catch(() => {});
  await waitUntil(() => accepted, 5000);
  daemon.stop();
  const sawDrain = await waitUntil(() => drained, 2000);
  await relay.stop();
  await sleep(50);
  check("Z1 graceful stop() sends agent.draining before disconnect", sawDrain);
}

interface LifecycleCliResult {
  status: number;
  stdout: string;
  stderr: string;
}

function runLifecycleCli(args: string[], env: NodeJS.ProcessEnv): LifecycleCliResult {
  const result = spawnSync(process.execPath, ["--import", "tsx", join(REPO_ROOT, "src", "cli.ts"), ...args], {
    cwd: REPO_ROOT,
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return {
    status: result.status ?? 1,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function runLifecycleCliAsync(args: string[], env: NodeJS.ProcessEnv): Promise<LifecycleCliResult> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", "tsx", join(REPO_ROOT, "src", "cli.ts"), ...args], {
      cwd: REPO_ROOT,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("close", (code) => resolve({ status: code ?? 1, stdout, stderr }));
    child.on("error", (e) => resolve({ status: 1, stdout, stderr: `${stderr}${String(e)}` }));
  });
}

function lifecycleStateDir(): string {
  return mkdtempSync(join(tmpdir(), "hugind-lifecycle-"));
}

function lifecycleEnv(stateDir: string, args: string[]): NodeJS.ProcessEnv {
  return {
    ...process.env,
    HUGIND_STATE_DIR: stateDir,
    HUGIND_DAEMON_CMD: process.execPath,
    HUGIND_DAEMON_ARGS: JSON.stringify(args),
  };
}

function deadPid(): number {
  let pid = 999_999_999;
  while (pidAlive(pid)) pid++;
  return pid;
}

function writeLifecycleRecord(pidfile: string, record: LifecyclePidRecord): void {
  writeFileSync(pidfile, `${JSON.stringify(record)}\n`);
}

function startedPid(result: LifecycleCliResult): number | null {
  const match = /hugind started \(pid (\d+)\)/.exec(result.stdout);
  if (!match) return null;
  const pid = Number(match[1]);
  return Number.isInteger(pid) && pid > 0 ? pid : null;
}

async function reapLifecycleStub(pidfile: string, env: NodeJS.ProcessEnv): Promise<void> {
  const pid = readLifecyclePid(pidfile);
  if (pid === null || !pidAlive(pid)) return;
  runLifecycleCli(["stop", "--force"], env);
  await waitUntil(() => !pidAlive(pid), 3000);
  if (pidAlive(pid)) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Best-effort cleanup; the check below records failure if it remains live.
    }
    await waitUntil(() => !pidAlive(pid), 2000);
  }
}

async function terminatePid(pid: number): Promise<void> {
  if (!pidAlive(pid)) return;
  try {
    process.kill(pid);
  } catch {
    // Best-effort cleanup; SIGKILL below handles stubborn processes.
  }
  await waitUntil(() => !pidAlive(pid), 1000);
  if (!pidAlive(pid)) return;
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // Best-effort cleanup only.
  }
  await waitUntil(() => !pidAlive(pid), 2000);
}

async function scenarioAX(): Promise<void> {
  const stateDir = lifecycleStateDir();
  const pidfile = join(stateDir, "hugind.pid");
  const env = lifecycleEnv(stateDir, ["-e", "setInterval(()=>{},1e9)"]);

  try {
    const start1 = runLifecycleCli(["start"], env);
    const pid1 = readLifecyclePid(pidfile);
    const startedAlive = pid1 !== null && (await waitUntil(() => pidAlive(pid1), 1000));
    check(
      "AX1 lifecycle start writes a pidfile and the stub pid is alive",
      start1.status === 0 && start1.stdout.includes("hugind started") && pid1 !== null && startedAlive,
    );

    const start2 = runLifecycleCli(["start"], env);
    check(
      "AX2 lifecycle start refuses an already-running pid",
      pid1 !== null && start2.status !== 0 && start2.stdout.includes(`already running (pid ${pid1})`),
    );

    const statusRunning = runLifecycleCli(["status"], env);
    check(
      "AX3 lifecycle status reports running with the pid",
      pid1 !== null && statusRunning.status === 0 && statusRunning.stdout.includes(`running (pid ${pid1}, logs:`),
    );

    const stop = runLifecycleCli(["stop"], env);
    const stopped = pid1 !== null && (await waitUntil(() => !pidAlive(pid1), 3000));
    check(
      "AX4 lifecycle stop terminates the process and removes the pidfile",
      stop.status === 0 && stopped && !existsSync(pidfile),
    );

    const statusStopped = runLifecycleCli(["status"], env);
    check(
      "AX5 lifecycle status reports stopped with a non-zero exit after stop",
      statusStopped.status !== 0 && statusStopped.stdout.trim() === "stopped",
    );

    writeFileSync(pidfile, `${deadPid()}\n`);
    const statusStale = runLifecycleCli(["status"], env);
    check(
      "AX6 lifecycle status cleans a stale pidfile",
      statusStale.status !== 0 && statusStale.stdout.trim() === "stopped" && !existsSync(pidfile),
    );

    writeFileSync(pidfile, `${deadPid()}\n`);
    const startAfterStale = runLifecycleCli(["start"], env);
    const pid2 = readLifecyclePid(pidfile);
    const restartedAlive = pid2 !== null && (await waitUntil(() => pidAlive(pid2), 1000));
    check(
      "AX7 lifecycle start proceeds after a stale pidfile",
      startAfterStale.status === 0 && pid2 !== null && restartedAlive,
    );
  } finally {
    await reapLifecycleStub(pidfile, env);
    rmSync(stateDir, { recursive: true, force: true });
  }

  const failStateDir = lifecycleStateDir();
  const failPidfile = join(failStateDir, "hugind.pid");
  const failEnv = lifecycleEnv(failStateDir, ["-e", "console.error('boot failed');process.exit(1)"]);
  try {
    const failedStart = runLifecycleCli(["start"], failEnv);
    check(
      "AX8 lifecycle start fails and removes pidfile when child exits immediately",
      failedStart.status !== 0 && failedStart.stdout.includes("child exited immediately") && !existsSync(failPidfile),
    );
  } finally {
    await reapLifecycleStub(failPidfile, failEnv);
    rmSync(failStateDir, { recursive: true, force: true });
  }

  const foreignStateDir = lifecycleStateDir();
  const foreignPidfile = join(foreignStateDir, "hugind.pid");
  const foreignEnv = lifecycleEnv(foreignStateDir, ["-e", "setInterval(()=>{},1e9)"]);
  let foreignPid: number | undefined;
  try {
    if (!canInspectProcessCommands()) {
      check("AX9 lifecycle foreign-pid no-kill check skipped when process command inspection is unavailable", true);
    } else {
      const foreign = spawn(process.execPath, ["-e", "setInterval(()=>{},1e9)"], { stdio: "ignore" });
      const pid = foreign.pid;
      foreignPid = pid;
      const live = pid !== undefined && (await waitUntil(() => pidAlive(pid), 1000));
      if (pid !== undefined) {
        writeLifecycleRecord(foreignPidfile, { pid, startedAt: Date.now(), cmd: "totally-unrelated-cmd" });
      }
      const stopForeign = runLifecycleCli(["stop"], foreignEnv);
      const statusForeign = runLifecycleCli(["status"], foreignEnv);
      check(
        "AX9 lifecycle stop treats a live non-matching pidfile as stale and does not kill it",
        live &&
          pid !== undefined &&
          pidAlive(pid) &&
          stopForeign.status !== 0 &&
          stopForeign.stdout.includes("stale pidfile removed") &&
          statusForeign.status !== 0 &&
          statusForeign.stdout.trim() === "stopped",
      );
    }
  } finally {
    if (foreignPid !== undefined) await terminatePid(foreignPid);
    rmSync(foreignStateDir, { recursive: true, force: true });
  }

  const raceStateDir = lifecycleStateDir();
  const racePidfile = join(raceStateDir, "hugind.pid");
  const raceEnv = lifecycleEnv(raceStateDir, ["-e", "setInterval(()=>{},1e9)"]);
  const raceStartedPids: number[] = [];
  try {
    const results = await Promise.all([runLifecycleCliAsync(["start"], raceEnv), runLifecycleCliAsync(["start"], raceEnv)]);
    for (const result of results) {
      const pid = startedPid(result);
      if (pid !== null) raceStartedPids.push(pid);
    }
    const successCount = results.filter((result) => result.status === 0 && result.stdout.includes("hugind started")).length;
    const refusedCount = results.filter((result) => result.status !== 0 && result.stdout.includes("already running")).length;
    const racePid = readLifecyclePid(racePidfile);
    check(
      "AX10 lifecycle concurrent double-start is serialized by the pidfile claim",
      successCount === 1 && refusedCount === 1 && racePid !== null && pidAlive(racePid),
    );
  } finally {
    await reapLifecycleStub(racePidfile, raceEnv);
    for (const pid of raceStartedPids) await terminatePid(pid);
    rmSync(raceStateDir, { recursive: true, force: true });
  }

  const legacyStateDir = lifecycleStateDir();
  const legacyPidfile = join(legacyStateDir, "hugind.pid");
  const legacyEnv = lifecycleEnv(legacyStateDir, ["-e", "setInterval(()=>{},1e9)"]);
  try {
    writeFileSync(legacyPidfile, `${deadPid()}\n`);
    const legacyStatus = runLifecycleCli(["status"], legacyEnv);
    check(
      "AX11 lifecycle status tolerates a legacy bare-number pidfile",
      legacyStatus.status !== 0 && legacyStatus.stdout.trim() === "stopped" && !existsSync(legacyPidfile),
    );
  } finally {
    await reapLifecycleStub(legacyPidfile, legacyEnv);
    rmSync(legacyStateDir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Track A — production auth: real Ed25519 device-key signer ⇄ verifying relay.
// ---------------------------------------------------------------------------

/** Set up a real keychain-style signer over an in-memory seed store (CI-safe:
 *  no OS keychain) + the pairing record the relay verifies it against. */
async function makeAuthPair(keyId: string, agentId: string, tenantId: string, serverUrl: string, recordTenantId = tenantId) {
  const store = memorySeedStore();
  const dk = newDeviceKey();
  await store.set(keyId, dk.seed);
  const signer = await keychainSigner(keyId, store);
  const origin = canonicalizeServerOrigin(serverUrl);
  const record: PairingRecord = {
    agentId,
    keyId,
    publicKeyHex: dk.publicRaw.toString("hex"),
    tenantId: recordTenantId,
    serverOrigin: origin ?? "ORIGIN_NON_CANONICAL",
  };
  return { signer, record, originOk: origin !== null };
}

/** Track A positive (live): a real keychain-style Ed25519 signer completes a
 *  handshake the relay actually VERIFIES against the registered public key. */
async function scenarioAA(): Promise<void> {
  let accepts = 0;
  let rejectCode: string | null = null;
  const relay = new MockRelay({
    onAccept: () => { accepts++; },
    onHandshakeReject: (code) => { rejectCode = code; },
  });
  const port = await relay.start();
  const serverUrl = `ws://127.0.0.1:${port}`;
  const { signer, record, originOk } = await makeAuthPair("key-aa", "agent-abc", "acme", serverUrl);
  relay.setVerifyAuth(record);
  const daemon = new Daemon(
    loadConfig({ serverUrl, agentId: "agent-abc", keyId: "key-aa", tenantId: "acme", dbPath: ":memory:" }),
    signer,
    new FakeEngine({ events: [] }),
  );
  void daemon.start().catch(() => {});
  const accepted = await waitUntil(() => accepts >= 1, 6000);
  daemon.stop();
  await relay.stop();
  await sleep(50);
  check("AA0 loopback server_origin canonicalizes", originOk);
  check("AA1 real Ed25519 signer accepted by a VERIFYING relay", accepted && accepts >= 1);
  check("AA2 no handshake rejection on the valid signature", rejectCode === null);
}

/** Track A negative (live): a tampered transcript field — the relay reconstructs
 *  a DIFFERENT tenant_id than the daemon signed — must fail verification with
 *  bad_signature, and the daemon must NOT be accepted (fail closed). */
async function scenarioAB(): Promise<void> {
  let accepts = 0;
  let rejectCode: string | null = null;
  const relay = new MockRelay({
    onAccept: () => { accepts++; },
    onHandshakeReject: (code) => { rejectCode = code; },
  });
  const port = await relay.start();
  const serverUrl = `ws://127.0.0.1:${port}`;
  // Daemon signs tenant "acme"; the relay's pairing record binds a DIFFERENT
  // tenant — the reconstructed transcript diverges by one field.
  const { signer, record } = await makeAuthPair("key-ab", "agent-abc", "acme", serverUrl, "acme-TAMPERED");
  relay.setVerifyAuth(record);
  const daemon = new Daemon(
    loadConfig({ serverUrl, agentId: "agent-abc", keyId: "key-ab", tenantId: "acme", dbPath: ":memory:" }),
    signer,
    new FakeEngine({ events: [] }),
  );
  void daemon.start().catch(() => {});
  const rejected = await waitUntil(() => rejectCode !== null, 6000);
  daemon.stop();
  await relay.stop();
  await sleep(50);
  check("AB1 tampered transcript field → relay rejects bad_signature", rejected && rejectCode === "bad_signature");
  check("AB2 daemon NOT accepted on a failed signature (fail closed)", accepts === 0);
}

interface BaselineVector {
  label: string;
  challenge_id: string;
  nonce_base64url: string;
  agent_id: string;
  key_id: string;
  protocol_version: string;
  tenant_id: string;
  canonical_server_origin: string;
  ed25519_public_hex: string;
  expected_signature_base64url: string;
}

function loadBaselineVector(): BaselineVector {
  const vf = JSON.parse(readFileSync(new URL("../protocol/v1/test-vectors.json", import.meta.url), "utf8")) as {
    positives: BaselineVector[];
  };
  const v = vf.positives.find((p) => p.label === "baseline");
  if (!v) throw new Error("baseline positive vector missing from test-vectors.json");
  return v;
}

function helloFromVector(v: BaselineVector, over: { signature?: string; agentId?: string } = {}) {
  const m = parseMessage({
    id: "m", ts: "2026-07-01T00:00:00.000Z", type: "hello",
    protocol_version: v.protocol_version, agent_id: over.agentId ?? v.agent_id, agent_version: "0.0.0",
    auth: { challenge_id: v.challenge_id, key_id: v.key_id, signature: over.signature ?? v.expected_signature_base64url, alg: "ed25519" },
    os: { platform: "darwin", arch: "arm64" },
    capabilities: { engines: { claude: { installed: true }, codex: { installed: false } }, project_roots: [] },
    active_jobs: [], pending_results: [],
  });
  if (m.type !== "hello") throw new Error("helloFromVector did not build a hello");
  return m;
}

/** Track A reference (deterministic): drive the relay's verifyHello directly with
 *  the committed F4 vector (auth-pairing-spec §5) — the same transcript/signature
 *  a Go/Rust relay uses. Positive verifies; each tampered input fails as stated. */
function scenarioAC(): void {
  const v = loadBaselineVector();
  const issued = { challengeId: v.challenge_id, nonce: v.nonce_base64url };
  const record: PairingRecord = {
    agentId: v.agent_id, keyId: v.key_id, publicKeyHex: v.ed25519_public_hex,
    tenantId: v.tenant_id, serverOrigin: v.canonical_server_origin,
  };
  check("AC1 committed baseline vector verifies (relay verifyHello)", verifyHello(helloFromVector(v), issued, record).ok);

  const rTenant = verifyHello(helloFromVector(v), issued, { ...record, tenantId: "evil" });
  check("AC2 tampered tenant_id → bad_signature", !rTenant.ok && rTenant.code === "bad_signature");

  const rOrigin = verifyHello(helloFromVector(v), issued, { ...record, serverOrigin: "wss://evil.example.com" });
  check("AC3 tampered server_origin → bad_signature", !rOrigin.ok && rOrigin.code === "bad_signature");

  const otherNonce = Buffer.alloc(32, 0xab).toString("base64url");
  const rNonce = verifyHello(helloFromVector(v), { challengeId: v.challenge_id, nonce: otherNonce }, record);
  check("AC4 tampered nonce → bad_signature", !rNonce.ok && rNonce.code === "bad_signature");

  const rAgent = verifyHello(helloFromVector(v, { agentId: "agent-x" }), issued, record);
  check("AC5 unknown (agent_id,key_id) → agent_unknown (before curve check)", !rAgent.ok && rAgent.code === "agent_unknown");

  const badSig = (v.expected_signature_base64url[0] === "A" ? "B" : "A") + v.expected_signature_base64url.slice(1);
  const rSig = verifyHello(helloFromVector(v, { signature: badSig }), issued, record);
  check("AC6 corrupted signature → bad_signature", !rSig.ok && rSig.code === "bad_signature");

  // record-level validation: the verifier never binds a non-canonical origin or
  // invalid tenant from a misconfigured pairing record (rejects, never normalizes).
  const rBadOrigin = verifyHello(helloFromVector(v), issued, { ...record, serverOrigin: "wss://relay.example.com/" });
  check("AC7 non-canonical record server_origin → agent_unknown (record validated)", !rBadOrigin.ok && rBadOrigin.code === "agent_unknown");
  const rBadTenant = verifyHello(helloFromVector(v), issued, { ...record, tenantId: "bad tenant!" });
  check("AC8 invalid record tenant_id → agent_unknown (record validated)", !rBadTenant.ok && rBadTenant.code === "agent_unknown");
}

/** Track A OS-keychain round-trip (guarded): exercise the REAL keychain via
 *  @napi-rs/keyring — generate → store → keychainSigner loads + signs → verify →
 *  delete. SKIPPED (not failed) where no OS keychain is present (CI). */
async function scenarioAD(): Promise<void> {
  const service = "com.contextualai.hugin-agent.e2e";
  const keyId = `e2e-${process.pid}-${Date.now()}`; // Date.now is fine in the e2e script
  const store = keychainSeedStore(service);
  const dk = newDeviceKey();
  let available = true;
  try {
    await store.set(keyId, dk.seed);
    if ((await store.get(keyId)) === null) available = false;
  } catch {
    available = false;
  }
  if (!available) {
    console.log("⚠ AD keychain round-trip SKIPPED (no OS keychain in this environment)");
    return;
  }
  try {
    const signer = await keychainSigner(keyId, store);
    const t = buildTranscript({
      challenge_id: "ch-ad", nonce_raw: Buffer.alloc(32, 0x11), agent_id: "agent-ad",
      key_id: keyId, protocol_version: "1.0.0", tenant_id: "acme", server_origin: "wss://relay.example.com",
    });
    check("AD1 keychain-loaded signer verifies against its public key", verifyTranscript(dk.publicRaw, t, signer.sign(t)));
  } finally {
    await store.delete(keyId); // always clean up the e2e keychain entry
  }
  check("AD2 keychain entry deleted after cleanup", (await store.get(keyId)) === null);
}

interface PairCompleteBody extends Record<string, unknown> {
  secret: string;
  public_key: string;
  pop_signature: string;
}

interface PairStatusBody extends Record<string, unknown> {
  poll_token: string;
}

interface SimpleCompleteBody extends Record<string, unknown> {
  device_code: string;
  public_key: string;
  hostname?: string;
}

function trackingSeedStore(): { store: SeedStore; setKeys: string[] } {
  const inner = memorySeedStore();
  const setKeys: string[] = [];
  return {
    setKeys,
    store: {
      async set(keyId, seed) {
        setKeys.push(keyId);
        await inner.set(keyId, seed);
      },
      get: inner.get,
      delete: inner.delete,
    },
  };
}

function makeAdvancingNow(start = Date.now()): () => number {
  let now = start;
  return () => {
    now += 25;
    return now;
  };
}

function testSeed(firstByte: number): Buffer {
  return Buffer.from(Array.from({ length: 32 }, (_, i) => firstByte + i));
}

function requestJsonBodies(pairing: MockPairingServer): Array<Record<string, unknown>> {
  const parsed: Array<Record<string, unknown>> = [];
  for (const raw of pairing.requestBodies) {
    try {
      const value: unknown = JSON.parse(raw);
      if (value && typeof value === "object" && !Array.isArray(value)) {
        parsed.push(value as Record<string, unknown>);
      }
    } catch {
      // Non-JSON request bodies are irrelevant to these pairing assertions.
    }
  }
  return parsed;
}

function completeBodies(pairing: MockPairingServer): PairCompleteBody[] {
  return requestJsonBodies(pairing).filter((body): body is PairCompleteBody =>
    typeof body.secret === "string" &&
    typeof body.public_key === "string" &&
    typeof body.pop_signature === "string",
  );
}

function statusBodies(pairing: MockPairingServer): PairStatusBody[] {
  return requestJsonBodies(pairing).filter((body): body is PairStatusBody => typeof body.poll_token === "string");
}

function simpleCompleteBodies(pairing: MockPairingServer): SimpleCompleteBody[] {
  return requestJsonBodies(pairing).filter((body): body is SimpleCompleteBody =>
    typeof body.device_code === "string" && typeof body.public_key === "string",
  );
}

function bodyString(body: unknown, field: string): string | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const value = (body as Record<string, unknown>)[field];
  return typeof value === "string" ? value : null;
}

function pairingFailed(body: unknown): boolean {
  return bodyString(body, "error") === "pairing_failed";
}

function tamperB64u(s: string): string {
  return `${s[0] === "A" ? "B" : "A"}${s.slice(1)}`;
}

function nonCanonicalB64u32Alias(): string {
  const alias = `${"A".repeat(42)}B`;
  if (validateB64u32(alias)) throw new Error("test non-canonical base64url alias unexpectedly validated");
  return alias;
}

function rewritePairingTokenOrigin(token: string, origin: string): string {
  const payload = token.split(".")[1];
  if (!payload) throw new Error("test token missing payload");
  const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, unknown>;
  return `hpk1.${b64u(Buffer.from(JSON.stringify({ ...decoded, origin }), "utf8"))}`;
}

function rewritePairingTokenSecret(token: string, secret: string): string {
  const payload = token.split(".")[1];
  if (!payload) throw new Error("test token missing payload");
  const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, unknown>;
  return `hpk1.${b64u(Buffer.from(JSON.stringify({ ...decoded, secret }), "utf8"))}`;
}

async function postPairComplete(
  baseUrl: string,
  token: ParsedPairingToken,
  seed: Buffer,
  opts: { tamperSignature?: boolean } = {},
): Promise<{ status: number; body: unknown; publicKeyB64u: string; fingerprint: string }> {
  if (!validateB64u32(token.secret)) throw new Error("test token secret is not canonical");
  const { privateKey, publicRaw } = deriveKeypairFromSeed(seed);
  const publicKeyB64u = b64u(publicRaw);
  if (!validateB64u32(publicKeyB64u)) throw new Error("test public key is not canonical");
  const transcript = buildPairingTranscript({
    secret: token.secret,
    publicRaw,
    server_origin: token.origin,
    protocol_version: PROTOCOL_VERSION,
  });
  let popSignature = signTranscript(privateKey, transcript);
  if (opts.tamperSignature) popSignature = tamperB64u(popSignature);

  const res = await fetch(`${baseUrl}/api/v1/hugin-agents/pair/complete`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ secret: token.secret, public_key: publicKeyB64u, pop_signature: popSignature }),
  });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  return { status: res.status, body, publicKeyB64u, fingerprint: keyFingerprint(publicRaw) };
}

async function postRawPairComplete(baseUrl: string, body: Record<string, unknown>): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${baseUrl}/api/v1/hugin-agents/pair/complete`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
  });
  let parsed: unknown = null;
  try {
    parsed = await res.json();
  } catch {
    parsed = null;
  }
  return { status: res.status, body: parsed };
}

async function expectConnectSimpleReject(
  label: string,
  cfgPath: string,
  store: ReturnType<typeof trackingSeedStore>,
  opts: Parameters<typeof connectSimple>[0],
  expectedError: string,
): Promise<string> {
  let message = "";
  try {
    await connectSimple({ ...opts, seedStore: store.store, configPath: cfgPath });
  } catch (err) {
    message = err instanceof Error ? err.message : String(err);
  }
  check(label, message === expectedError && readPairingConfig(cfgPath) === null && store.setKeys.length === 0);
  return message;
}

async function runConnectCli(opts: {
  cfgDir: string;
  configPath: string;
  args: string[];
  input?: string;
  env?: Record<string, string | undefined>;
}): Promise<{ status: number | null; stdout: string; stderr: string; argv: string[] }> {
  mkdirSync(opts.cfgDir, { recursive: true });
  const wrapperPath = join(opts.cfgDir, `connect-argv-hook-${Date.now()}-${Math.random().toString(16).slice(2)}.mjs`);
  const argvOut = join(opts.cfgDir, `argv-${Date.now()}-${Math.random().toString(16).slice(2)}.json`);
  writeFileSync(
    wrapperPath,
    `import { writeFileSync } from "node:fs";\n` +
      `writeFileSync(process.env.HG_ARGV_OUT ?? "", JSON.stringify(process.argv.slice(2)));\n`,
  );
  const child = spawn(process.execPath, ["--import", "tsx", "--import", pathToFileURL(wrapperPath).href, resolve("src/connect.ts"), ...opts.args], {
    env: { ...(process.env as Record<string, string>), ...opts.env, HG_ARGV_OUT: argvOut },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let spawnError = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  child.stdin.end(opts.input ?? "");
  const status = await new Promise<number | null>((resolveStatus) => {
    const timer = setTimeout(() => {
      spawnError = "connect child timed out";
      child.kill("SIGKILL");
    }, 15_000);
    child.on("error", (err) => {
      spawnError = err.message;
      clearTimeout(timer);
      resolveStatus(null);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolveStatus(code);
    });
  });
  let argv: string[] = [];
  try {
    argv = JSON.parse(readFileSync(argvOut, "utf8")) as string[];
  } catch {
    argv = [];
  }
  return {
    status,
    stdout,
    stderr: `${stderr}${spawnError}`,
    argv,
  };
}

async function postPairStatus(baseUrl: string, pollToken: string): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${baseUrl}/api/v1/hugin-agents/pair/status`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ poll_token: pollToken }),
  });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  return { status: res.status, body };
}

async function scenarioAEHappyPath(cfgDir: string): Promise<void> {
  const cfgPath = join(cfgDir, "ae1-config.json");
  const pairing = new MockPairingServer({
    tenantId: "acme",
    createdByUserId: "user-42",
    agentId: "agent-ae1",
    keyId: "key-ae1",
    confirmAfterStatusPolls: 1,
  });
  await pairing.start();
  try {
    const token = pairing.mint();
    const parsed = parsePairingToken(token, Date.now());
    const store = memorySeedStore();
    let surfacedFingerprint = "";
    const res = await connect({
      token,
      seedStore: store,
      configPath: cfgPath,
      sleepImpl: () => Promise.resolve(),
      nowImpl: makeAdvancingNow(),
      onFingerprint: (fp) => {
        surfacedFingerprint = fp;
      },
    });

    const cfg = readPairingConfig(cfgPath);
    check(
      "AE1 happy path persists ids, canonical serverUrl, and config file",
      cfg?.agentId === "agent-ae1" &&
        cfg?.keyId === "key-ae1" &&
        cfg?.tenantId === "acme" &&
        cfg?.serverUrl === parsed.origin &&
        res.agentId === "agent-ae1" &&
        res.keyId === "key-ae1" &&
        res.tenantId === "acme" &&
        res.serverUrl === parsed.origin &&
        res.configPath === cfgPath,
    );

    const seed = await store.get("key-ae1");
    const publicRaw = seed ? deriveKeypairFromSeed(seed).publicRaw : Buffer.alloc(0);
    const publicKeyB64u = seed ? b64u(publicRaw) : "NO_PUBLIC_KEY";
    const complete = completeBodies(pairing);
    const seedEncodings = seed
      ? [b64u(seed), seed.toString("base64"), seed.toString("hex"), seed.toString("hex").toUpperCase(), JSON.stringify(Array.from(seed))]
      : [];
    const seedLeaked = pairing.requestBodies.some((body) => seedEncodings.some((encoding) => body.includes(encoding)));
    const publicSent = complete.some((body) => body.public_key === publicKeyB64u);
    const popSent = complete.some((body) => body.public_key === publicKeyB64u && /^[A-Za-z0-9_-]{86}$/.test(body.pop_signature));
    check(
      "AE2 seed off-wire: public key + PoP sent, seed absent under common encodings, one key registered",
      seed?.length === 32 &&
        !seedLeaked &&
        publicSent &&
        popSent &&
        pairing.registeredPublicKeys.length === 1 &&
        pairing.registeredPublicKeys[0] === publicKeyB64u,
    );

    const replay = seed ? await postPairComplete(pairing.baseUrl(), parsed, seed) : null;
    check(
      "AE3 fingerprint match: onFingerprint == keyFingerprint(pub) == server returned fingerprint",
      seed !== null &&
        replay?.status === 202 &&
        surfacedFingerprint === keyFingerprint(publicRaw) &&
        bodyString(replay.body, "fingerprint") === replay.fingerprint,
    );
  } finally {
    await pairing.stop();
  }
}

async function scenarioAEFingerprintMismatchFailClosed(cfgDir: string): Promise<void> {
  const cfgPath = join(cfgDir, "ae3b-config.json");
  const pairing = new MockPairingServer({
    tenantId: "acme",
    agentId: "agent-ae3b",
    keyId: "key-ae3b",
    forceWrongFingerprint: true,
  });
  await pairing.start();
  try {
    let rejected = false;
    try {
      await connect({
        token: pairing.mint(),
        seedStore: memorySeedStore(),
        configPath: cfgPath,
        sleepImpl: () => Promise.resolve(),
        nowImpl: makeAdvancingNow(),
      });
    } catch {
      rejected = true;
    }
    check(
      "AE3b fingerprint mismatch rejects and does not persist config",
      rejected &&
        readPairingConfig(cfgPath) === null &&
        completeBodies(pairing).length === 1 &&
        statusBodies(pairing).length === 0,
    );
  } finally {
    await pairing.stop();
  }
}

async function scenarioAEOriginFailClosed(cfgDir: string): Promise<void> {
  const pairing = new MockPairingServer();
  await pairing.start();
  try {
    const token = pairing.mint();
    const badToken = rewritePairingTokenOrigin(token, `ws://127.0.0.1:${pairing.port}/`);
    let rejected = false;
    try {
      await connect({
        token: badToken,
        seedStore: memorySeedStore(),
        configPath: join(cfgDir, "ae4-config.json"),
        sleepImpl: () => Promise.resolve(),
        nowImpl: makeAdvancingNow(),
      });
    } catch {
      rejected = true;
    }
    check("AE4 origin fail-closed rejects non-canonical token origin before any POST", rejected && pairing.requestBodies.length === 0);

    const nonCanonicalSecret = nonCanonicalB64u32Alias();
    const badSecretToken = rewritePairingTokenSecret(token, nonCanonicalSecret);
    let parseRejected = false;
    let parseErrorMessage = "";
    try {
      parsePairingToken(badSecretToken, Date.now());
    } catch (err) {
      parseRejected = true;
      parseErrorMessage = err instanceof Error ? err.message : String(err);
    }
    const beforeConnectBodies = pairing.requestBodies.length;
    let connectRejected = false;
    try {
      await connect({
        token: badSecretToken,
        seedStore: memorySeedStore(),
        configPath: join(cfgDir, "ae4-secret-config.json"),
        sleepImpl: () => Promise.resolve(),
        nowImpl: makeAdvancingNow(),
      });
    } catch {
      connectRejected = true;
    }
    check(
      "AE4 parser rejects non-canonical token secret before any POST",
      parseRejected &&
        parseErrorMessage === "invalid pairing token; re-copy the token" &&
        !parseErrorMessage.includes(nonCanonicalSecret) &&
        connectRejected &&
        pairing.requestBodies.length === beforeConnectBodies,
    );
  } finally {
    await pairing.stop();
  }
}

async function scenarioAEServerDirectRefusals(): Promise<void> {
  const pairing = new MockPairingServer({ attemptCap: 5 });
  await pairing.start();
  try {
    const token = parsePairingToken(pairing.mint(), Date.now());
    const rejectedSeed = testSeed(0x01);
    const rejectedPubMatches = deriveKeypairFromSeed(rejectedSeed).publicRaw.toString("hex") === REJECTED_TEST_PUBLIC_HEX;
    const rejectedTestKey = await postPairComplete(pairing.baseUrl(), token, rejectedSeed);
    const badPop = await postPairComplete(pairing.baseUrl(), token, testSeed(0x21), { tamperSignature: true });
    check(
      "AE5 test-key and bad PoP completions return generic pairing_failed",
      rejectedPubMatches &&
        rejectedTestKey.status === 400 &&
        pairingFailed(rejectedTestKey.body) &&
        badPop.status === 400 &&
        pairingFailed(badPop.body),
    );
  } finally {
    await pairing.stop();
  }
}

async function scenarioAEPendingThenActive(cfgDir: string): Promise<void> {
  const pendingPolls = 2;
  const pairing = new MockPairingServer({
    tenantId: "acme",
    agentId: "agent-ae6",
    keyId: "key-ae6",
    confirmAfterStatusPolls: pendingPolls,
  });
  await pairing.start();
  try {
    const res = await connect({
      token: pairing.mint(),
      seedStore: memorySeedStore(),
      configPath: join(cfgDir, "ae6-config.json"),
      sleepImpl: () => Promise.resolve(),
      nowImpl: makeAdvancingNow(),
    });
    check(
      "AE6 client observes pending status responses before active",
      res.agentId === "agent-ae6" &&
        statusBodies(pairing).length >= pendingPolls + 1 &&
        completeBodies(pairing).length === 1,
    );
  } finally {
    await pairing.stop();
  }
}

async function scenarioAEIdempotentRecomplete(cfgDir: string): Promise<void> {
  const pendingRecovery = new MockPairingServer({
    tenantId: "acme",
    agentId: "agent-ae7-pending",
    keyId: "key-ae7-pending",
    confirmAfterStatusPolls: 1,
    forceValidStatus404s: 1,
  });
  await pendingRecovery.start();
  try {
    const res = await connect({
      token: pendingRecovery.mint(),
      seedStore: memorySeedStore(),
      configPath: join(cfgDir, "ae7-pending-config.json"),
      sleepImpl: () => Promise.resolve(),
      nowImpl: makeAdvancingNow(),
    });
    const complete = completeBodies(pendingRecovery);
    check(
      "AE7 idempotent re-complete recovers from first poll_token 404 while pending",
      res.agentId === "agent-ae7-pending" &&
        complete.length === 2 &&
        new Set(complete.map((body) => body.public_key)).size === 1 &&
        statusBodies(pendingRecovery).length >= 3,
    );
  } finally {
    await pendingRecovery.stop();
  }

  const repeated404 = new MockPairingServer({
    tenantId: "acme",
    agentId: "agent-ae7-repeated-404",
    keyId: "key-ae7-repeated-404",
    confirmAfterStatusPolls: 1,
    forceValidStatus404s: 2,
  });
  await repeated404.start();
  try {
    let rejected = false;
    const cfgPath = join(cfgDir, "ae7-repeated-404-config.json");
    try {
      await connect({
        token: repeated404.mint(),
        seedStore: memorySeedStore(),
        configPath: cfgPath,
        sleepImpl: () => Promise.resolve(),
        nowImpl: makeAdvancingNow(),
      });
    } catch {
      rejected = true;
    }
    const complete = completeBodies(repeated404);
    check(
      "AE7 second poll_token 404 fails after exactly one re-complete",
      rejected &&
        readPairingConfig(cfgPath) === null &&
        complete.length === 2 &&
        new Set(complete.map((body) => body.public_key)).size === 1 &&
        statusBodies(repeated404).length === 2,
    );
  } finally {
    await repeated404.stop();
  }

  const activeRecovery = new MockPairingServer({
    tenantId: "acme",
    agentId: "agent-ae7-active",
    keyId: "key-ae7-active",
    confirmAfterStatusPolls: 0,
    forceValidStatus404s: 1,
  });
  await activeRecovery.start();
  try {
    const res = await connect({
      token: activeRecovery.mint(),
      seedStore: memorySeedStore(),
      configPath: join(cfgDir, "ae7-active-config.json"),
      sleepImpl: () => Promise.resolve(),
      nowImpl: makeAdvancingNow(),
    });
    const complete = completeBodies(activeRecovery);
    check(
      "AE7 post-active same-key re-complete recovers ids after first poll_token 404",
      res.agentId === "agent-ae7-active" &&
        complete.length === 2 &&
        new Set(complete.map((body) => body.public_key)).size === 1 &&
        statusBodies(activeRecovery).length >= 2,
    );
  } finally {
    await activeRecovery.stop();
  }
}

async function scenarioAEWinnerBinding(): Promise<void> {
  const pairing = new MockPairingServer({
    tenantId: "acme",
    agentId: "agent-ae8",
    keyId: "key-ae8",
  });
  await pairing.start();
  try {
    const token = parsePairingToken(pairing.mint(), Date.now());
    const winner = await postPairComplete(pairing.baseUrl(), token, testSeed(0x21));
    const pollToken = bodyString(winner.body, "poll_token") ?? "";
    const winnerFingerprint = bodyString(winner.body, "fingerprint");
    const loser = await postPairComplete(pairing.baseUrl(), token, testSeed(0x41));
    const winnerAgain = await postPairComplete(pairing.baseUrl(), token, testSeed(0x21));
    const confirmed = pairing.confirm();
    const status = await postPairStatus(pairing.baseUrl(), pollToken);
    check(
      "AE8 pending winner-binding rejects a different key and leaves winning ids unaffected",
      winner.status === 202 &&
        winnerFingerprint === winner.fingerprint &&
        loser.publicKeyB64u !== winner.publicKeyB64u &&
        loser.status === 400 &&
        pairingFailed(loser.body) &&
        winnerAgain.status === 202 &&
        winnerAgain.publicKeyB64u === winner.publicKeyB64u &&
        bodyString(winnerAgain.body, "fingerprint") === winnerFingerprint &&
        pairing.registeredPublicKeys.length === 1 &&
        pairing.registeredPublicKeys[0] === winner.publicKeyB64u &&
        confirmed?.agent_id === "agent-ae8" &&
        confirmed.key_id === "key-ae8" &&
        status.status === 200 &&
        bodyString(status.body, "status") === "active" &&
        bodyString(status.body, "agent_id") === "agent-ae8" &&
        bodyString(status.body, "key_id") === "key-ae8",
    );
  } finally {
    await pairing.stop();
  }
}

async function scenarioAEAttemptCapBurn(): Promise<void> {
  const attemptCap = 3;
  const earlyGuard = new MockPairingServer({ attemptCap });
  await earlyGuard.start();
  try {
    const token = parsePairingToken(earlyGuard.mint(), Date.now());
    const gateFailure = await postRawPairComplete(earlyGuard.baseUrl(), {
      secret: nonCanonicalB64u32Alias(),
      public_key: "A".repeat(43),
      pop_signature: "A".repeat(86),
    });
    const invalidsBeforeCap: Array<{ status: number; body: unknown }> = [];
    for (let i = 0; i < attemptCap - 1; i++) {
      invalidsBeforeCap.push(await postPairComplete(earlyGuard.baseUrl(), token, testSeed(0x21), { tamperSignature: true }));
    }
    const validBeforeBurn = await postPairComplete(earlyGuard.baseUrl(), token, testSeed(0x21));
    check(
      "AE9 gate failures do not count and cap-minus-one bad PoPs still allow valid completion",
      gateFailure.status === 400 &&
        pairingFailed(gateFailure.body) &&
        invalidsBeforeCap.every((res) => res.status === 400 && pairingFailed(res.body)) &&
        validBeforeBurn.status === 202 &&
        bodyString(validBeforeBurn.body, "status") === "pending" &&
        earlyGuard.registeredPublicKeys.length === 1 &&
        earlyGuard.registeredPublicKeys[0] === validBeforeBurn.publicKeyB64u,
    );
  } finally {
    await earlyGuard.stop();
  }

  const burnGuard = new MockPairingServer({ attemptCap });
  await burnGuard.start();
  try {
    const token = parsePairingToken(burnGuard.mint(), Date.now());
    const invalidsAtCap: Array<{ status: number; body: unknown }> = [];
    for (let i = 0; i < attemptCap; i++) {
      invalidsAtCap.push(await postPairComplete(burnGuard.baseUrl(), token, testSeed(0x21), { tamperSignature: true }));
    }
    const validAfterBurn = await postPairComplete(burnGuard.baseUrl(), token, testSeed(0x21));
    check(
      "AE9 attempt-cap burn rejects subsequent valid completion only at threshold",
      invalidsAtCap.every((res) => res.status === 400 && pairingFailed(res.body)) &&
        validAfterBurn.status === 400 &&
        pairingFailed(validAfterBurn.body) &&
        burnGuard.registeredPublicKeys.length === 0,
    );
  } finally {
    await burnGuard.stop();
  }
}

/** Track A rev2 pairing (auth-pairing-spec §3/§5c): drive the real client
 *  against the real mock pairing server, keeping the daemon seed off-wire and
 *  covering completion, fingerprint, status, re-complete, winner, and burn paths. */
async function scenarioAE(): Promise<void> {
  const cfgDir = join(SCRATCH, "pairing-rev2");
  rmSync(cfgDir, { recursive: true, force: true });
  mkdirSync(cfgDir, { recursive: true });
  try {
    await scenarioAEHappyPath(cfgDir);
    await scenarioAEFingerprintMismatchFailClosed(cfgDir);
    await scenarioAEOriginFailClosed(cfgDir);
    await scenarioAEServerDirectRefusals();
    await scenarioAEPendingThenActive(cfgDir);
    await scenarioAEIdempotentRecomplete(cfgDir);
    await scenarioAEWinnerBinding();
    await scenarioAEAttemptCapBurn();
  } finally {
    rmSync(cfgDir, { recursive: true, force: true });
  }
}

async function scenarioALHappyPath(cfgDir: string): Promise<void> {
  const cfgPath = join(cfgDir, "al1-config.json");
  const pairing = new MockPairingServer({
    simplePairing: true,
    tenantId: "acme",
    agentId: "agent-al1",
    keyId: "key-al1",
  });
  const port = await pairing.start();
  const serverUrl = `ws://127.0.0.1:${port}`;
  const deviceCode = pairing.mintSimpleDeviceCode("device-code-al1");
  const tracked = trackingSeedStore();
  let publicKeyHex = "";
  try {
    const res = await connectSimple({
      deviceCode,
      serverUrl,
      hostname: "test-host",
      seedStore: tracked.store,
      configPath: cfgPath,
    });
    const cfg = readPairingConfig(cfgPath);
    const seed = await tracked.store.get("key-al1");
    const publicRaw = seed ? deriveKeypairFromSeed(seed).publicRaw : Buffer.alloc(0);
    publicKeyHex = publicRaw.toString("hex");
    const publicKeyB64u = seed ? b64u(publicRaw) : "NO_PUBLIC_KEY";
    const complete = simpleCompleteBodies(pairing);
    const seedEncodings = seed
      ? [b64u(seed), seed.toString("base64"), seed.toString("hex"), seed.toString("hex").toUpperCase(), JSON.stringify(Array.from(seed))]
      : [];
    const seedLeaked = pairing.requestBodies.some((body) => seedEncodings.some((encoding) => body.includes(encoding)));
    check(
      "AL1 simple happy path persists canonical --url, returned ids, seed under key_id, and keeps seed off-wire",
      cfg?.agentId === "agent-al1" &&
        cfg?.keyId === "key-al1" &&
        cfg?.tenantId === "acme" &&
        cfg?.serverUrl === serverUrl &&
        res.agentId === "agent-al1" &&
        res.keyId === "key-al1" &&
        res.tenantId === "acme" &&
        res.serverUrl === serverUrl &&
        tracked.setKeys.length === 1 &&
        tracked.setKeys[0] === "key-al1" &&
        seed?.length === 32 &&
        complete.length === 1 &&
        complete[0]?.device_code === deviceCode &&
        complete[0]?.public_key === publicKeyB64u &&
        complete[0]?.hostname === "test-host" &&
        pairing.registeredPublicKeys.length === 1 &&
        pairing.registeredPublicKeys[0] === publicKeyB64u &&
        !seedLeaked,
    );
  } finally {
    await pairing.stop();
  }

  const relay = new MockRelay();
  relay.setVerifyAuth({
    agentId: "agent-al1",
    keyId: "key-al1",
    publicKeyHex,
    tenantId: "acme",
    serverOrigin: serverUrl,
  });
  const relayPort = await relay.start(port);
  const client = new RelayClient();
  try {
    const cfg = readPairingConfig(cfgPath);
    if (!cfg) throw new Error("AL1 config missing before handshake");
    await client.connect(serverUrl);
    const signer = await keychainSigner("key-al1", tracked.store);
    const hs = await performHandshake(
      client,
      loadConfig({
        serverUrl: cfg.serverUrl,
        agentId: cfg.agentId,
        keyId: cfg.keyId,
        tenantId: cfg.tenantId,
        dbPath: ":memory:",
      }),
      signer,
      { activeJobs: [], pendingResults: [] },
      { engines: TEST_ENGINE_CAPABILITIES },
    );
    check("AL1b simple pair-then-WSS handshake reaches hello.accepted on the same --url origin", relayPort === port && hs.connectionEpoch === 1);
  } finally {
    client.close();
    await relay.stop();
  }
}

async function scenarioALHostnameSchema(): Promise<void> {
  const pairing = new MockPairingServer({ simplePairing: true });
  await pairing.start();
  try {
    const publicKey = b64u(Buffer.alloc(32, 0x5a));
    if (!validateB64u32(publicKey)) throw new Error("test public key is not canonical");
    const postSimple = async (label: string, body: Record<string, unknown>): Promise<{ status: number; body: unknown }> =>
      postRawPairComplete(pairing.baseUrl(), {
        device_code: pairing.mintSimpleDeviceCode(`device-code-${label}`),
        public_key: publicKey,
        ...body,
      });

    const withoutHostname = await postSimple("al-hostname-absent", {});
    const withHostname = await postSimple("al-hostname-valid", { hostname: "a".repeat(255) });
    const tooLong = await postSimple("al-hostname-too-long", { hostname: "a".repeat(256) });
    const nonString = await postSimple("al-hostname-non-string", { hostname: 42 });
    const extraKey = await postSimple("al-hostname-extra-key", { foo: "bar" });

    check("AL10 simple /pair/complete accepts omitted hostname", withoutHostname.status === 200);
    check("AL10b simple /pair/complete accepts valid hostname metadata", withHostname.status === 200);
    check("AL10c simple /pair/complete rejects hostname longer than 255", tooLong.status !== 200 && pairingFailed(tooLong.body));
    check("AL10d simple /pair/complete rejects non-string hostname", nonString.status !== 200 && pairingFailed(nonString.body));
    check("AL10e simple /pair/complete rejects unknown extra request keys", extraKey.status !== 200 && pairingFailed(extraKey.body));
  } finally {
    await pairing.stop();
  }
}

async function scenarioALCliGate(cfgDir: string): Promise<void> {
  const pairing = new MockPairingServer({ simplePairing: true });
  await pairing.start();
  try {
    const cfgPath = join(cfgDir, "al2-config.json");
    const res = await runConnectCli({
      cfgDir,
      configPath: cfgPath,
      args: ["--config", cfgPath, "--url", `ws://127.0.0.1:${pairing.port}`],
      env: { HUGIN_SIMPLE_PAIRING: "" },
    });
    const output = `${res.stdout}\n${res.stderr}`;
    check(
      "AL2 --url without HUGIN_SIMPLE_PAIRING rejects before stdin/network/config",
      res.status !== 0 &&
        output.includes("simple pairing is disabled; set HUGIN_SIMPLE_PAIRING=1 for dev, or omit --url for rev2") &&
        pairing.requestBodies.length === 0 &&
        readPairingConfig(cfgPath) === null,
    );
  } finally {
    await pairing.stop();
  }
}

async function scenarioALNonCanonicalUrl(cfgDir: string): Promise<void> {
  await expectConnectSimpleReject(
    "AL3 non-canonical --url rejects without seed/config",
    join(cfgDir, "al3-config.json"),
    trackingSeedStore(),
    { deviceCode: "device-code-al3", serverUrl: "ws://relay.example.com/path" },
    "simple pairing relay URL is invalid; provide a canonical dev ws(s):// relay origin",
  );
}

async function scenarioALCapabilityRejects(cfgDir: string): Promise<void> {
  const wrongShapes: unknown[] = [{ simple_pairing: "yes" }, { pairing_mode: "simple" }];
  for (let i = 0; i < wrongShapes.length; i++) {
    const pairing = new MockPairingServer({
      simplePairing: true,
      capabilityBody: wrongShapes[i],
    });
    await pairing.start();
    try {
      const code = pairing.mintSimpleDeviceCode(`device-code-al4-${i}`);
      await expectConnectSimpleReject(
        i === 0
          ? "AL4 capability rejects truthy-but-non-true marker without seed/config"
          : "AL4b capability rejects enum-shaped marker without seed/config",
        join(cfgDir, `al4-${i}-config.json`),
        trackingSeedStore(),
        { deviceCode: code, serverUrl: `ws://127.0.0.1:${pairing.port}` },
        "this relay does not support simple pairing",
      );
      check(`AL4${i === 0 ? "" : "b"} capability rejection stops before /pair/complete`, simpleCompleteBodies(pairing).length === 0);
    } finally {
      await pairing.stop();
    }
  }
}

async function scenarioALCapabilityForwardCompat(cfgDir: string): Promise<void> {
  // A /capability discovery endpoint may grow fields over time; the daemon must
  // still pair as long as `simple_pairing: true` is present (fail-closed on the
  // marker VALUE only, not the whole object shape).
  const pairing = new MockPairingServer({
    simplePairing: true,
    capabilityBody: { simple_pairing: true, protocol_version: "1.0.0", max_devices: 10 },
    agentId: "agent-al4c",
    keyId: "key-al4c",
    tenantId: "acme",
  });
  await pairing.start();
  const cfgPath = join(cfgDir, "al4c-config.json");
  const tracked = trackingSeedStore();
  try {
    const code = pairing.mintSimpleDeviceCode("device-code-al4c");
    const res = await connectSimple({
      deviceCode: code,
      serverUrl: `ws://127.0.0.1:${pairing.port}`,
      seedStore: tracked.store,
      configPath: cfgPath,
    });
    const cfg = readPairingConfig(cfgPath);
    check(
      "AL4c capability with extra fields alongside simple_pairing:true is accepted (forward-compatible)",
      res.agentId === "agent-al4c" &&
        res.keyId === "key-al4c" &&
        cfg?.agentId === "agent-al4c" &&
        cfg?.keyId === "key-al4c" &&
        tracked.setKeys.length === 1 &&
        simpleCompleteBodies(pairing).length === 1,
    );
  } finally {
    await pairing.stop();
  }
}

async function scenarioALMixedModeGuard(cfgDir: string): Promise<void> {
  const pairing = new MockPairingServer({ simplePairing: true });
  await pairing.start();
  try {
    await expectConnectSimpleReject(
      "AL5 hpk1-prefixed payload under --url rejects without seed/config",
      join(cfgDir, "al5-config.json"),
      trackingSeedStore(),
      { deviceCode: "hpk1.not-a-device-code", serverUrl: `ws://127.0.0.1:${pairing.port}` },
      "simple pairing expected a device code, but received a rev2 hpk1 token",
    );
    await expectConnectSimpleReject(
      "AL5b leading-whitespace hpk1 payload under --url rejects without seed/config",
      join(cfgDir, "al5b-config.json"),
      trackingSeedStore(),
      { deviceCode: "  hpk1.not-a-device-code", serverUrl: `ws://127.0.0.1:${pairing.port}` },
      "simple pairing expected a device code, but received a rev2 hpk1 token",
    );
    check("AL5c mixed-mode guard fires before capability probe", pairing.requestBodies.length === 0);
  } finally {
    await pairing.stop();
  }
}

async function scenarioALCompletionRejects(cfgDir: string): Promise<void> {
  const cases: Array<{ label: string; file: string; status: number; body: unknown; error: string }> = [
    {
      label: "AL6 simple /pair/complete non-200 rejects without seed/config",
      file: "al6-config.json",
      status: 500,
      body: { error: "boom" },
      error: "simple pairing completion failed; relay did not return HTTP 200",
    },
    {
      label: "AL7 simple /pair/complete rev2-shaped 202 rejects without seed/config",
      file: "al7-config.json",
      status: 202,
      body: { status: "pending", fingerprint: "A".repeat(43), poll_token: "poll-token" },
      error: "simple pairing refused a rev2 completion response; check relay pairing mode",
    },
    {
      label: "AL8 simple /pair/complete malformed 200 rejects without seed/config",
      file: "al8-config.json",
      status: 200,
      body: { agent_id: "agent-al8", key_id: "bad key", tenant_id: "acme" },
      error: "simple pairing server returned an invalid completion response; re-pair this device",
    },
  ];

  for (let i = 0; i < cases.length; i++) {
    const c = cases[i]!;
    const pairing = new MockPairingServer({
      simplePairing: true,
      simpleCompleteStatus: c.status,
      simpleCompleteBody: c.body,
    });
    await pairing.start();
    try {
      const code = pairing.mintSimpleDeviceCode(`device-code-${c.file}`);
      await expectConnectSimpleReject(
        c.label,
        join(cfgDir, c.file),
        trackingSeedStore(),
        { deviceCode: code, serverUrl: `ws://127.0.0.1:${pairing.port}` },
        c.error,
      );
      check(`AL${6 + i} rejection still sent device_code (+ hostname) in the POST body`, simpleCompleteBodies(pairing).some((body) => body.device_code === code));
    } finally {
      await pairing.stop();
    }
  }
}

async function scenarioALDeviceCodeNotArgv(cfgDir: string): Promise<void> {
  const pairing = new MockPairingServer({
    simplePairing: true,
    simpleCompleteStatus: 500,
    simpleCompleteBody: { error: "intentional" },
  });
  await pairing.start();
  try {
    const cfgPath = join(cfgDir, "al9-config.json");
    const deviceCode = pairing.mintSimpleDeviceCode("device-code-al9-secret");
    const res = await runConnectCli({
      cfgDir,
      configPath: cfgPath,
      args: ["--config", cfgPath, "--url", `ws://127.0.0.1:${pairing.port}`],
      input: `${deviceCode}\n`,
      env: { HUGIN_SIMPLE_PAIRING: "1" },
    });
    const output = `${res.stdout}\n${res.stderr}`;
    check(
      "AL9 device_code is read from stdin and absent from the connect child argv",
      res.status !== 0 &&
        simpleCompleteBodies(pairing).some((body) => body.device_code === deviceCode) &&
        !res.argv.some((arg) => arg.includes(deviceCode)) &&
        !output.includes(deviceCode) &&
        readPairingConfig(cfgPath) === null,
    );
  } finally {
    await pairing.stop();
  }
}

async function scenarioAL(): Promise<void> {
  const cfgDir = join(SCRATCH, "pairing-simple");
  rmSync(cfgDir, { recursive: true, force: true });
  mkdirSync(cfgDir, { recursive: true });
  try {
    await scenarioALHappyPath(cfgDir);
    await scenarioALHostnameSchema();
    await scenarioALCliGate(cfgDir);
    await scenarioALNonCanonicalUrl(cfgDir);
    await scenarioALCapabilityRejects(cfgDir);
    await scenarioALCapabilityForwardCompat(cfgDir);
    await scenarioALMixedModeGuard(cfgDir);
    await scenarioALCompletionRejects(cfgDir);
    await scenarioALDeviceCodeNotArgv(cfgDir);
  } finally {
    rmSync(cfgDir, { recursive: true, force: true });
  }
}

function scenarioAMCanonicalizeDevOrigin(): void {
  const accepted = [
    "ws://100.120.25.112:5173",
    "wss://host.tailnet.ts.net",
    "ws://localhost:8787",
    "ws://127.0.0.1:8787",
  ];
  const rejected = [
    "ws://relay.example.com/path",
    "ws://user@relay.example.com:8787",
    "ws://relay.example.com:8787?x=1",
    "ws://relay.example.com:8787#frag",
    "ws://relay.example.com:0",
    "wss://Host.tailnet.ts.net",
    "ws://999.1.1.1:80",
  ];
  check("AM1 canonicalizeDevOrigin accepts ws/wss dev origins including raw IPs", accepted.every((origin) => canonicalizeDevOrigin(origin) === origin));
  check("AM2 canonicalizeDevOrigin rejects path/userinfo/query/fragment/port0/non-canonical/bad IPv4", rejected.every((origin) => canonicalizeDevOrigin(origin) === null));
  check("AM3 frozen canonicalizeServerOrigin still rejects non-loopback raw ws IP", canonicalizeServerOrigin("ws://100.120.25.112:5173") === null);

  // relayDialUrl: the WS dial gains the C2 agent-connect PATH, but the transcript
  // server_origin (canonicalize of the same serverUrl) stays PATH-LESS. The mock
  // relay accepts an upgrade on any path, so only a pure assertion can guard this
  // split — a wrong path is exactly the 403-then-reconnect bug this fixes.
  check(
    "AM7 relayDialUrl appends the C2 agent-connect path to a bare origin",
    relayDialUrl("ws://100.120.25.112:8004") === "ws://100.120.25.112:8004/api/v1/hugin-agents/connect",
  );
  check(
    "AM8 relayDialUrl joins cleanly over a trailing slash and preserves wss",
    relayDialUrl("wss://relay.example.com/") === "wss://relay.example.com/api/v1/hugin-agents/connect",
  );
  check(
    "AM9 relayDialUrl strips stray query/hash before dialing",
    relayDialUrl("ws://127.0.0.1:8787/?x=1#frag") === "ws://127.0.0.1:8787/api/v1/hugin-agents/connect",
  );
  check(
    "AM10 dial gains a path but the transcript server_origin stays path-less",
    canonicalizeDevOrigin("ws://100.120.25.112:8004") === "ws://100.120.25.112:8004",
  );
}

async function scenarioAMHandshakeDevOrigin(): Promise<void> {
  const rawDevOrigin = "ws://100.120.25.112:5173";

  const acceptingRelay = new MockRelay();
  const acceptingPort = await acceptingRelay.start();
  const acceptingClient = new RelayClient();
  try {
    await acceptingClient.connect(`ws://127.0.0.1:${acceptingPort}`);
    const hs = await performHandshake(
      acceptingClient,
      loadConfig({ serverUrl: rawDevOrigin, allowDevOrigin: true, agentId: "agent-am-dev", dbPath: ":memory:" }),
      devSigner("key-am-dev"),
      { activeJobs: [], pendingResults: [] },
      { engines: TEST_ENGINE_CAPABILITIES },
    );
    check("AM4 allowDevOrigin:true permits raw-IP dev origin transcript and reaches hello.accepted", hs.connectionEpoch === 1);
  } finally {
    acceptingClient.close();
    await acceptingRelay.stop();
  }

  const strictRelay = new MockRelay();
  const strictPort = await strictRelay.start();
  const strictClient = new RelayClient();
  let message = "";
  try {
    await strictClient.connect(`ws://127.0.0.1:${strictPort}`);
    await performHandshake(
      strictClient,
      loadConfig({ serverUrl: rawDevOrigin, allowDevOrigin: false, agentId: "agent-am-strict", dbPath: ":memory:" }),
      devSigner("key-am-strict"),
      { activeJobs: [], pendingResults: [] },
      { engines: TEST_ENGINE_CAPABILITIES },
    );
  } catch (err) {
    message = err instanceof Error ? err.message : String(err);
  } finally {
    strictClient.close();
    await strictRelay.stop();
  }
  check("AM5 allowDevOrigin:false keeps raw-IP dev origin fail-closed", message === `non-canonical serverUrl: ${rawDevOrigin}`);
}

async function scenarioAMCliNonTtyNeedsUrl(cfgDir: string): Promise<void> {
  const cfgPath = join(cfgDir, "am6-config.json");
  const res = await runConnectCli({
    cfgDir,
    configPath: cfgPath,
    args: ["--config", cfgPath],
    input: "device-code-am6\n",
    env: { HUGIN_SIMPLE_PAIRING: "1" },
  });
  const output = `${res.stdout}\n${res.stderr}`;
  check(
    "AM6 gate set + no --url + non-TTY rejects with needs --url and persists nothing",
    res.status !== 0 &&
      output.includes("simple pairing needs --url when input is not a terminal") &&
      readPairingConfig(cfgPath) === null,
  );
}

async function scenarioAM(): Promise<void> {
  const cfgDir = join(SCRATCH, "pairing-simple-rev2");
  rmSync(cfgDir, { recursive: true, force: true });
  mkdirSync(cfgDir, { recursive: true });
  try {
    scenarioAMCanonicalizeDevOrigin();
    await scenarioAMHandshakeDevOrigin();
    await scenarioAMCliNonTtyNeedsUrl(cfgDir);
  } finally {
    rmSync(cfgDir, { recursive: true, force: true });
  }
}

/** Track A robustness (Codex re-review): a duplicate `hello` on an ALREADY-
 *  authenticated connection is ignored — no re-verify, no second hello.accepted.
 *  (`validateInbound` permits handshake types post-auth, so the relay guards it;
 *  cross-connection replay is separately defeated by the per-connection nonce.) */
async function scenarioAF(): Promise<void> {
  let accepts = 0;
  const relay = new MockRelay({ onAccept: () => { accepts++; } });
  const port = await relay.start();
  const serverUrl = `ws://127.0.0.1:${port}`;
  const client = new RelayClient();
  await client.connect(serverUrl);
  const config = loadConfig({ serverUrl, agentId: "agent-af", dbPath: ":memory:" });
  await performHandshake(client, config, devSigner("key-af"), { activeJobs: [], pendingResults: [] }, { engines: TEST_ENGINE_CAPABILITIES });
  await waitUntil(() => accepts >= 1, 3000);
  // Re-send a hello on the SAME authed socket — must NOT be re-accepted.
  client.send(
    parseMessage({
      id: "m-dup", ts: "2026-07-01T00:00:00.000Z", type: "hello",
      protocol_version: PROTOCOL_VERSION, agent_id: "agent-af", agent_version: "0.0.0",
      auth: { challenge_id: "ch-dup", key_id: "key-af", signature: "A".repeat(86), alg: "ed25519" },
      os: { platform: "darwin", arch: "arm64" },
      capabilities: { engines: { claude: { installed: true }, codex: { installed: false } }, project_roots: [] },
      active_jobs: [], pending_results: [],
    }),
  );
  await sleep(250);
  client.close();
  await relay.stop();
  await sleep(50);
  check("AF1 duplicate post-auth hello ignored (exactly one accept)", accepts === 1);
}

/** Track A handshake integrity (Codex final review): a `hello.accepted` the relay
 *  sends BEFORE the daemon's signed hello is DISCARDED — the handshake completes
 *  only on the real post-hello accept (armForAccept), never a premature/replayed
 *  one. The mock sends a premature accept{epoch:999}; the real post-hello accept
 *  carries epoch 1, so completing at 1 proves the premature one was dropped. */
async function scenarioAG(): Promise<void> {
  const relay = new MockRelay({ prematureAcceptEpoch: 999 });
  const port = await relay.start();
  const serverUrl = `ws://127.0.0.1:${port}`;
  const client = new RelayClient();
  await client.connect(serverUrl);
  const config = loadConfig({ serverUrl, agentId: "agent-ag", dbPath: ":memory:" });
  const hs = await performHandshake(client, config, devSigner("key-ag"), { activeJobs: [], pendingResults: [] }, { engines: TEST_ENGINE_CAPABILITIES });
  client.close();
  await relay.stop();
  await sleep(50);
  check("AG1 premature hello.accepted discarded — handshake used the post-hello accept", hs.connectionEpoch === 1);
}

type VersionHandshakeResult =
  | { ok: true; negotiatedVersion: string }
  | { ok: false; message: string };

async function versionHandshake(opts: {
  agentId: string;
  protocolVersion?: string;
  supportedVersions?: readonly string[];
  forceNegotiatedVersion?: string;
}): Promise<VersionHandshakeResult> {
  const relay = new MockRelay({
    ...(opts.supportedVersions === undefined ? {} : { supportedVersions: opts.supportedVersions }),
    ...(opts.forceNegotiatedVersion === undefined ? {} : { forceNegotiatedVersion: opts.forceNegotiatedVersion }),
  });
  const port = await relay.start();
  const serverUrl = `ws://127.0.0.1:${port}`;
  const client = new RelayClient();
  try {
    await client.connect(serverUrl);
    const hs = await performHandshake(
      client,
      loadConfig({
        serverUrl,
        agentId: opts.agentId,
        dbPath: ":memory:",
        ...(opts.protocolVersion === undefined ? {} : { protocolVersion: opts.protocolVersion }),
      }),
      devSigner(`key-${opts.agentId}`),
      { activeJobs: [], pendingResults: [] },
      { engines: TEST_ENGINE_CAPABILITIES },
    );
    return { ok: true, negotiatedVersion: hs.negotiatedVersion };
  } catch (err) {
    return { ok: false, message: err instanceof Error ? err.message : String(err) };
  } finally {
    client.close();
    await relay.stop();
    await sleep(50);
  }
}

/** Protocol-version negotiation scaffolding: the daemon can advertise v1 or v2,
 *  and the relay cleanly rejects unsupported majors without authenticating. */
async function scenarioAN(): Promise<void> {
  const prevConfig = process.env.HUGIND_CONFIG;
  try {
    process.env.HUGIND_CONFIG = join(SCRATCH, "missing-hugind-config.json");
    const baseEnv = {
      HUGIND_SERVER_URL: "ws://127.0.0.1:1",
      HUGIND_AGENT_ID: "agent-an-env",
    } as NodeJS.ProcessEnv;
    const unset = loadConfigFromEnv(baseEnv);
    const v1 = loadConfigFromEnv({ ...baseEnv, HUGIND_PROTOCOL_VERSION: PROTOCOL_VERSION } as NodeJS.ProcessEnv);
    const v2 = loadConfigFromEnv({ ...baseEnv, HUGIND_PROTOCOL_VERSION: PROTOCOL_VERSION_V2 } as NodeJS.ProcessEnv);
    check(
      "AN0 HUGIND_PROTOCOL_VERSION unset defaults to 2.0.0; env 1.0.0 downgrades; env 2.0.0 stays v2",
      unset.protocolVersion === PROTOCOL_VERSION_V2 &&
        v1.protocolVersion === PROTOCOL_VERSION &&
        v2.protocolVersion === PROTOCOL_VERSION_V2,
    );
  } finally {
    if (prevConfig !== undefined) process.env.HUGIND_CONFIG = prevConfig;
    else delete process.env.HUGIND_CONFIG;
  }

  const detectBase = mkdtempSync(join(tmpdir(), "hugind-e2e-detect-"));
  try {
    const mkVersionCli = (name: string, output: string): string => {
      const p = join(detectBase, name);
      writeFileSync(
        p,
        `#!/usr/bin/env node
if (process.argv[2] === '--version') {
  console.log(${JSON.stringify(output)});
  process.exit(0);
}
process.exit(1);
`,
      );
      chmodSync(p, 0o755);
      return p;
    };
    const detected = await detectEngineCapabilities({
      claudeCommand: mkVersionCli("claude.js", "claude-code 1.2.3"),
      codexCommand: mkVersionCli("codex.js", "codex-cli 4.5.6"),
      timeoutMs: 1_000,
    });
    check(
      "AN0b engine detection runs --version once and parses versions",
      detected.claude.installed === true &&
        detected.claude.version === "1.2.3" &&
        detected.codex.installed === true &&
        detected.codex.version === "4.5.6",
    );
  } finally {
    rmSync(detectBase, { recursive: true, force: true });
  }

  const customCaps: EngineCapabilities = { claude: { installed: false }, codex: { installed: true, version: "9.8.7", logged_in: true } };
  const capSeen: { helloCaps?: { engines: EngineCapabilities; [key: string]: unknown } } = {};
  const capRelay = new MockRelay({
    onAccept: (ctx) => {
      capSeen.helloCaps = ctx.hello.capabilities;
    },
  });
  const capPort = await capRelay.start();
  const capUrl = `ws://127.0.0.1:${capPort}`;
  const capClient = new RelayClient();
  try {
    await capClient.connect(capUrl);
    await performHandshake(
      capClient,
      loadConfig({ serverUrl: capUrl, agentId: "agent-an-caps", dbPath: ":memory:" }),
      devSigner("key-agent-an-caps"),
      { activeJobs: [], pendingResults: [] },
      { engines: customCaps },
    );
  } finally {
    capClient.close();
    await capRelay.stop();
    await sleep(50);
  }
  const helloCaps = capSeen.helloCaps;
  check(
    "AN0c hello.capabilities uses detected engines and keeps frozen v1 schema",
    JSON.stringify(helloCaps?.engines) === JSON.stringify(customCaps) && helloCaps !== undefined && !("sessions" in helloCaps),
  );

  const an1 = await versionHandshake({
    agentId: "agent-an1",
    protocolVersion: PROTOCOL_VERSION,
    supportedVersions: [PROTOCOL_VERSION],
  });
  check("AN1 explicit-v1 daemon + v1-only relay negotiates 1.0.0", an1.ok && an1.negotiatedVersion === PROTOCOL_VERSION);

  const an2 = await versionHandshake({
    agentId: "agent-an2",
    protocolVersion: PROTOCOL_VERSION_V2,
    supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
  });
  check("AN2 v2 daemon + dual-support relay negotiates 2.0.0", an2.ok && an2.negotiatedVersion === PROTOCOL_VERSION_V2);

  const an3 = await versionHandshake({
    agentId: "agent-an3",
    protocolVersion: PROTOCOL_VERSION_V2,
    supportedVersions: [PROTOCOL_VERSION],
  });
  check("AN3 v2 daemon + v1-only relay fails with unsupported_version", !an3.ok && an3.message.includes("hello.rejected: unsupported_version"));

  const an4 = await versionHandshake({ agentId: "agent-an4" });
  check("AN4 default daemon + default relay negotiates 2.0.0", an4.ok && an4.negotiatedVersion === PROTOCOL_VERSION_V2);

  const an5 = await versionHandshake({
    agentId: "agent-an5",
    forceNegotiatedVersion: "3.0.0",
  });
  check(
    "AN5 daemon rejects a relay-forced unsupported negotiated_version",
    !an5.ok && an5.message.includes('relay negotiated an unsupported version "3.0.0"'),
  );
}

/** Phase 2a AO: default v2 session.list plumbing remains fail-closed; without
 *  an injected enumerator the daemon returns an empty list on negotiated v2. */
async function scenarioAO(): Promise<void> {
  type SessionListResponse = Extract<MessageV2, { type: "session.list.response" }>;

  const ao1 = { response: null as SessionListResponse | null };
  const ao1Relay = new MockRelay({
    supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
    sendSessionListAfterAccept: true,
    onSessionListResponse: (m) => {
      ao1.response = m;
    },
  });
  const ao1Port = await ao1Relay.start();
  const ao1Daemon = new Daemon(
    loadConfig({
      serverUrl: `ws://127.0.0.1:${ao1Port}`,
      agentId: "agent-ao1",
      dbPath: ":memory:",
      protocolVersion: PROTOCOL_VERSION_V2,
    }),
    devSigner("key-ao1"),
    new FakeEngine({ events: [] }),
  );
  try {
    void ao1Daemon.start().catch(() => {});
    await waitUntil(() => ao1.response !== null, 5000);
  } finally {
    ao1Daemon.stop();
    await ao1Relay.stop();
    await sleep(50);
  }
  const ao1Response = ao1.response;
  check(
    "AO1 v2 session.list.request returns the default empty response",
    ao1Response?.request_id === "session-list-e2e" &&
      Array.isArray(ao1Response.sessions) &&
      ao1Response.sessions.length === 0 &&
      ao1Response.next_cursor === null &&
      ao1Response.truncated === false,
  );

  let ao2Accepted = 0;
  const ao2 = { response: null as SessionListResponse | null };
  const ao2Relay = new MockRelay({
    supportedVersions: [PROTOCOL_VERSION],
    sendSessionListAfterAccept: true,
    onAccept: () => {
      ao2Accepted++;
    },
    onSessionListResponse: (m) => {
      ao2.response = m;
    },
  });
  const ao2Port = await ao2Relay.start();
  const ao2Daemon = new Daemon(
    loadConfig({
      serverUrl: `ws://127.0.0.1:${ao2Port}`,
      agentId: "agent-ao2",
      dbPath: ":memory:",
      // Explicit v1 daemon: AO2 verifies a v1-NEGOTIATED connection gates
      // session.* (the daemon default is now v2 — issue #12 — so pin v1 here to
      // negotiate 1.0.0 with this v1-only relay and exercise the gate).
      protocolVersion: PROTOCOL_VERSION,
    }),
    devSigner("key-ao2"),
    new FakeEngine({ events: [] }),
  );
  try {
    void ao2Daemon.start().catch(() => {});
    await waitUntil(() => ao2Accepted > 0, 5000);
    await sleep(300);
  } finally {
    ao2Daemon.stop();
    await ao2Relay.stop();
    await sleep(50);
  }
  const ao2Frame = JSON.stringify({
    id: "ao2-direct",
    ts: "2026-07-01T00:00:00.000Z",
    type: "session.list.request",
    request_id: "session-list-e2e",
  });
  const ao2Decode = decodeInbound(ao2Frame, { receiver: "agent", authed: true });
  check("AO2 v1 decoder rejects session.list.request as invalid_message", !ao2Decode.ok && ao2Decode.code === "invalid_message");
  check("AO2 v1 daemon does not reply with session.list.response", ao2Accepted > 0 && ao2.response === null);
}

interface SessionFixtureStore {
  base: string;
  allowRoot: string;
  claudeProjectsDir: string;
  codexSessionsDir: string;
  nowMs: number;
}

function writeJsonlFixture(path: string, records: readonly unknown[], mtimeMs: number): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${records.map((r) => JSON.stringify(r)).join("\n")}\n`);
  const mtime = new Date(mtimeMs);
  utimesSync(path, mtime, mtime);
}

function createSessionFixtureStore(): SessionFixtureStore {
  const base = mkdtempSync(join(tmpdir(), "hugind-e2e-sessions-"));
  const allowRoot = join(base, "allowed");
  const outsideRoot = join(base, "outside");
  const claudeCwd = join(allowRoot, "repo-claude");
  const claudeSidechainCwd = join(allowRoot, "repo-claude-sidechain");
  const codexCwd = join(allowRoot, "repo-codex");
  const codexSubagentCwd = join(allowRoot, "repo-codex-subagent");
  const outsideCwd = join(outsideRoot, "repo-outside");
  const claudeProjectsDir = join(base, "claude", "projects");
  const codexSessionsDir = join(base, "codex", "sessions");
  const nowMs = Date.parse("2026-07-05T12:00:00.000Z");
  mkdirSync(claudeCwd, { recursive: true });
  mkdirSync(claudeSidechainCwd, { recursive: true });
  mkdirSync(codexCwd, { recursive: true });
  mkdirSync(codexSubagentCwd, { recursive: true });
  mkdirSync(outsideCwd, { recursive: true });

  writeJsonlFixture(
    join(claudeProjectsDir, "encoded-claude", "11111111-1111-4111-8111-111111111111.jsonl"),
    [
      { type: "system", timestamp: "2026-07-05T10:00:00.000Z", message: "init" },
      { type: "system", timestamp: "2026-07-05T10:00:01.000Z", cwd: claudeCwd, gitBranch: "main", version: "1.2.3" },
      { type: "ai-title", timestamp: "2026-07-05T10:00:02.000Z", title: "Claude fixture title\nwith extra spacing" },
      { type: "user", timestamp: "2026-07-05T10:00:03.000Z", isSidechain: false, message: { role: "user", content: "SENSITIVE_PROMPT_CLAUDE" } },
    ],
    nowMs - 5 * 60 * 1000,
  );

  writeJsonlFixture(
    join(claudeProjectsDir, "encoded-claude", "77777777-7777-4777-8777-777777777777.jsonl"),
    [
      { type: "system", timestamp: "2026-07-05T10:02:00.000Z", cwd: claudeSidechainCwd, gitBranch: "sidechain", version: "1.2.4" },
      { type: "ai-title", timestamp: "2026-07-05T10:02:01.000Z", title: "Claude top-level sidechain-content fixture" },
      { type: "user", timestamp: "2026-07-05T10:02:02.000Z", isSidechain: true, message: { role: "user", content: "SENSITIVE_SIDECHAIN_PROMPT" } },
      { type: "assistant", timestamp: "2026-07-05T10:02:03.000Z", isSidechain: true, message: { role: "assistant", content: "SENSITIVE_SIDECHAIN_REPLY" } },
    ],
    nowMs - 20 * 60 * 1000,
  );

  writeJsonlFixture(
    join(codexSessionsDir, "2026", "07", "05", "rollout-2026-07-05T10-00-00-22222222-2222-4222-8222-222222222222.jsonl"),
    [
      {
        type: "session_meta",
        payload: {
          id: "codex-fixture-session",
          cwd: codexCwd,
          cli_version: "0.4.5",
          source: "exec",
          timestamp: "2026-07-05T09:30:00.000Z",
          base_instructions: "BASE_INSTRUCTIONS_SECRET",
        },
      },
      {
        type: "event_msg",
        payload: {
          type: "user_message",
          message: "<permissions instructions>\nSENSITIVE_PERMISSIONS_SECRET\n</permissions instructions>\nCodex fixture title with a concise request",
        },
      },
      { type: "event_msg", payload: { type: "assistant_message", message: "ASSISTANT_OUTPUT_SECRET" } },
    ],
    nowMs - 30 * 60 * 1000,
  );

  writeJsonlFixture(
    join(codexSessionsDir, "2026", "07", "05", "rollout-2026-07-05T10-03-00-88888888-8888-4888-8888-888888888888.jsonl"),
    [
      {
        type: "session_meta",
        payload: {
          id: "codex-subagent-session",
          cwd: codexSubagentCwd,
          cli_version: "0.4.6",
          source: { subagent: "review" },
          timestamp: "2026-07-05T10:03:00.000Z",
          base_instructions: "BASE_INSTRUCTIONS_SUBAGENT_SECRET",
        },
      },
      {
        type: "event_msg",
        payload: {
          type: "user_message",
          message: "SENSITIVE_CODEX_SUBAGENT_PROMPT",
        },
      },
      { type: "event_msg", payload: { type: "assistant_message", message: "SENSITIVE_CODEX_SUBAGENT_REPLY" } },
    ],
    nowMs - 6 * 60 * 1000,
  );

  writeJsonlFixture(
    join(
      claudeProjectsDir,
      "encoded-claude",
      "11111111-1111-4111-8111-111111111111",
      "subagents",
      "agent-a07f1234567890abcdef1234567890ab.jsonl",
    ),
    [
      {
        parentUuid: "11111111-1111-4111-8111-111111111111",
        isSidechain: true,
        agentId: "agent-a07f1234567890abcdef1234567890ab",
        type: "system",
        message: "subagent init",
        cwd: claudeCwd,
        sessionId: "11111111-1111-4111-8111-111111111111",
        timestamp: "2026-07-05T10:05:00.000Z",
        gitBranch: "nested",
        version: "1.2.5",
      },
      {
        parentUuid: "11111111-1111-4111-8111-111111111111",
        isSidechain: true,
        agentId: "agent-a07f1234567890abcdef1234567890ab",
        type: "ai-title",
        cwd: claudeCwd,
        sessionId: "11111111-1111-4111-8111-111111111111",
        timestamp: "2026-07-05T10:05:01.000Z",
        title: "Claude nested subagent fixture",
      },
      {
        parentUuid: "11111111-1111-4111-8111-111111111111",
        isSidechain: true,
        agentId: "agent-a07f1234567890abcdef1234567890ab",
        type: "user",
        cwd: claudeCwd,
        sessionId: "11111111-1111-4111-8111-111111111111",
        timestamp: "2026-07-05T10:05:02.000Z",
        message: { role: "user", content: "SENSITIVE_CLAUDE_SUBAGENT_PROMPT" },
      },
      {
        parentUuid: "11111111-1111-4111-8111-111111111111",
        isSidechain: true,
        agentId: "agent-a07f1234567890abcdef1234567890ab",
        type: "assistant",
        cwd: claudeCwd,
        sessionId: "11111111-1111-4111-8111-111111111111",
        timestamp: "2026-07-05T10:05:03.000Z",
        message: { role: "assistant", content: "SENSITIVE_CLAUDE_SUBAGENT_REPLY" },
      },
    ],
    nowMs - 2 * 60 * 1000,
  );

  writeJsonlFixture(
    join(claudeProjectsDir, "encoded-outside", "44444444-4444-4444-8444-444444444444.jsonl"),
    [
      { type: "system", timestamp: "2026-07-05T10:10:00.000Z", cwd: outsideCwd, gitBranch: "outside", version: "8.8.8" },
      { type: "ai-title", timestamp: "2026-07-05T10:10:01.000Z", title: "Outside should not appear" },
    ],
    nowMs - 1 * 60 * 1000,
  );

  return { base, allowRoot, claudeProjectsDir, codexSessionsDir, nowMs };
}

function fixtureEnumerator(
  fx: SessionFixtureStore,
  allowlist: readonly string[] = [fx.allowRoot],
  overrides: Partial<Pick<SessionEnumeratorOpts, "maxSubagentFiles">> = {},
): SessionEnumerator {
  return new SessionEnumerator({
    claudeProjectsDir: fx.claudeProjectsDir,
    codexSessionsDir: fx.codexSessionsDir,
    allowlist,
    now: () => fx.nowMs,
    ...overrides,
  });
}

function byEngine(sessions: readonly SessionInfo[], engine: "claude" | "codex"): SessionInfo | null {
  return sessions.find((s) => s.engine === engine) ?? null;
}

const SESSION_ID_RE = /^s_[0-9a-f]{32}$/;

async function scenarioAP(): Promise<void> {
  type SessionListResponse = Extract<MessageV2, { type: "session.list.response" }>;
  const fx = createSessionFixtureStore();
  try {
    const enumerator = fixtureEnumerator(fx);
    const listed = enumerator.list({});
    const sessions = listed.sessions;
    const claude = byEngine(sessions, "claude");
    const codex = byEngine(sessions, "codex");
    const claudeTopLevelSidechainMain = sessions.find(
      (s) => s.engine === "claude" && s.title === "Claude top-level sidechain-content fixture",
    );

    check(
      "AP1 enumerator lists allowlisted claude + codex metadata",
      sessions.length === 3 &&
        claude?.cwd === "repo-claude" &&
        claude.git_branch === "main" &&
        claude.cli_version === "1.2.3" &&
        claude.title === "Claude fixture title with extra spacing" &&
        claude.created_at === "2026-07-05T10:00:00.000Z" &&
        claude.msg_count === 4 &&
        claude.active === true &&
        claude.is_subagent === false &&
        codex?.cwd === "repo-codex" &&
        codex.git_branch === null &&
        codex.cli_version === "0.4.5" &&
        codex.title === "codex · repo-codex" &&
        codex.created_at === "2026-07-05T09:30:00.000Z" &&
        codex.msg_count === 3 &&
        codex.active === false &&
        codex.is_subagent === false,
    );

    const withSubagents = enumerator.list({ filter: { include_subagents: true } }).sessions;
    const claudeNestedSubagent = withSubagents.find((s) => s.engine === "claude" && s.title === "Claude nested subagent fixture");
    const codexSubagent = withSubagents.find((s) => s.engine === "codex" && s.cwd === "repo-codex-subagent");
    const includedClaudeMain = withSubagents.find((s) => s.handle === claude?.handle);
    const includedClaudeTopLevelSidechainMain = withSubagents.find((s) => s.handle === claudeTopLevelSidechainMain?.handle);
    const includedCodexMain = withSubagents.find((s) => s.handle === codex?.handle);
    check(
      "AP1b session.list defaults exclude nested claude and codex subagents; include_subagents restores them",
      sessions.length === 3 &&
        sessions.every((s) => s.is_subagent === false) &&
        !sessions.some((s) => s.title === "Claude nested subagent fixture") &&
        !sessions.some((s) => s.cwd === "repo-codex-subagent") &&
        withSubagents.length === 5 &&
        includedClaudeMain?.is_subagent === false &&
        includedClaudeTopLevelSidechainMain?.is_subagent === false &&
        includedCodexMain?.is_subagent === false &&
        claudeNestedSubagent?.is_subagent === true &&
        claudeNestedSubagent.cwd === "repo-claude" &&
        claudeNestedSubagent.git_branch === "nested" &&
        claudeNestedSubagent.cli_version === "1.2.5" &&
        claudeNestedSubagent.msg_count === 4 &&
        codexSubagent?.is_subagent === true &&
        codexSubagent.cli_version === "0.4.6" &&
        withSubagents.filter((s) => s.is_subagent).length === 2,
    );
    check(
      "AP1c claude top-level UUID file with isSidechain records is classified as main by location",
      claudeTopLevelSidechainMain?.is_subagent === false &&
        claudeTopLevelSidechainMain.cwd === "repo-claude-sidechain" &&
        claudeTopLevelSidechainMain.git_branch === "sidechain" &&
        claudeTopLevelSidechainMain.msg_count === 4,
    );

    const codexOnly = enumerator.list({ filter: { engine: "codex" } }).sessions;
    const activeOnly = enumerator.list({ filter: { active_only: true } }).sessions;
    const cwdPrefixed = enumerator.list({ filter: { cwd_prefix: "repo-claude" } }).sessions;
    const recentlyUpdated = enumerator.list({ filter: { updated_after: new Date(fx.nowMs - 10 * 60 * 1000).toISOString() } }).sessions;
    check(
      "AP1 filters honor engine, cwd_prefix, active_only, and updated_after",
      codexOnly.length === 1 &&
        codexOnly[0]?.engine === "codex" &&
        activeOnly.length === 1 &&
        activeOnly[0]?.engine === "claude" &&
        cwdPrefixed.length === 1 &&
        cwdPrefixed[0]?.engine === "claude" &&
        recentlyUpdated.length === 1 &&
        recentlyUpdated[0]?.engine === "claude",
    );

    const serialized = JSON.stringify(sessions);
    const serializedWithSubagents = JSON.stringify(withSubagents);
    const emptyAllowlist = fixtureEnumerator(fx, []).list({});
    check(
      "AP2 out-of-allowlist sessions excluded and empty allowlist returns empty",
      !serialized.includes("Outside should not appear") && emptyAllowlist.sessions.length === 0 && emptyAllowlist.truncated === false,
    );
    check(
      "AP3 default list excludes nested claude and codex subagent logs",
      !serialized.includes("Claude nested subagent fixture") && !serialized.includes("repo-codex-subagent"),
    );
    check(
      "AP4 response is redacted metadata only",
      !serializedWithSubagents.includes("SENSITIVE_PROMPT_CLAUDE") &&
        !serializedWithSubagents.includes("Codex fixture title with a concise request") &&
        !serializedWithSubagents.includes("SENSITIVE_PERMISSIONS_SECRET") &&
        !serializedWithSubagents.includes("ASSISTANT_OUTPUT_SECRET") &&
        !serializedWithSubagents.includes("BASE_INSTRUCTIONS_SECRET") &&
        !serializedWithSubagents.includes("SENSITIVE_SIDECHAIN_PROMPT") &&
        !serializedWithSubagents.includes("SENSITIVE_SIDECHAIN_REPLY") &&
        !serializedWithSubagents.includes("SENSITIVE_CLAUDE_SUBAGENT_PROMPT") &&
        !serializedWithSubagents.includes("SENSITIVE_CLAUDE_SUBAGENT_REPLY") &&
        !serializedWithSubagents.includes("BASE_INSTRUCTIONS_SUBAGENT_SECRET") &&
        !serializedWithSubagents.includes("SENSITIVE_CODEX_SUBAGENT_PROMPT") &&
        !serializedWithSubagents.includes("SENSITIVE_CODEX_SUBAGENT_REPLY") &&
        !serializedWithSubagents.includes(fx.base) &&
        withSubagents.every((s) => typeof s.is_subagent === "boolean" && !("content" in s) && !("path" in s)),
    );

    const freshSessions = fixtureEnumerator(fx).list({}).sessions;
    const freshClaude = byEngine(freshSessions, "claude");
    const freshCodex = byEngine(freshSessions, "codex");
    check(
      "AP4b session_id is opaque, stable, and distinct from handles",
      sessions.every((s) => SESSION_ID_RE.test(s.session_id) && s.session_id !== s.handle) &&
        claude?.session_id !== codex?.session_id &&
        freshClaude?.session_id === claude?.session_id &&
        freshCodex?.session_id === codex?.session_id &&
        freshClaude?.handle !== claude?.handle &&
        freshCodex?.handle !== codex?.handle &&
        !serialized.includes("11111111-1111-4111-8111-111111111111") &&
        !serialized.includes("codex-fixture-session") &&
        !serialized.includes(join(fx.allowRoot, "repo-claude")) &&
        !serialized.includes(join(fx.allowRoot, "repo-codex")),
    );

    const page1 = enumerator.list({ page: { limit: 1 } });
    const page2 = enumerator.list({ page: { limit: 1, cursor: page1.next_cursor ?? undefined } });
    const page3 = enumerator.list({ page: { limit: 1, cursor: page2.next_cursor ?? undefined } });
    const page2Again = enumerator.list({ page: { limit: 1, cursor: page1.next_cursor ?? undefined } });
    check(
      "AP5 pagination limit and cursor are deterministic",
      page1.sessions.length === 1 &&
        page1.truncated === true &&
        typeof page1.next_cursor === "string" &&
        page2.sessions.length === 1 &&
        page2.truncated === true &&
        typeof page2.next_cursor === "string" &&
        page3.sessions.length === 1 &&
        page3.truncated === false &&
        page3.next_cursor === null &&
        page1.sessions[0]?.handle !== page2.sessions[0]?.handle &&
        page1.sessions[0]?.handle !== page3.sessions[0]?.handle &&
        page2.sessions[0]?.handle !== page3.sessions[0]?.handle &&
        page2Again.sessions[0]?.handle === page2.sessions[0]?.handle,
    );

    const ap6 = { response: null as SessionListResponse | null };
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionListAfterAccept: true,
      onSessionListResponse: (m) => {
        ap6.response = m;
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-ap6",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx.allowRoot],
      }),
      devSigner("key-ap6"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx),
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => ap6.response !== null, 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    const ap6Sessions = ap6.response?.sessions ?? [];
    check(
      "AP6 v2 daemon replies over the wire with enumerated sessions",
      ap6.response?.request_id === "session-list-e2e" &&
        ap6Sessions.length === 3 &&
        ap6Sessions.every((s) => s.is_subagent === false) &&
        byEngine(ap6Sessions, "claude")?.cwd === "repo-claude" &&
        byEngine(ap6Sessions, "codex")?.cwd === "repo-codex",
    );

    const capSubagentDir = join(
      fx.claudeProjectsDir,
      "encoded-claude",
      "11111111-1111-4111-8111-111111111111",
      "subagents",
    );
    for (const i of [1, 2]) {
      writeJsonlFixture(
        join(capSubagentDir, `agent-cap-extra-${i}.jsonl`),
        [
          {
            parentUuid: "11111111-1111-4111-8111-111111111111",
            isSidechain: true,
            agentId: `agent-cap-extra-${i}`,
            type: "system",
            cwd: join(fx.allowRoot, "repo-claude"),
            sessionId: "11111111-1111-4111-8111-111111111111",
            timestamp: `2026-07-05T10:06:0${i}.000Z`,
            gitBranch: "nested",
            version: "1.2.5",
          },
          {
            parentUuid: "11111111-1111-4111-8111-111111111111",
            isSidechain: true,
            agentId: `agent-cap-extra-${i}`,
            type: "ai-title",
            cwd: join(fx.allowRoot, "repo-claude"),
            sessionId: "11111111-1111-4111-8111-111111111111",
            timestamp: `2026-07-05T10:06:1${i}.000Z`,
            title: `Claude capped subagent fixture ${i}`,
          },
          {
            parentUuid: "11111111-1111-4111-8111-111111111111",
            isSidechain: true,
            agentId: `agent-cap-extra-${i}`,
            type: "user",
            cwd: join(fx.allowRoot, "repo-claude"),
            sessionId: "11111111-1111-4111-8111-111111111111",
            timestamp: `2026-07-05T10:06:2${i}.000Z`,
            message: { role: "user", content: `SENSITIVE_CLAUDE_CAPPED_SUBAGENT_${i}` },
          },
        ],
        fx.nowMs - (70 + i) * 1000,
      );
    }
    const uncappedSubagents = fixtureEnumerator(fx).list({ filter: { include_subagents: true }, page: { limit: 256 } });
    const cappedSubagents = fixtureEnumerator(fx, [fx.allowRoot], { maxSubagentFiles: 2 }).list({
      filter: { include_subagents: true },
      page: { limit: 256 },
    });
    const uncappedClaudeSubagentCount = uncappedSubagents.sessions.filter((s) => s.engine === "claude" && s.is_subagent).length;
    const cappedClaudeSubagentCount = cappedSubagents.sessions.filter((s) => s.engine === "claude" && s.is_subagent).length;
    check(
      "AP7 claude subagent scan cap reports truncation without changing pagination cursor semantics",
      uncappedSubagents.truncated === false &&
        uncappedClaudeSubagentCount === 3 &&
        cappedSubagents.truncated === true &&
        cappedSubagents.next_cursor === null &&
        cappedClaudeSubagentCount < uncappedClaudeSubagentCount,
    );
  } finally {
    rmSync(fx.base, { recursive: true, force: true });
  }
}

async function scenarioAW(): Promise<void> {
  type SessionHistoryResponse = Extract<MessageV2, { type: "session.history.response" }>;
  type SessionError = Extract<MessageV2, { type: "session.error" }>;

  const fx1 = createSessionFixtureStore();
  try {
    const enumerator = fixtureEnumerator(fx1);
    const handle = byEngine(enumerator.list({}).sessions, "claude")?.handle;
    const aw1 = { response: null as SessionHistoryResponse | null, error: null as SessionError | null };
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionHistoryAfterAccept: { request_id: "aw1-history", handle: handle ?? "missing", limit: 5 },
      onSessionHistoryResponse: (m) => {
        aw1.response = m;
      },
      onSessionError: (m) => {
        aw1.error = m;
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-aw1",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx1.allowRoot],
      }),
      devSigner("key-aw1"),
      new FakeEngine({ events: [] }),
      true,
      enumerator,
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => aw1.response !== null || aw1.error !== null, 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    const first = aw1.response?.entries[0];
    check(
      "AW1 v2 session.history.request returns entries for a valid handle",
      typeof handle === "string" &&
        aw1.error === null &&
        aw1.response?.request_id === "aw1-history" &&
        Array.isArray(aw1.response.entries) &&
        aw1.response.entries.length > 0 &&
        typeof first?.entry_id === "string" &&
        first.entry_id.length > 0 &&
        (first?.role === "user" || first?.role === "assistant") &&
        typeof first?.content === "string",
    );
  } finally {
    rmSync(fx1.base, { recursive: true, force: true });
  }

  const fx2 = createSessionFixtureStore();
  try {
    const aw2 = { response: null as SessionHistoryResponse | null, error: null as SessionError | null };
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionHistoryAfterAccept: { request_id: "aw2-history", handle: "h_missing" },
      onSessionHistoryResponse: (m) => {
        aw2.response = m;
      },
      onSessionError: (m) => {
        aw2.error = m;
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-aw2",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx2.allowRoot],
      }),
      devSigner("key-aw2"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx2),
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => aw2.error !== null, 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AW2 bogus history handle returns session.error handle_invalid",
      aw2.error?.request_id === "aw2-history" && aw2.error.code === "handle_invalid" && aw2.response === null,
    );
  } finally {
    rmSync(fx2.base, { recursive: true, force: true });
  }

  const fx3 = createSessionFixtureStore();
  try {
    const enumerator = fixtureEnumerator(fx3);
    const handle = byEngine(enumerator.list({}).sessions, "claude")?.handle;
    const aw3 = { response: null as SessionHistoryResponse | null, error: null as SessionError | null };
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionHistoryAfterAccept: { request_id: "aw3-history", handle: handle ?? "missing", cursor: "not a cursor!", limit: 2 },
      onSessionHistoryResponse: (m) => {
        aw3.response = m;
      },
      onSessionError: (m) => {
        aw3.error = m;
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-aw3",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx3.allowRoot],
      }),
      devSigner("key-aw3"),
      new FakeEngine({ events: [] }),
      true,
      enumerator,
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => aw3.error !== null, 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AW3 malformed history cursor returns session.error cursor_invalid",
      typeof handle === "string" && aw3.error?.request_id === "aw3-history" && aw3.error.code === "cursor_invalid" && aw3.response === null,
    );
  } finally {
    rmSync(fx3.base, { recursive: true, force: true });
  }

  let aw4Accepted = 0;
  const aw4 = { response: null as SessionHistoryResponse | null };
  const relay = new MockRelay({
    supportedVersions: [PROTOCOL_VERSION],
    sendSessionHistoryAfterAccept: { request_id: "aw4-history", handle: "h_missing" },
    onAccept: () => {
      aw4Accepted++;
    },
    onSessionHistoryResponse: (m) => {
      aw4.response = m;
    },
  });
  const port = await relay.start();
  const daemon = new Daemon(
    loadConfig({
      serverUrl: `ws://127.0.0.1:${port}`,
      agentId: "agent-aw4",
      dbPath: ":memory:",
      protocolVersion: PROTOCOL_VERSION,
    }),
    devSigner("key-aw4"),
    new FakeEngine({ events: [] }),
  );
  try {
    void daemon.start().catch(() => {});
    await waitUntil(() => aw4Accepted > 0, 5000);
    await sleep(300);
  } finally {
    daemon.stop();
    await relay.stop();
    await sleep(50);
  }
  const aw4Frame = JSON.stringify({
    id: "aw4-direct",
    ts: "2026-07-01T00:00:00.000Z",
    type: "session.history.request",
    request_id: "aw4-history",
    handle: "h_missing",
  });
  const aw4Decode = decodeInbound(aw4Frame, { receiver: "agent", authed: true });
  check("AW4 v1 decoder rejects session.history.request as invalid_message", !aw4Decode.ok && aw4Decode.code === "invalid_message");
  check("AW4 v1 daemon does not reply with session.history.response", aw4Accepted > 0 && aw4.response === null);
}

function jsonlFixture(records: readonly unknown[]): string {
  return `${records.map((r) => JSON.stringify(r)).join("\n")}\n`;
}

function scenarioAV(): void {
  const claudeSessionId = "claude-av-session";
  const codexSessionId = "codex-av-session";
  const longContent = "C".repeat(HISTORY_CONTENT_CAP + 19);
  const longToolOutput = "O".repeat(HISTORY_TOOL_IO_CAP + 23);

  const claudeContent = jsonlFixture([
    { type: "system", timestamp: "2026-07-06T00:00:00.000Z", content: "drop" },
    { type: "user", timestamp: "2026-07-06T00:00:01.000Z", message: { role: "user", content: "  Please inspect.  " } },
    {
      type: "assistant",
      timestamp: "2026-07-06T00:00:02.000Z",
      message: {
        role: "assistant",
        content: [
          { type: "text", text: " I'll check. " },
          { type: "tool_use", id: "cl_call_1", name: "read_file", input: { path: "src/a.ts" } },
          { type: "tool_use", id: "cl_call_2", name: "shell", input: "npm test" },
        ],
      },
    },
    { type: "attachment", timestamp: "2026-07-06T00:00:03.000Z", attachment: { name: "drop" } },
    {
      type: "user",
      timestamp: "2026-07-06T00:00:04.000Z",
      message: { role: "user", content: [{ type: "tool_result", tool_use_id: "cl_call_2", content: "tests ok" }] },
    },
    {
      type: "user",
      timestamp: "2026-07-06T00:00:05.000Z",
      message: {
        role: "user",
        content: [
          { type: "text", text: "Here is more context" },
          { type: "tool_result", tool_use_id: "cl_call_1", content: "file text" },
        ],
      },
    },
    {
      type: "assistant",
      timestamp: "2026-07-06T00:00:06.000Z",
      message: {
        role: "assistant",
        content: [
          { type: "tool_use", id: "cl_unmatched", name: "no_result", input: { x: 1 } },
          { type: "tool_use", id: "cl_empty", name: "noop", input: {} },
        ],
      },
    },
    {
      type: "user",
      timestamp: "2026-07-06T00:00:07.000Z",
      message: { role: "user", content: [{ type: "tool_result", tool_use_id: "cl_empty", content: "" }] },
    },
    { type: "user", timestamp: "2026-07-06T00:00:08.000Z", message: { role: "user", content: [{ type: "image", source: "omitted" }] } },
    { type: "assistant", timestamp: "2026-07-06T00:00:09.000Z", message: { role: "assistant", content: [{ type: "thinking", thinking: "hidden" }] } },
    {
      type: "assistant",
      timestamp: "2026-07-06T00:00:10.000Z",
      message: { role: "assistant", content: [{ type: "strange_block", value: true }, { type: "fallback", reason: "fallback" }] },
    },
    { type: "assistant", timestamp: "2026-07-06T00:00:11.000Z", message: { role: "assistant", content: longContent } },
    {
      type: "assistant",
      timestamp: "2026-07-06T00:00:12.000Z",
      message: { role: "assistant", content: [{ type: "tool_use", id: "cl_big", name: "shell", input: "printf big" }] },
    },
    {
      type: "user",
      timestamp: "2026-07-06T00:00:13.000Z",
      message: { role: "user", content: [{ type: "tool_result", tool_use_id: "cl_big", content: longToolOutput }] },
    },
  ]);

  const claudeEntries = buildHistoryEntries("claude", claudeContent, claudeSessionId);
  const claudeEntriesAgain = buildHistoryEntries("claude", claudeContent, claudeSessionId);
  const claudeIds = claudeEntries.map((e) => e.entry_id);
  const claudeFirstTools = claudeEntries.find((e) => e.tool_calls?.some((c) => c.id === "cl_call_1"));
  const clCall1 = claudeFirstTools?.tool_calls?.find((c) => c.id === "cl_call_1");
  const clCall2 = claudeFirstTools?.tool_calls?.find((c) => c.id === "cl_call_2");
  const claudeToolOnly = claudeEntries.find((e) => e.tool_calls?.some((c) => c.id === "cl_unmatched"));
  const clUnmatched = claudeToolOnly?.tool_calls?.find((c) => c.id === "cl_unmatched");
  const clEmpty = claudeToolOnly?.tool_calls?.find((c) => c.id === "cl_empty");
  const clBig = claudeEntries.flatMap((e) => e.tool_calls ?? []).find((c) => c.id === "cl_big");
  const claudeLong = claudeEntries.find((e) => e.content_truncated === true);

  check(
    "AV1 Claude keeps only user/assistant entries in chronological order",
    claudeEntries.length === 9 &&
      claudeEntries.every((e) => e.role === "user" || e.role === "assistant") &&
      claudeEntries[0]?.content === "Please inspect." &&
      claudeEntries[1]?.content === "I'll check." &&
      claudeEntries[2]?.content === "Here is more context" &&
      !JSON.stringify(claudeEntries).includes("attachment"),
  );
  check(
    "AV2 Claude correlates tool calls/results by id across non-adjacent lines",
    claudeFirstTools?.role === "assistant" &&
      claudeFirstTools.tool_calls?.length === 2 &&
      clCall1?.output === "file text" &&
      clCall1.status === "ok" &&
      clCall2?.output === "tests ok" &&
      clCall2.status === "ok",
  );
  check(
    "AV3 Claude preserves tool-only, unmatched, and completed-no-output cases",
    claudeToolOnly?.content === "" &&
      clUnmatched !== undefined &&
      clUnmatched.output === undefined &&
      clUnmatched.status === undefined &&
      clEmpty?.status === "ok" &&
      clEmpty.output === undefined,
  );
  check(
    "AV4 Claude records omitted non-text blocks without dropping turns",
    claudeEntries.some((e) => e.role === "user" && e.content === "" && e.omitted?.[0]?.kind === "image" && e.omitted[0].count === 1) &&
      claudeEntries.some((e) => e.role === "assistant" && e.content === "" && e.omitted?.[0]?.kind === "thinking" && e.omitted[0].count === 1) &&
      claudeEntries.some(
        (e) =>
          e.role === "assistant" &&
          e.content === "" &&
          e.omitted?.some((o) => o.kind === "fallback" && o.count === 1) &&
          e.omitted?.some((o) => o.kind === "other" && o.count === 1),
      ),
  );
  check(
    "AV5 caps content and tool output with truncation flags",
    claudeLong?.content.length === HISTORY_CONTENT_CAP &&
      claudeLong.content_truncated === true &&
      clBig?.output?.length === HISTORY_TOOL_IO_CAP &&
      clBig.output_truncated === true &&
      clBig.status === "ok",
  );
  check(
    "AV6 entry ids are opaque, unique, stable, and not handles/session ids",
    claudeIds.length === new Set(claudeIds).size &&
      claudeIds.every((id) => /^e_[0-9a-f]{16,}$/.test(id) && id !== claudeSessionId && id !== "h_av_handle") &&
      JSON.stringify(claudeIds) === JSON.stringify(claudeEntriesAgain.map((e) => e.entry_id)),
  );

  const codexContent = jsonlFixture([
    { type: "session_meta", timestamp: "2026-07-06T01:00:00.000Z", payload: { id: codexSessionId, cwd: SCRATCH } },
    { type: "event_msg", timestamp: "2026-07-06T01:00:01.000Z", payload: { type: "user_message", message: "Codex user" } },
    {
      type: "response_item",
      timestamp: "2026-07-06T01:00:02.000Z",
      payload: { type: "message", role: "developer", content: [{ type: "input_text", text: "developer dropped" }] },
    },
    {
      type: "response_item",
      timestamp: "2026-07-06T01:00:03.000Z",
      payload: { type: "message", role: "user", content: [{ type: "input_text", text: "Codex user" }] },
    },
    { type: "event_msg", timestamp: "2026-07-06T01:00:04.000Z", payload: { type: "agent_message", message: "Codex assistant" } },
    {
      type: "response_item",
      timestamp: "2026-07-06T01:00:05.000Z",
      payload: { type: "message", role: "assistant", content: [{ type: "output_text", text: "Codex assistant" }] },
    },
    { type: "response_item", timestamp: "2026-07-06T01:00:06.000Z", payload: { type: "reasoning", summary: "dropped" } },
    {
      type: "response_item",
      timestamp: "2026-07-06T01:00:07.000Z",
      payload: { type: "function_call", call_id: "cx_patch", name: "apply_patch", arguments: "{\"patch\":true}" },
    },
    { type: "event_msg", timestamp: "2026-07-06T01:00:08.000Z", payload: { type: "token_count", info: {} } },
    {
      type: "event_msg",
      timestamp: "2026-07-06T01:00:09.000Z",
      payload: { type: "patch_apply_end", call_id: "cx_patch", success: true, status: "success", changes: { "src/a.ts": "modified" }, stdout: "applied" },
    },
    {
      type: "response_item",
      timestamp: "2026-07-06T01:00:10.000Z",
      payload: { type: "function_call", call_id: "cx_no_output", name: "noop", arguments: "{}" },
    },
    {
      type: "response_item",
      timestamp: "2026-07-06T01:00:11.000Z",
      payload: { type: "function_call_output", call_id: "cx_no_output", output: "" },
    },
    {
      type: "response_item",
      timestamp: "2026-07-06T01:00:12.000Z",
      payload: { type: "custom_tool_call", call_id: "cx_unmatched", name: "custom", input: "raw input" },
    },
    {
      type: "response_item",
      timestamp: "2026-07-06T01:00:13.000Z",
      payload: { type: "message", role: "user", content: [{ type: "input_text", text: "After tools" }] },
    },
    {
      type: "event_msg",
      timestamp: "2026-07-06T01:00:14.000Z",
      payload: { type: "patch_apply_end", call_id: "cx_synthetic", success: true, status: "success", changes: { "src/lonely.ts": "created" } },
    },
  ]);
  const codexEntries = buildHistoryEntries("codex", codexContent, codexSessionId);
  const codexAssistant = codexEntries.find((e) => e.content === "Codex assistant");
  const cxPatch = codexAssistant?.tool_calls?.find((c) => c.id === "cx_patch");
  const cxNoOutput = codexAssistant?.tool_calls?.find((c) => c.id === "cx_no_output");
  const cxUnmatched = codexAssistant?.tool_calls?.find((c) => c.id === "cx_unmatched");
  const cxSynthetic = codexEntries.flatMap((e) => e.tool_calls ?? []).find((c) => c.id === "cx_synthetic");

  check(
    "AV7 Codex uses response_item only for messages and drops meta/developer/reasoning",
    codexEntries.length === 4 &&
      codexEntries.filter((e) => e.content === "Codex user").length === 1 &&
      codexEntries.filter((e) => e.content === "Codex assistant").length === 1 &&
      !JSON.stringify(codexEntries).includes("developer dropped") &&
      !JSON.stringify(codexEntries).includes("reasoning"),
  );
  check(
    "AV8 Codex correlates tools, completed-no-output, unmatched, and patch enrichment",
    cxPatch?.status === "ok" &&
      cxPatch.output?.includes("patch_apply_end") === true &&
      cxPatch.output.includes("src/a.ts") &&
      cxNoOutput?.status === "ok" &&
      cxNoOutput.output === undefined &&
      cxUnmatched !== undefined &&
      cxUnmatched.status === undefined &&
      cxUnmatched.output === undefined &&
      cxSynthetic?.name === "apply_patch" &&
      cxSynthetic.output?.includes("src/lonely.ts") === true,
  );

  const page1 = readSessionHistory("claude", claudeContent, claudeSessionId, { limit: 3 });
  const page2 = readSessionHistory("claude", claudeContent, claudeSessionId, { limit: 3, cursor: page1.next_cursor ?? undefined });
  const page3 = readSessionHistory("claude", claudeContent, claudeSessionId, { limit: 3, cursor: page2.next_cursor ?? undefined });
  const pagedIds = [...page1.entries, ...page2.entries, ...page3.entries].map((e) => e.entry_id);
  const appendedClaudeContent =
    claudeContent +
    `${JSON.stringify({ type: "user", timestamp: "2026-07-06T00:00:14.000Z", message: { role: "user", content: "appended" } })}\n`;
  const page2AfterAppend = readSessionHistory("claude", appendedClaudeContent, claudeSessionId, { limit: 3, cursor: page1.next_cursor ?? undefined });
  let malformedCursorRejected = false;
  try {
    readSessionHistory("claude", claudeContent, claudeSessionId, { cursor: "not a cursor!", limit: 2 });
  } catch (e) {
    malformedCursorRejected = e instanceof HistoryCursorError && e.code === "cursor_invalid";
  }
  check(
    "AV9 pagination is newest-first, walks older without dup/skip, and is append-stable",
    page1.entries.length === 3 &&
      page1.entries[0]?.entry_id === claudeEntries[6]?.entry_id &&
      page1.truncated === true &&
      typeof page1.next_cursor === "string" &&
      page2.entries.length === 3 &&
      page3.entries.length === 3 &&
      page3.next_cursor === null &&
      pagedIds.length === claudeEntries.length &&
      new Set(pagedIds).size === claudeEntries.length &&
      claudeIds.every((id) => pagedIds.includes(id)) &&
      JSON.stringify(page2.entries.map((e) => e.entry_id)) === JSON.stringify(page2AfterAppend.entries.map((e) => e.entry_id)) &&
      malformedCursorRejected,
  );

  const claudeWire = safeParseMessageV2({
    id: "m-av-claude",
    ts: "2026-07-06T02:00:00.000Z",
    type: "session.history.response",
    request_id: "req-av-claude",
    entries: claudeEntries,
    truncated: false,
  });
  const codexWire = safeParseMessageV2({
    id: "m-av-codex",
    ts: "2026-07-06T02:00:01.000Z",
    type: "session.history.response",
    request_id: "req-av-codex",
    entries: codexEntries,
    truncated: false,
  });
  check("AV10 produced history entries validate against the v2 wire schema", claudeWire.success && codexWire.success);

  type SessionHistoryResponse = Extract<MessageV2, { type: "session.history.response" }>;
  const historyResponse = (
    page: { entries: SessionHistoryResponse["entries"]; next_cursor: string | null; truncated: boolean },
    requestId: string,
  ): SessionHistoryResponse => ({
    id: `m-${requestId}`,
    ts: "2026-07-06T02:30:00.000Z",
    type: "session.history.response",
    request_id: requestId,
    entries: page.entries,
    next_cursor: page.next_cursor,
    truncated: page.truncated,
  });
  const historyResponseBytes = (response: SessionHistoryResponse): number => Buffer.byteLength(JSON.stringify(response), "utf8");

  const largeSessionId = "claude-av-large-session";
  const timestampAt = (offsetSeconds: number): string => new Date(Date.UTC(2026, 6, 7, 0, 0, offsetSeconds)).toISOString();
  const largeToolInput = "I".repeat(HISTORY_TOOL_IO_CAP + 31);
  const largeToolOutput = "O".repeat(HISTORY_TOOL_IO_CAP + 37);
  const largeContentRecords = [
    ...Array.from({ length: 72 }, (_, i) => ({
      type: "user",
      timestamp: timestampAt(i),
      message: { role: "user", content: `${i}:${"M".repeat(HISTORY_CONTENT_CAP + 101)}` },
    })),
    {
      type: "assistant",
      timestamp: timestampAt(72),
      message: {
        role: "assistant",
        content: [
          { type: "text", text: "oversized tool entry" },
          ...Array.from({ length: HISTORY_PAGE_MAX }, (_, i) => ({
            type: "tool_use",
            id: `large_call_${i}`,
            name: "shell",
            input: `${i}:${largeToolInput}`,
          })),
        ],
      },
    },
    {
      type: "user",
      timestamp: timestampAt(73),
      message: {
        role: "user",
        content: Array.from({ length: HISTORY_PAGE_MAX }, (_, i) => ({
          type: "tool_result",
          tool_use_id: `large_call_${i}`,
          content: `${i}:${largeToolOutput}`,
        })),
      },
    },
  ];
  const largeContentFixture = jsonlFixture(largeContentRecords);
  const largeEntries = buildHistoryEntries("claude", largeContentFixture, largeSessionId);
  const largeOversizedEntry = largeEntries.find((e) => e.content === "oversized tool entry");
  const largeDroppedTools = HISTORY_PAGE_MAX - (largeOversizedEntry?.tool_calls?.length ?? 0);

  const largeWalkedIds: string[] = [];
  let largeCursor: string | undefined;
  let largeWalkTerminated = false;
  let largePagesFitFrame = true;
  let largePagesNonEmpty = true;
  for (let i = 0; i < 20; i++) {
    const page = readSessionHistory("claude", largeContentFixture, largeSessionId, { limit: HISTORY_PAGE_MAX, cursor: largeCursor });
    const response = historyResponse(page, `req-av11-${i}`);
    largePagesFitFrame =
      largePagesFitFrame &&
      historyResponseBytes(response) <= LIMITS.MAX_FRAME_BYTES &&
      safeParseMessageV2(response).success &&
      page.entries.every((entry) => Buffer.byteLength(JSON.stringify(entry), "utf8") <= HISTORY_ENTRY_BYTE_MAX);
    largePagesNonEmpty = largePagesNonEmpty && page.entries.length > 0;
    largeWalkedIds.push(...page.entries.map((entry) => entry.entry_id));
    if (page.next_cursor === null) {
      largeWalkTerminated = true;
      break;
    }
    largeCursor = page.next_cursor;
  }
  check(
    "AV11 large history pages stay under the frame cap and walk without dup/skip",
    largePagesFitFrame &&
      largePagesNonEmpty &&
      largeWalkTerminated &&
      largeWalkedIds.length === largeEntries.length &&
      new Set(largeWalkedIds).size === largeEntries.length &&
      largeEntries.every((entry) => largeWalkedIds.includes(entry.entry_id)) &&
      largeDroppedTools > 0 &&
      largeOversizedEntry?.omitted?.some((item) => item.kind === "other" && item.count === largeDroppedTools) === true,
  );

  const duplicateClaudeContent = jsonlFixture([
    {
      type: "assistant",
      timestamp: "2026-07-06T03:00:00.000Z",
      message: {
        role: "assistant",
        content: [
          { type: "text", text: "duplicate claude calls" },
          { type: "tool_use", id: "dup_call", name: "shell", input: "first" },
          { type: "tool_use", id: "dup_call", name: "shell", input: "second" },
        ],
      },
    },
    {
      type: "user",
      timestamp: "2026-07-06T03:00:01.000Z",
      message: {
        role: "user",
        content: [
          { type: "tool_result", tool_use_id: "dup_call", content: "claude result 1" },
          { type: "tool_result", tool_use_id: "dup_call", content: "claude result 2" },
        ],
      },
    },
  ]);
  const duplicateClaudeCalls = buildHistoryEntries("claude", duplicateClaudeContent, "claude-av-duplicate-session").flatMap((e) => e.tool_calls ?? []);
  const duplicateCodexContent = jsonlFixture([
    {
      type: "response_item",
      timestamp: "2026-07-06T03:01:00.000Z",
      payload: { type: "message", role: "assistant", content: [{ type: "output_text", text: "duplicate codex calls" }] },
    },
    { type: "response_item", timestamp: "2026-07-06T03:01:01.000Z", payload: { type: "function_call", call_id: "dup_call", name: "shell", arguments: "first" } },
    { type: "response_item", timestamp: "2026-07-06T03:01:02.000Z", payload: { type: "function_call_output", call_id: "dup_call", output: "codex result 1" } },
    { type: "response_item", timestamp: "2026-07-06T03:01:03.000Z", payload: { type: "function_call", call_id: "dup_call", name: "shell", arguments: "second" } },
    { type: "response_item", timestamp: "2026-07-06T03:01:04.000Z", payload: { type: "function_call_output", call_id: "dup_call", output: "codex result 2" } },
  ]);
  const duplicateCodexCalls = buildHistoryEntries("codex", duplicateCodexContent, "codex-av-duplicate-session").flatMap((e) => e.tool_calls ?? []);
  check(
    "AV12 duplicate tool-call ids consume results FIFO",
    duplicateClaudeCalls.length === 2 &&
      duplicateClaudeCalls[0]?.output === "claude result 1" &&
      duplicateClaudeCalls[0].status === "ok" &&
      duplicateClaudeCalls[1]?.output === "claude result 2" &&
      duplicateClaudeCalls[1].status === "ok" &&
      duplicateCodexCalls.length === 2 &&
      duplicateCodexCalls[0]?.output === "codex result 1" &&
      duplicateCodexCalls[0].status === "ok" &&
      duplicateCodexCalls[1]?.output === "codex result 2" &&
      duplicateCodexCalls[1].status === "ok",
  );

  const cursorContentA = jsonlFixture(
    Array.from({ length: 4 }, (_, i) => ({
      type: "user",
      timestamp: `2026-07-06T03:02:0${i}.000Z`,
      message: { role: "user", content: `cursor A ${i}` },
    })),
  );
  const cursorContentB = jsonlFixture(
    Array.from({ length: 4 }, (_, i) => ({
      type: "user",
      timestamp: `2026-07-06T03:03:0${i}.000Z`,
      message: { role: "user", content: `cursor B ${i}` },
    })),
  );
  const cursorA1 = readSessionHistory("claude", cursorContentA, "cursor-session-a", { limit: 2 });
  const cursorA2 = readSessionHistory("claude", cursorContentA, "cursor-session-a", { limit: 2, cursor: cursorA1.next_cursor ?? undefined });
  let crossSessionCursorRejected = false;
  try {
    readSessionHistory("claude", cursorContentB, "cursor-session-b", { limit: 2, cursor: cursorA1.next_cursor ?? undefined });
  } catch (e) {
    crossSessionCursorRejected = e instanceof HistoryCursorError && e.code === "cursor_invalid";
  }
  const sameRawBase = mkdtempSync(join(tmpdir(), "hugind-e2e-cursor-scope-"));
  let scopedSameFileCursorAccepted = false;
  let scopedCrossFileCursorRejected = false;
  try {
    const allowRoot = join(sameRawBase, "allowed");
    const cwdA = join(allowRoot, "cursor-file-a");
    const cwdB = join(allowRoot, "cursor-file-b");
    const claudeProjectsDir = join(sameRawBase, "claude", "projects");
    const codexSessionsDir = join(sameRawBase, "codex", "sessions");
    mkdirSync(cwdA, { recursive: true });
    mkdirSync(cwdB, { recursive: true });
    const rawSessionId = "99999999-9999-4999-8999-999999999999";
    const scopedRecords = (cwd: string, title: string, prefix: string): unknown[] => [
      { type: "system", timestamp: "2026-07-06T03:04:00.000Z", cwd, gitBranch: "main", version: "scope-test" },
      { type: "ai-title", timestamp: "2026-07-06T03:04:01.000Z", title },
      ...Array.from({ length: 4 }, (_, i) => ({
        type: "user",
        timestamp: `2026-07-06T03:04:0${i + 2}.000Z`,
        message: { role: "user", content: `${prefix} ${i}` },
      })),
    ];
    writeJsonlFixture(
      join(claudeProjectsDir, "encoded-cursor-a", `${rawSessionId}.jsonl`),
      scopedRecords(cwdA, "Cursor scoped file A", "file A"),
      Date.parse("2026-07-06T03:05:00.000Z"),
    );
    writeJsonlFixture(
      join(claudeProjectsDir, "encoded-cursor-b", `${rawSessionId}.jsonl`),
      scopedRecords(cwdB, "Cursor scoped file B", "file B"),
      Date.parse("2026-07-06T03:06:00.000Z"),
    );
    const scopedEnumerator = new SessionEnumerator({
      claudeProjectsDir,
      codexSessionsDir,
      allowlist: [allowRoot],
      now: () => Date.parse("2026-07-06T03:10:00.000Z"),
    });
    const scopedSessions = scopedEnumerator.list({ filter: { engine: "claude" }, page: { limit: 10 } }).sessions;
    const scopedA = scopedSessions.find((s) => s.title === "Cursor scoped file A");
    const scopedB = scopedSessions.find((s) => s.title === "Cursor scoped file B");
    if (scopedA && scopedB && scopedA.session_id === scopedB.session_id) {
      const scopedPageA1 = scopedEnumerator.readHistory(scopedA.handle, { limit: 2 });
      if (scopedPageA1.ok && typeof scopedPageA1.next_cursor === "string") {
        const scopedPageA2 = scopedEnumerator.readHistory(scopedA.handle, { limit: 2, cursor: scopedPageA1.next_cursor });
        const scopedReplayOnB = scopedEnumerator.readHistory(scopedB.handle, { limit: 2, cursor: scopedPageA1.next_cursor });
        scopedSameFileCursorAccepted =
          scopedPageA2.ok &&
          scopedPageA2.entries.length === 2 &&
          scopedPageA2.entries[0]?.content === "file A 0" &&
          scopedPageA2.next_cursor === null;
        scopedCrossFileCursorRejected = !scopedReplayOnB.ok && scopedReplayOnB.code === "cursor_invalid";
      }
    }
  } finally {
    rmSync(sameRawBase, { recursive: true, force: true });
  }
  check(
    "AV13 history cursors are bound to the session id and exact session file scope",
    typeof cursorA1.next_cursor === "string" &&
      cursorA2.entries.length === 2 &&
      cursorA2.entries[0]?.content === "cursor A 0" &&
      cursorA2.next_cursor === null &&
      crossSessionCursorRejected &&
      scopedSameFileCursorAccepted &&
      scopedCrossFileCursorRejected,
  );
}

async function scenarioAQ(): Promise<void> {
  type SessionResumeAccept = Extract<MessageV2, { type: "session.resume.accept" }>;
  type SessionResumeReject = Extract<MessageV2, { type: "session.resume.reject" }>;
  type SessionEvent = Extract<MessageV2, { type: "session.event" }>;
  type SessionTurnResult = Extract<MessageV2, { type: "session.turn.result" }>;

  const fx1 = createSessionFixtureStore();
  try {
    const runner = new FakeResumeRunner({
      events: [{ kind: "assistant_text", text: "resumed" }],
      finalMessage: "resume complete",
      newSessionId: "55555555-5555-4555-8555-555555555555",
    });
    const aq1 = {
      accept: null as SessionResumeAccept | null,
      events: [] as SessionEvent[],
      result: null as SessionTurnResult | null,
    };
    let wsRef: WebSocket | null = null;
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionListAfterAccept: true,
      onAccept: (ctx) => {
        wsRef = ctx.ws;
      },
      onSessionListResponse: (m) => {
        const handle = byEngine(m.sessions, "claude")?.handle;
        if (handle && wsRef) relay.resumeSession(wsRef, { request_id: "aq1", handle, message: "continue" });
      },
      onSessionResumeAccept: (m) => {
        aq1.accept = m;
      },
      onSessionEvent: (m) => {
        aq1.events.push(m);
      },
      onSessionTurnResult: (m) => {
        aq1.result = m;
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-aq1",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx1.allowRoot],
      }),
      devSigner("key-aq1"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx1),
      runner,
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => aq1.result !== null, 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AQ1 valid claude handle → accept, session.event, ok turn.result with fork handle",
      aq1.accept?.request_id === "aq1" &&
        typeof aq1.accept.turn_id === "string" &&
        aq1.accept.effective_options?.fork === true &&
        aq1.accept.effective_options?.sandbox === "read_only" &&
        aq1.events.length >= 1 &&
        aq1.events[0]?.seq === 1 &&
        aq1.events[0]?.event.kind === "assistant_text" &&
        aq1.result?.status === "ok" &&
        aq1.result.final_message === "resume complete" &&
        typeof aq1.result.new_session_handle === "string" &&
        runner.runCount === 1 &&
        runner.specs[0]?.fork === true &&
        runner.specs[0]?.sandbox === "read_only",
    );
  } finally {
    rmSync(fx1.base, { recursive: true, force: true });
  }

  const fx2 = createSessionFixtureStore();
  try {
    const runner = new FakeResumeRunner({ events: [] });
    const aq2 = {
      reject: null as SessionResumeReject | null,
      accept: null as SessionResumeAccept | null,
      result: null as SessionTurnResult | null,
    };
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      onAccept: (ctx) => {
        relay.resumeSession(ctx.ws, { request_id: "aq2", handle: "h_missing", message: "continue" });
      },
      onSessionResumeAccept: (m) => {
        aq2.accept = m;
      },
      onSessionResumeReject: (m) => {
        aq2.reject = m;
      },
      onSessionTurnResult: (m) => {
        aq2.result = m;
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-aq2",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx2.allowRoot],
      }),
      devSigner("key-aq2"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx2),
      runner,
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => aq2.reject !== null, 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AQ2 unknown handle → session.resume.reject handle_invalid and no turn",
      aq2.reject?.request_id === "aq2" &&
        aq2.reject.code === "handle_invalid" &&
        aq2.accept === null &&
        aq2.result === null &&
        runner.runCount === 0,
    );
  } finally {
    rmSync(fx2.base, { recursive: true, force: true });
  }

  const fx3 = createSessionFixtureStore();
  try {
    const runner = new FakeResumeRunner({ events: [{ kind: "assistant_text", text: "still running" }], hang: true });
    const aq3 = { accepts: [] as SessionResumeAccept[], reject: null as SessionResumeReject | null };
    let wsRef: WebSocket | null = null;
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionListAfterAccept: true,
      onAccept: (ctx) => {
        wsRef = ctx.ws;
      },
      onSessionListResponse: (m) => {
        const handle = byEngine(m.sessions, "claude")?.handle;
        if (!handle || !wsRef) return;
        relay.resumeSession(wsRef, { request_id: "aq3-first", handle, message: "first" });
        relay.resumeSession(wsRef, { request_id: "aq3-second", handle, message: "second" });
      },
      onSessionResumeAccept: (m) => {
        aq3.accepts.push(m);
      },
      onSessionResumeReject: (m) => {
        aq3.reject = m;
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-aq3",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx3.allowRoot],
      }),
      devSigner("key-aq3"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx3),
      runner,
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => aq3.accepts.length >= 1 && aq3.reject !== null, 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AQ3 second resume on in-flight handle → session_busy",
      aq3.accepts.some((m) => m.request_id === "aq3-first") &&
        aq3.reject?.request_id === "aq3-second" &&
        aq3.reject.code === "session_busy" &&
        runner.runCount === 1,
    );
  } finally {
    rmSync(fx3.base, { recursive: true, force: true });
  }

  const fx4 = createSessionFixtureStore();
  try {
    const runner = new FakeResumeRunner({ events: [] });
    const aq4 = { reject: null as SessionResumeReject | null };
    let wsRef: WebSocket | null = null;
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionListAfterAccept: true,
      onAccept: (ctx) => {
        wsRef = ctx.ws;
      },
      onSessionListResponse: (m) => {
        const handle = byEngine(m.sessions, "codex")?.handle;
        if (handle && wsRef) relay.resumeSession(wsRef, { request_id: "aq4", handle, message: "continue" });
      },
      onSessionResumeReject: (m) => {
        aq4.reject = m;
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-aq4",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx4.allowRoot],
      }),
      devSigner("key-aq4"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx4),
      runner,
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => aq4.reject !== null, 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AQ4 codex handle → engine_unavailable",
      aq4.reject?.request_id === "aq4" && aq4.reject.code === "engine_unavailable" && runner.runCount === 0,
    );
  } finally {
    rmSync(fx4.base, { recursive: true, force: true });
  }

  const fx5 = createSessionFixtureStore();
  try {
    const enumerator = fixtureEnumerator(fx5);
    const handle = byEngine(enumerator.list({}).sessions, "claude")?.handle ?? "";
    const runner = new FakeResumeRunner({ events: [], hang: true });
    const messages: MessageV2[] = [];
    const manager = new SessionResumeManager((m) => messages.push(m), {
      enumerator,
      runners: { claude: runner },
      cancelGraceMs: 1,
    });
    let msgSeq = 0;
    const req = (requestId: string, message: string): Extract<MessageV2, { type: "session.resume.request" }> => ({
      id: `ar5-${++msgSeq}`,
      ts: "2026-07-05T12:00:00.000Z",
      type: "session.resume.request",
      request_id: requestId,
      handle,
      message,
    });

    manager.handleRequest(req("ar5-first", "first"));
    await waitUntil(() => messages.some((m) => m.type === "session.resume.accept" && m.request_id === "ar5-first"), 1000);
    manager.cancelActiveTurns();
    await waitUntil(() => messages.some((m) => m.type === "session.turn.result" && m.status === "cancelled"), 1000);
    manager.handleRequest(req("ar5-followup", "after cancel-all"));
    await waitUntil(() => messages.some((m) => m.type === "session.resume.accept" && m.request_id === "ar5-followup"), 1000);

    check(
      "AR5 cancelActiveTurns finalizes cancelled and releases the session mutex",
      messages.some((m) => m.type === "session.turn.result" && m.status === "cancelled" && m.final_message === "session connection closed") &&
        messages.some((m) => m.type === "session.resume.accept" && m.request_id === "ar5-followup") &&
        runner.cancelCount === 1 &&
        runner.runCount === 2,
    );
  } finally {
    rmSync(fx5.base, { recursive: true, force: true });
  }

  const fx6 = createSessionFixtureStore();
  try {
    const runner = new FakeResumeRunner({ events: [], hang: true });
    const ar6 = { accepts: [] as SessionResumeAccept[] };
    let wsRef: WebSocket | null = null;
    let handle = "";
    let connectionCount = 0;
    let sentFirst = false;
    let sentFollowup = false;
    let stopped = false;
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionListAfterAccept: true,
      onAccept: (ctx) => {
        wsRef = ctx.ws;
        connectionCount++;
      },
      onSessionListResponse: (m) => {
        handle ||= byEngine(m.sessions, "claude")?.handle ?? "";
        if (!handle || !wsRef) return;
        if (!sentFirst) {
          sentFirst = true;
          relay.resumeSession(wsRef, { request_id: "ar6-first", handle, message: "first" });
          return;
        }
        if (connectionCount >= 2) maybeSendFollowup();
      },
      onSessionResumeAccept: (m) => {
        ar6.accepts.push(m);
        if (m.request_id === "ar6-first") setTimeout(() => wsRef?.close(), 0);
      },
    });
    const maybeSendFollowup = () => {
      if (stopped || sentFollowup || !wsRef || !handle) return;
      if (runner.cancelCount <= 0) {
        setTimeout(maybeSendFollowup, 25);
        return;
      }
      sentFollowup = true;
      relay.resumeSession(wsRef, { request_id: "ar6-followup", handle, message: "after disconnect" });
    };
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-ar6",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx6.allowRoot],
      }),
      devSigner("key-ar6"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx6),
      runner,
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => ar6.accepts.some((m) => m.request_id === "ar6-followup"), 8000);
    } finally {
      stopped = true;
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AR6 relay disconnect cancels active session turn and releases the session mutex",
      runner.cancelCount >= 1 && ar6.accepts.some((m) => m.request_id === "ar6-followup") && runner.runCount === 2,
    );
  } finally {
    rmSync(fx6.base, { recursive: true, force: true });
  }
}

async function scenarioAR(): Promise<void> {
  type SessionResumeAccept = Extract<MessageV2, { type: "session.resume.accept" }>;
  type SessionEvent = Extract<MessageV2, { type: "session.event" }>;
  type SessionTurnResult = Extract<MessageV2, { type: "session.turn.result" }>;

  const fx1 = createSessionFixtureStore();
  try {
    const runner = new FakeResumeRunner({ events: [], hang: true });
    const ar1 = { accepts: [] as SessionResumeAccept[], results: [] as SessionTurnResult[] };
    let wsRef: WebSocket | null = null;
    let handle = "";
    let firstTurn = "";
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionListAfterAccept: true,
      onAccept: (ctx) => {
        wsRef = ctx.ws;
      },
      onSessionListResponse: (m) => {
        handle = byEngine(m.sessions, "claude")?.handle ?? "";
        if (handle && wsRef) relay.resumeSession(wsRef, { request_id: "ar1-first", handle, message: "first" });
      },
      onSessionResumeAccept: (m) => {
        ar1.accepts.push(m);
        if (m.request_id === "ar1-first" && wsRef) {
          firstTurn = m.turn_id;
          relay.sendSessionCancel(wsRef, m.turn_id);
        }
      },
      onSessionTurnResult: (m) => {
        ar1.results.push(m);
        if (m.turn_id === firstTurn && m.status === "cancelled" && handle && wsRef) {
          relay.resumeSession(wsRef, { request_id: "ar1-followup", handle, message: "after cancel" });
        }
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-ar1",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx1.allowRoot],
      }),
      devSigner("key-ar1"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx1),
      runner,
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => ar1.accepts.some((m) => m.request_id === "ar1-followup"), 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AR1 session.cancel finalizes cancelled and releases the session mutex",
      ar1.results.some((m) => m.turn_id === firstTurn && m.status === "cancelled") &&
        ar1.accepts.some((m) => m.request_id === "ar1-followup") &&
        runner.runCount === 2,
    );
  } finally {
    rmSync(fx1.base, { recursive: true, force: true });
  }

  const fx2 = createSessionFixtureStore();
  try {
    const cap = 3;
    const runner = new FakeResumeRunner({
      events: Array.from({ length: 8 }, (_, i): { kind: "assistant_text"; text: string } => ({ kind: "assistant_text", text: `bp-${i}` })),
      hang: true,
    });
    const ar2 = { events: [] as SessionEvent[] };
    let wsRef: WebSocket | null = null;
    let turnId = "";
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionListAfterAccept: true,
      onAccept: (ctx) => {
        wsRef = ctx.ws;
      },
      onSessionListResponse: (m) => {
        const handle = byEngine(m.sessions, "claude")?.handle;
        if (handle && wsRef) relay.resumeSession(wsRef, { request_id: "ar2", handle, message: "backpressure" });
      },
      onSessionResumeAccept: (m) => {
        turnId = m.turn_id;
      },
      onSessionEvent: (m) => {
        ar2.events.push(m);
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-ar2",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx2.allowRoot],
        maxUnackedEventsPerAttempt: cap,
      }),
      devSigner("key-ar2"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx2),
      runner,
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => runner.pauseCount > 0 && ar2.events.length === cap, 5000);
      if (wsRef && turnId) relay.sendSessionAck(wsRef, turnId, cap);
      await waitUntil(() => runner.resumeCount > 0 && ar2.events.length > cap, 5000);
      if (wsRef && turnId) relay.sendSessionCancel(wsRef, turnId);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AR2 session.ack applies turn-scoped backpressure pause/resume",
      runner.pauseCount >= 1 && runner.resumeCount >= 1 && ar2.events[0]?.seq === 1 && ar2.events.length > cap,
    );
  } finally {
    rmSync(fx2.base, { recursive: true, force: true });
  }

  const fx3 = createSessionFixtureStore();
  try {
    const forkedSessionId = "66666666-6666-4666-8666-666666666666";
    writeJsonlFixture(
      join(fx3.claudeProjectsDir, "encoded-claude", `${forkedSessionId}.jsonl`),
      [
        { type: "system", timestamp: "2026-07-05T09:59:00.000Z", message: "fork init" },
        { type: "system", timestamp: "2026-07-05T09:59:01.000Z", cwd: join(fx3.allowRoot, "repo-claude"), gitBranch: "main", version: "1.2.3" },
        { type: "ai-title", timestamp: "2026-07-05T09:59:02.000Z", title: "Forked Claude fixture" },
      ],
      fx3.nowMs - 6 * 60 * 1000,
    );
    const runner = new FakeResumeRunner({
      events: [{ kind: "assistant_text", text: "turn" }],
      finalMessage: "turn complete",
      newSessionId: forkedSessionId,
    });
    const ar3 = { accepts: [] as SessionResumeAccept[], results: [] as SessionTurnResult[] };
    let wsRef: WebSocket | null = null;
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionListAfterAccept: true,
      onAccept: (ctx) => {
        wsRef = ctx.ws;
      },
      onSessionListResponse: (m) => {
        const handle = byEngine(m.sessions, "claude")?.handle;
        if (handle && wsRef) relay.resumeSession(wsRef, { request_id: "ar3-first", handle, message: "first turn" });
      },
      onSessionResumeAccept: (m) => {
        ar3.accepts.push(m);
      },
      onSessionTurnResult: (m) => {
        ar3.results.push(m);
        if (ar3.results.length === 1 && m.new_session_handle && wsRef) {
          relay.sendSessionMessage(wsRef, { request_id: "ar3-message", handle: m.new_session_handle, message: "second turn" });
        }
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-ar3",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx3.allowRoot],
      }),
      devSigner("key-ar3"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx3),
      runner,
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => ar3.results.length >= 2, 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AR3 session.message starts a follow-up turn with the supplied message",
      ar3.accepts.some((m) => m.request_id === "ar3-first") &&
        ar3.accepts.some((m) => m.request_id === "ar3-message") &&
        ar3.results.length >= 2 &&
        runner.runCount === 2 &&
        runner.specs[1]?.message === "second turn",
    );
  } finally {
    rmSync(fx3.base, { recursive: true, force: true });
  }

  const fx4 = createSessionFixtureStore();
  try {
    const runner = new FakeResumeRunner({ events: [], hang: true });
    const ar4 = { accepts: [] as SessionResumeAccept[], results: [] as SessionTurnResult[] };
    let wsRef: WebSocket | null = null;
    let handle = "";
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionListAfterAccept: true,
      onAccept: (ctx) => {
        wsRef = ctx.ws;
      },
      onSessionListResponse: (m) => {
        handle = byEngine(m.sessions, "claude")?.handle ?? "";
        if (handle && wsRef) relay.resumeSession(wsRef, { request_id: "ar4-timeout", handle, message: "timeout" });
      },
      onSessionResumeAccept: (m) => {
        ar4.accepts.push(m);
      },
      onSessionTurnResult: (m) => {
        ar4.results.push(m);
        if (m.status === "error" && m.final_message === "resume turn timed out" && handle && wsRef) {
          relay.resumeSession(wsRef, { request_id: "ar4-followup", handle, message: "after timeout" });
        }
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-ar4",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx4.allowRoot],
        sessionTurnTimeoutMs: 50,
      }),
      devSigner("key-ar4"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx4),
      runner,
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => ar4.accepts.some((m) => m.request_id === "ar4-followup"), 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AR4 per-turn timeout emits error and releases the session mutex",
      ar4.results.some((m) => m.status === "error" && m.final_message === "resume turn timed out") &&
        ar4.accepts.some((m) => m.request_id === "ar4-followup") &&
        runner.runCount >= 2,
    );
  } finally {
    rmSync(fx4.base, { recursive: true, force: true });
  }
}

async function scenarioAS(): Promise<void> {
  type SessionResumeAccept = Extract<MessageV2, { type: "session.resume.accept" }>;
  type SessionResumeReject = Extract<MessageV2, { type: "session.resume.reject" }>;
  type SessionEvent = Extract<MessageV2, { type: "session.event" }>;
  type SessionTurnResult = Extract<MessageV2, { type: "session.turn.result" }>;

  const fx1 = createSessionFixtureStore();
  try {
    const runner = new FakeResumeRunner({
      events: [{ kind: "assistant_text", text: "codex resumed" }],
      finalMessage: "codex resume complete",
      newSessionId: "99999999-9999-4999-8999-999999999999",
    });
    const as1 = {
      accept: null as SessionResumeAccept | null,
      events: [] as SessionEvent[],
      result: null as SessionTurnResult | null,
    };
    let wsRef: WebSocket | null = null;
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionListAfterAccept: true,
      onAccept: (ctx) => {
        wsRef = ctx.ws;
      },
      onSessionListResponse: (m) => {
        const handle = byEngine(m.sessions, "codex")?.handle;
        if (handle && wsRef) relay.resumeSession(wsRef, { request_id: "as1", handle, message: "continue" });
      },
      onSessionResumeAccept: (m) => {
        as1.accept = m;
      },
      onSessionEvent: (m) => {
        as1.events.push(m);
      },
      onSessionTurnResult: (m) => {
        as1.result = m;
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-as1",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx1.allowRoot],
      }),
      devSigner("key-as1"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx1),
      { codex: runner },
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => as1.result !== null, 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AS1 valid codex handle → accept, in-place read-only session.event, ok turn.result without fork handle",
      as1.accept?.request_id === "as1" &&
        typeof as1.accept.turn_id === "string" &&
        as1.accept.effective_options?.fork === false &&
        as1.accept.effective_options?.sandbox === "read_only" &&
        as1.accept.effective_options?.mutates_source === true &&
        as1.events.length >= 1 &&
        as1.events[0]?.seq === 1 &&
        as1.events[0]?.event.kind === "assistant_text" &&
        as1.result?.status === "ok" &&
        as1.result.final_message === "codex resume complete" &&
        as1.result.new_session_handle === undefined &&
        runner.runCount === 1 &&
        runner.specs[0]?.engine === "codex" &&
        runner.specs[0]?.fork === false &&
        runner.specs[0]?.sandbox === "read_only",
    );
  } finally {
    rmSync(fx1.base, { recursive: true, force: true });
  }

  const fx2 = createSessionFixtureStore();
  try {
    const runner = new FakeResumeRunner({ events: [] });
    const as2 = { reject: null as SessionResumeReject | null, accept: null as SessionResumeAccept | null };
    let wsRef: WebSocket | null = null;
    const relay = new MockRelay({
      supportedVersions: [PROTOCOL_VERSION, PROTOCOL_VERSION_V2],
      sendSessionListAfterAccept: true,
      onAccept: (ctx) => {
        wsRef = ctx.ws;
      },
      onSessionListResponse: (m) => {
        const handle = byEngine(m.sessions, "codex")?.handle;
        if (handle && wsRef) relay.resumeSession(wsRef, { request_id: "as2", handle, message: "continue" });
      },
      onSessionResumeAccept: (m) => {
        as2.accept = m;
      },
      onSessionResumeReject: (m) => {
        as2.reject = m;
      },
    });
    const port = await relay.start();
    const daemon = new Daemon(
      loadConfig({
        serverUrl: `ws://127.0.0.1:${port}`,
        agentId: "agent-as2",
        dbPath: ":memory:",
        protocolVersion: PROTOCOL_VERSION_V2,
        projectRoots: [fx2.allowRoot],
      }),
      devSigner("key-as2"),
      new FakeEngine({ events: [] }),
      true,
      fixtureEnumerator(fx2),
      { claude: runner },
    );
    try {
      void daemon.start().catch(() => {});
      await waitUntil(() => as2.reject !== null, 5000);
    } finally {
      daemon.stop();
      await relay.stop();
      await sleep(50);
    }
    check(
      "AS2 codex handle with no codex runner → engine_unavailable",
      as2.reject?.request_id === "as2" && as2.reject.code === "engine_unavailable" && as2.accept === null && runner.runCount === 0,
    );
  } finally {
    rmSync(fx2.base, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Track B — real approval bridge (CI-safe: an MCP client stands in for claude).
// ---------------------------------------------------------------------------

/** An MCP Client spawns the REAL permission.ts subprocess and calls
 *  `permission_prompt` exactly as claude's `--permission-prompt-tool` would —
 *  proving the whole round-trip (MCP stdio + unix-socket IPC + onApprovalRequest/
 *  resolve) with NO real claude or env-auth. */
async function approvalBridgeRoundTrip(decision: "allow" | "deny"): Promise<{ req: ApprovalRequest | null; payload: Record<string, unknown> }> {
  const sockPath = join(tmpdir(), `hg-e2e-appr-${process.pid}-${decision}.sock`);
  const bridge = new ApprovalBridge(sockPath);
  await bridge.start();
  let req: ApprovalRequest | null = null;
  bridge.onRequest((r) => {
    req = r;
    bridge.resolve(r.requestId, decision, decision === "deny" ? "blocked by e2e" : undefined);
  });
  const launch = permissionServerLaunch();
  const childEnv: Record<string, string> = { ...(process.env as Record<string, string>), HUGIN_APPROVAL_SOCK: sockPath };
  const transport = new StdioClientTransport({ command: launch.command, args: launch.args, env: childEnv });
  const client = new Client({ name: "e2e-claude-standin", version: "1.0.0" });
  let payload: Record<string, unknown> = {};
  try {
    await client.connect(transport);
    const result = await client.callTool({ name: "permission_prompt", arguments: { tool_name: "Bash", input: { command: "ls -la" } } });
    const content = (result.content as Array<{ type: string; text?: string }> | undefined) ?? [];
    payload = JSON.parse(content.find((c) => c.type === "text")?.text ?? "{}") as Record<string, unknown>;
  } finally {
    await client.close().catch(() => {});
    await bridge.close();
  }
  return { req, payload };
}

async function scenarioAH(): Promise<void> {
  const allow = await approvalBridgeRoundTrip("allow");
  check(
    "AH1 bridge relays the tool prompt (toolName + input) to onApprovalRequest",
    allow.req?.toolName === "Bash" && JSON.stringify(allow.req?.input) === JSON.stringify({ command: "ls -la" }),
  );
  check(
    "AH2 allow → {behavior:allow, updatedInput:<cached input>}",
    allow.payload.behavior === "allow" && (allow.payload.updatedInput as { command?: string } | undefined)?.command === "ls -la",
  );

  const deny = await approvalBridgeRoundTrip("deny");
  check("AH3 deny → {behavior:deny, message} (fail-closed shape)", deny.payload.behavior === "deny" && typeof deny.payload.message === "string");
}

/** Track B wiring (CI-safe): ClaudeEngine spawns a FAKE claude that dumps its
 *  argv + the --mcp-config it was handed. Proves the daemon passes the
 *  permission-prompt-tool + strict-mcp-config wiring correctly — without real
 *  claude. (The live gate itself is validated on a suitable host via e2e:claude.) */
async function scenarioAI(): Promise<void> {
  const base = join(SCRATCH, "wiring");
  rmSync(base, { recursive: true, force: true });
  const repo = join(base, "repo");
  mkdirSync(repo, { recursive: true });
  const git = (...a: string[]) => execFileSync("git", ["-C", repo, ...a], { stdio: "pipe" });
  git("init", "-q");
  git("config", "user.email", "e2e@test.local");
  git("config", "user.name", "e2e");
  writeFileSync(join(repo, "f.txt"), "x\n");
  git("add", "-A");
  git("commit", "-qm", "init");

  const argvOut = join(base, "argv.json");
  const mcpOut = join(base, "mcp.json");
  const fakeClaude = join(base, "fake-claude.js");
  writeFileSync(
    fakeClaude,
    `#!/usr/bin/env node
const fs = require('fs');
const argv = process.argv.slice(2);
fs.writeFileSync(process.env.HG_ARGV_OUT, JSON.stringify(argv));
const i = argv.indexOf('--mcp-config');
if (i >= 0) fs.writeFileSync(process.env.HG_MCP_OUT, fs.readFileSync(argv[i + 1], 'utf8'));
process.exit(0);
`,
  );
  chmodSync(fakeClaude, 0o755);

  const engine = new ClaudeEngine({ command: fakeClaude, env: { HG_ARGV_OUT: argvOut, HG_MCP_OUT: mcpOut }, allowlist: [repo], stateDir: base, timeoutMs: 30_000 });
  const run = engine.run({ engine: "claude", prompt: "hi", attemptId: "wire1", repoRoot: repo });
  await new Promise<void>((res) => run.onDone(() => res()));
  await sleep(50);

  const argv = JSON.parse(readFileSync(argvOut, "utf8")) as string[];
  check("AI1 claude args route the gate through mcp__hugin__permission_prompt", argv.includes("--permission-prompt-tool") && argv.includes("mcp__hugin__permission_prompt"));
  check("AI2 claude args include --mcp-config + --strict-mcp-config", argv.includes("--mcp-config") && argv.includes("--strict-mcp-config"));
  check("AI3 claude args keep --permission-mode default (gate can fire)", argv.includes("--permission-mode") && argv[argv.indexOf("--permission-mode") + 1] === "default");
  const mcp = JSON.parse(readFileSync(mcpOut, "utf8")) as { mcpServers?: { hugin?: { type?: string; command?: string; env?: { HUGIN_APPROVAL_SOCK?: string } } } };
  const hugin = mcp.mcpServers?.hugin;
  check(
    "AI4 mcp-config declares the hugin stdio server + HUGIN_APPROVAL_SOCK",
    hugin?.type === "stdio" && hugin.command === permissionServerLaunch().command && typeof hugin.env?.HUGIN_APPROVAL_SOCK === "string",
  );
  // read_only (default) must DISALLOW the write/exec tools (enforced sandbox).
  check(
    "AI5 read_only enforced: --disallowedTools includes Write/Edit/Bash",
    argv.includes("--disallowedTools") && argv.includes("Write") && argv.includes("Edit") && argv.includes("Bash"),
  );

  // workspace_write must NOT disallow those tools (they run, gated by the bridge).
  const wwArgvOut = join(base, "argv-ww.json");
  const engineWW = new ClaudeEngine({ command: fakeClaude, env: { HG_ARGV_OUT: wwArgvOut }, allowlist: [repo], stateDir: base, timeoutMs: 30_000 });
  const runWW = engineWW.run({ engine: "claude", prompt: "hi", attemptId: "wire2", repoRoot: repo, sandbox: "workspace_write" });
  await new Promise<void>((res) => runWW.onDone(() => res()));
  await sleep(50);
  const wwArgv = JSON.parse(readFileSync(wwArgvOut, "utf8")) as string[];
  check("AI6 workspace_write leaves write tools enabled (no --disallowedTools)", !wwArgv.includes("--disallowedTools"));
  rmSync(base, { recursive: true, force: true });
}

/** Track B gate self-check (CI-safe): selfCheckGate asks a FAKE claude to WRITE a
 *  sentinel, DENIES it, and requires the write to have been BLOCKED. Proves the
 *  gate is "live" only when a dangerous tool both routes through the prompt AND is
 *  actually stopped by a deny — not merely that the prompt was called. */
async function scenarioAJ(): Promise<void> {
  const base = join(SCRATCH, "gatecheck");
  rmSync(base, { recursive: true, force: true });
  mkdirSync(base, { recursive: true });
  const mk = (name: string, body: string): string => {
    const p = join(base, name);
    writeFileSync(p, `#!/usr/bin/env node\n${body}`);
    chmodSync(p, 0o755);
    return p;
  };
  // Connect to the bridge (via the --mcp-config socket) and raise a Write prompt.
  const CONNECT = `const fs=require('fs'),net=require('net');
const a=process.argv.slice(2);
const cfg=JSON.parse(fs.readFileSync(a[a.indexOf('--mcp-config')+1],'utf8'));
const c=net.connect(cfg.mcpServers.hugin.env.HUGIN_APPROVAL_SOCK);
let b='';
c.on('error',()=>process.exit(1));
c.on('connect',()=>c.write(JSON.stringify({t:'req',id:'p',tool_name:'Write',input:{file_path:process.env.HUGIN_GATE_SENTINEL,content:'X'}})+'\\n'));`;
  const fires = mk("claude-fires.js", `${CONNECT}
c.on('data',(d)=>{b+=d;if(b.includes('"decision"')){c.end();process.exit(0);}});`); // honors deny → no write
  const ignores = mk("claude-ignores.js", `${CONNECT}
c.on('data',(d)=>{b+=d;if(b.includes('"decision"')){fs.writeFileSync(process.env.HUGIN_GATE_SENTINEL,'X');c.end();process.exit(0);}});`); // ignores deny → writes
  const preapproved = mk("claude-preapproved.js", "require('fs').writeFileSync(process.env.HUGIN_GATE_SENTINEL,'X');process.exit(0);"); // never prompts → writes

  const firesR = await selfCheckGate({}, fires, 8000);
  check("AJ1 gate LIVE: prompt fired AND deny blocked the write → gateFires", firesR.gateFires === true);
  const ignoresR = await selfCheckGate({}, ignores, 8000);
  check("AJ2 deny NOT honored (write despite prompt) → gate unavailable (fail closed)", ignoresR.gateFires === false);
  const preR = await selfCheckGate({}, preapproved, 5000);
  check("AJ3 tool pre-approved (no prompt, write happened) → gate unavailable (fail closed)", preR.gateFires === false);
  rmSync(base, { recursive: true, force: true });
}

/** Track B env-auth injection (CI-safe): buildIsolation folds ANTHROPIC_API_KEY /
 *  CLAUDE_CODE_OAUTH_TOKEN into the isolated child env (the isolation-finding
 *  unblock), and injects nothing when neither is set. */
function scenarioAK(): void {
  const base = join(SCRATCH, "envauth");
  rmSync(base, { recursive: true, force: true });
  const prevKey = process.env.ANTHROPIC_API_KEY;
  const prevTok = process.env.CLAUDE_CODE_OAUTH_TOKEN;
  try {
    process.env.ANTHROPIC_API_KEY = "sk-ant-e2e-fake";
    delete process.env.CLAUDE_CODE_OAUTH_TOKEN;
    const iso = buildIsolation("home-swap", base);
    check(
      "AK1 env-auth (ANTHROPIC_API_KEY) injected into the isolated child env",
      iso.env.ANTHROPIC_API_KEY === "sk-ant-e2e-fake" && iso.env.HOME === join(base, "isolation", "home-swap"),
    );
    iso.cleanup();

    delete process.env.ANTHROPIC_API_KEY;
    const iso2 = buildIsolation("config-dir", base);
    check(
      "AK2 no env-auth set → none injected (child relies on host login)",
      iso2.env.ANTHROPIC_API_KEY === undefined && iso2.env.CLAUDE_CODE_OAUTH_TOKEN === undefined,
    );
    iso2.cleanup();
  } finally {
    if (prevKey !== undefined) process.env.ANTHROPIC_API_KEY = prevKey;
    else delete process.env.ANTHROPIC_API_KEY;
    if (prevTok !== undefined) process.env.CLAUDE_CODE_OAUTH_TOKEN = prevTok;
    else delete process.env.CLAUDE_CODE_OAUTH_TOKEN;
    rmSync(base, { recursive: true, force: true });
  }
}

async function scenarioAT(): Promise<void> {
  const base = join(SCRATCH, "resume-env");
  rmSync(base, { recursive: true, force: true });
  mkdirSync(base, { recursive: true });
  const prevSentinel = process.env.HUGIN_RESUME_SECRET_SENTINEL;
  try {
    process.env.HUGIN_RESUME_SECRET_SENTINEL = "host-only-secret";
    const fakeCli = join(base, "fake-resume-cli.js");
    writeFileSync(
      fakeCli,
      `#!/usr/bin/env node
const fs = require('fs');
const envOut = process.env.HG_ENV_OUT;
if (envOut) {
  fs.writeFileSync(envOut, JSON.stringify({
    sentinel: process.env.HUGIN_RESUME_SECRET_SENTINEL ?? null,
    overlay: process.env.HG_ENV_OVERLAY ?? null
  }));
}
const argv = process.argv.slice(2);
const outputIdx = argv.indexOf('-o');
if (outputIdx >= 0) fs.writeFileSync(argv[outputIdx + 1], 'resume done');
console.log(JSON.stringify({ type: 'result', result: 'resume done', session_id: 'resume-env-session' }));
`,
    );
    chmodSync(fakeCli, 0o755);

    const runAndReadEnv = async (engine: "claude" | "codex", out: string): Promise<Record<string, unknown>> => {
      const runner =
        engine === "claude"
          ? new ClaudeResumeRunner({ command: fakeCli, env: { HG_ENV_OUT: out, HG_ENV_OVERLAY: `${engine}-overlay` } })
          : new CodexResumeRunner({ command: fakeCli, env: { HG_ENV_OUT: out, HG_ENV_OVERLAY: `${engine}-overlay` } });
      const run = runner.run({
        engine,
        sessionId: "resume-env-session",
        cwd: base,
        message: "continue",
        fork: false,
        sandbox: "read_only",
      });
      await new Promise<void>((resolve) => run.onDone(() => resolve()));
      return JSON.parse(readFileSync(out, "utf8")) as Record<string, unknown>;
    };

    const claudeEnv = await runAndReadEnv("claude", join(base, "claude-env.json"));
    const codexEnv = await runAndReadEnv("codex", join(base, "codex-env.json"));
    check(
      "AT1 resume runners spawn with scrubbed env overlays and no host sentinel",
      claudeEnv.overlay === "claude-overlay" &&
        claudeEnv.sentinel === null &&
        codexEnv.overlay === "codex-overlay" &&
        codexEnv.sentinel === null,
    );
  } finally {
    if (prevSentinel !== undefined) process.env.HUGIN_RESUME_SECRET_SENTINEL = prevSentinel;
    else delete process.env.HUGIN_RESUME_SECRET_SENTINEL;
    rmSync(base, { recursive: true, force: true });
  }
}

async function main(): Promise<void> {
  console.log("=== hugind e2e (P1–P5 + Track A auth + Track B approval) ===\n[scenario A: live handshake + heartbeat + reconnect]");
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
  console.log("\n[scenario Z: graceful drain on stop]");
  await scenarioZ();
  console.log("\n[scenario AX: lifecycle CLI detached resident process]");
  await scenarioAX();
  console.log("\n[scenario AA: Track A live positive — verifying relay accepts real signer]");
  await scenarioAA();
  console.log("\n[scenario AB: Track A live negative — tampered transcript → bad_signature]");
  await scenarioAB();
  console.log("\n[scenario AC: Track A relay verifyHello vs committed F4 vectors]");
  scenarioAC();
  console.log("\n[scenario AD: Track A OS-keychain round-trip (guarded)]");
  await scenarioAD();
  console.log("\n[scenario AE: Track A rev2 device pairing — AE1–AE9]");
  await scenarioAE();
  console.log("\n[scenario AL: simple pairing mode — gate, strict 200, and WSS handshake]");
  await scenarioAL();
  console.log("\n[scenario AM: simple pairing Rev 2 — interactive UX + dev-origin relaxation]");
  await scenarioAM();
  console.log("\n[scenario AF: Track A duplicate post-auth hello ignored]");
  await scenarioAF();
  console.log("\n[scenario AG: Track A premature hello.accepted discarded]");
  await scenarioAG();
  console.log("\n[scenario AN: protocol-version negotiation]");
  await scenarioAN();
  console.log("\n[scenario AO: v2 session.list plumbing]");
  await scenarioAO();
  console.log("\n[scenario AP: fixture-backed session enumeration]");
  await scenarioAP();
  console.log("\n[scenario AW: v2 session history handler]");
  await scenarioAW();
  console.log("\n[scenario AV: session history reader]");
  scenarioAV();
  console.log("\n[scenario AQ: v2 session resume turn]");
  await scenarioAQ();
  console.log("\n[scenario AR: v2 Claude resume lifecycle controls]");
  await scenarioAR();
  console.log("\n[scenario AS: v2 Codex continue-only resume turn]");
  await scenarioAS();
  console.log("\n[scenario AH: Track B approval bridge round-trip (MCP client stand-in)]");
  await scenarioAH();
  console.log("\n[scenario AI: Track B ClaudeEngine permission-prompt-tool wiring (fake claude)]");
  await scenarioAI();
  console.log("\n[scenario AJ: Track B gate self-check drives gateAvailable (fake claude)]");
  await scenarioAJ();
  console.log("\n[scenario AK: Track B env-auth injection into isolation]");
  scenarioAK();
  console.log("\n[scenario AT: session resume env scrub]");
  await scenarioAT();
  console.log(`\n${failures === 0 ? `ALL E2E PASS` : `${failures} e2e failure(s)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
