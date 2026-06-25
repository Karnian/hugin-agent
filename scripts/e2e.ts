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

import { LIMITS } from "../protocol/v1/index";
import { loadConfig } from "../src/config";
import { Daemon } from "../src/daemon";
import { devSigner } from "../src/conn/handshake";
import { decodeInbound } from "../src/conn/framing";
import { RelayClient } from "../src/conn/client";
import { MockRelay } from "../mock-relay/server";

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
  });
  const daemon = new Daemon(config, devSigner());
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
  const d = new Daemon(loadConfig({ serverUrl: "wss://relay.example.com", agentId: "a" }), devSigner());
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
  const daemon = new Daemon(loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-epoch" }), devSigner());
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

async function main(): Promise<void> {
  console.log("=== hugind P1 e2e ===\n[scenario A: live handshake + heartbeat + reconnect]");
  await scenarioA();
  console.log("\n[scenario B: framing + epoch gate]");
  scenarioB();
  console.log("\n[scenario C: non-monotonic epoch rejection (live)]");
  await scenarioC();
  console.log("\n[scenario Q: inbound-queue race]");
  await scenarioQueueRace();
  console.log(`\n${failures === 0 ? `ALL E2E PASS` : `${failures} e2e failure(s)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
