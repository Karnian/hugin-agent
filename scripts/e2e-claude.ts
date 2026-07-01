/**
 * hugind P2b real-CLI validation (opt-in — makes real `claude` calls).
 *
 *   npm run e2e:claude      # requires `claude` installed + logged in
 *
 * Drives a real read-only Claude job end-to-end through the daemon + mock relay +
 * ClaudeEngine: spawn `claude -p stream-json` in a throwaway git worktree, parse +
 * normalize the stream, produce a digest-acked terminal result. A read-only reply
 * needs no approval gate, so it validates the adapter on the host config.
 *
 * It also records the isolation finding (does config-dir isolation keep the login
 * on this host?) — the deny→blocked gate itself needs the P3 approval bridge and
 * a host without a permissive global allow-list.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadConfig } from "../src/config";
import { Daemon } from "../src/daemon";
import { devSigner } from "../src/conn/handshake";
import { ClaudeEngine } from "../src/engine/claude";
import { buildIsolation, selfCheckLogin } from "../src/engine/isolate";
import { MockRelay } from "../mock-relay/server";

const SCRATCH = "/private/tmp/claude-501/-Users-k-Desktop-sub-project-hugin-agent/500bdae6-f9cf-45b3-9e5b-a2819e8bcd4b/scratchpad/e2e-claude";

let failures = 0;
function check(label: string, cond: boolean): void {
  console.log(`${cond ? "✓" : "✗"} ${label}`);
  if (!cond) failures++;
}
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
async function waitUntil(pred: () => boolean, timeoutMs: number, stepMs = 100): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pred()) return true;
    await sleep(stepMs);
  }
  return pred();
}

function throwawayRepo(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const git = (...a: string[]) => execFileSync("git", ["-C", dir, ...a], { stdio: "pipe" });
  git("init", "-q");
  git("config", "user.email", "e2e@test.local");
  git("config", "user.name", "e2e");
  writeFileSync(join(dir, "README.md"), "hello\n");
  git("add", "-A");
  git("commit", "-qm", "init");
}

async function main(): Promise<void> {
  console.log("=== hugind P2b real-CLI validation ===");
  const repo = join(SCRATCH, "repo");
  const stateDir = join(SCRATCH, "state");
  throwawayRepo(repo);

  // Finding: is the login logged in under host config, and does isolation keep it?
  const hostLogin = await selfCheckLogin({});
  check("A1 claude is logged in under host config", hostLogin.loggedIn);
  const iso = buildIsolation("config-dir", stateDir);
  const isoLogin = await selfCheckLogin(iso.env);
  console.log(`  [finding] config-dir isolation → login ${isoLogin.loggedIn ? "PRESERVED" : "LOST"} (${isoLogin.detail})`);
  iso.cleanup();

  if (!hostLogin.loggedIn) {
    console.log("\nclaude not logged in — skipping the live adapter run.");
    process.exit(failures === 0 ? 0 : 1);
  }

  // Full adapter path: real read-only job via daemon + mock relay + ClaudeEngine.
  const kinds: string[] = [];
  let resultSeen = false;
  let finalStatus = "";
  const relay = new MockRelay({
    onStreamEvent: (m) => kinds.push(m.event.kind),
    onResult: (m) => {
      resultSeen = true;
      finalStatus = m.final_status;
    },
    onAccept: (ctx) =>
      relay.assign(ctx.ws, {
        job_id: "j1",
        attempt_id: "cli1",
        lease_id: "L1",
        prompt: "Reply with exactly: HELLO. Do not use any tools.",
        repo_root: repo,
      }),
  });
  const port = await relay.start();
  const engine = new ClaudeEngine({ allowlist: [repo], stateDir, timeoutMs: 120_000 });
  const daemon = new Daemon(
    loadConfig({ serverUrl: `ws://127.0.0.1:${port}`, agentId: "agent-cli", dbPath: ":memory:", projectRoots: [repo] }),
    devSigner(),
    engine,
  );
  void daemon.start().catch((e) => console.error("daemon", e));

  const gcd = await waitUntil(() => resultSeen && daemon.pendingResultCount() === 0, 120_000);
  check("A2 adapter spawned claude + produced a terminal result", resultSeen);
  check("A3 result final_status = success (read-only reply)", finalStatus === "success");
  check("A4 stream produced assistant_text", kinds.includes("assistant_text"));
  check("A5 result digest-acked → GC", gcd && daemon.pendingResultCount() === 0);
  console.log(`  stream kinds: ${[...new Set(kinds)].join(", ") || "(none)"}`);

  daemon.stop();
  await relay.stop();
  await sleep(100);
  console.log(`\n${failures === 0 ? "ALL REAL-CLI CHECKS PASS" : `${failures} failure(s)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
