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
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import type { MessageV2 } from "../protocol/v1/index";
import { loadConfig } from "../src/config";
import { Daemon } from "../src/daemon";
import { devSigner } from "../src/conn/handshake";
import { ClaudeEngine } from "../src/engine/claude";
import { buildIsolation, selfCheckGate, selfCheckLogin } from "../src/engine/isolate";
import { ClaudeResumeRunner, CodexResumeRunner } from "../src/sessions/resume";
import { SessionResumeManager } from "../src/sessions/resume-manager";
import { MockRelay } from "../mock-relay/server";

const SCRATCH = join(tmpdir(), "hugind-e2e-claude");

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

function createRememberingClaudeSession(repo: string): string {
  const out = execFileSync(
    "claude",
    ["-p", "Remember codeword for this session: ZZZ. Reply exactly: stored.", "--output-format", "json"],
    { cwd: repo, encoding: "utf8", timeout: 120_000 },
  );
  const parsed = JSON.parse(out.trim()) as { session_id?: unknown };
  if (typeof parsed.session_id !== "string" || parsed.session_id.length === 0) {
    throw new Error("claude json output did not include session_id");
  }
  return parsed.session_id;
}

function createRememberingCodexSession(dir: string): { sessionId: string; skipped: false } | { skipped: true; detail: string } {
  mkdirSync(dir, { recursive: true });
  const started = Date.now();
  let out = "";
  try {
    out = execFileSync(
      "codex",
      ["exec", "-s", "read-only", "--json", "--skip-git-repo-check", "Remember codeword: QQQ. reply stored."],
      { cwd: dir, encoding: "utf8", input: "", timeout: 120_000 },
    );
  } catch (e) {
    return { skipped: true, detail: String((e as Error).message ?? e) };
  }
  const streamSessionId = codexSessionIdFromJsonl(out);
  const sessionId = streamSessionId ?? newestCodexSessionIdForCwd(dir, started);
  if (!sessionId) return { skipped: true, detail: "codex session id was not discoverable from stream or session logs" };
  return { skipped: false, sessionId };
}

async function resumeRememberingClaudeSession(repo: string, sessionId: string): Promise<MessageV2[]> {
  const messages: MessageV2[] = [];
  const handle = "live-claude-resume-handle";
  const target = {
    engine: "claude" as const,
    session_id: sessionId,
    cwd: repo,
    path: join(repo, `${sessionId}.jsonl`),
    mtime: Date.now(),
  };
  const manager = new SessionResumeManager((m) => messages.push(m), {
    enumerator: {
      validateHandle: (h) => (h === handle ? target : null),
      registerForked: (forked) => `live-fork-${forked.session_id}`,
    },
    runners: { claude: new ClaudeResumeRunner() },
    turnTimeoutMs: 120_000,
  });
  manager.handleRequest({
    id: "live-resume-message",
    ts: new Date().toISOString(),
    type: "session.resume.request",
    request_id: "live-resume",
    handle,
    message: "What codeword did I ask you to remember earlier in this session? Reply with only the codeword. Do not use tools.",
  });
  await waitUntil(() => messages.some((m) => m.type === "session.turn.result"), 120_000, 250);
  return messages;
}

async function resumeRememberingCodexSession(dir: string, sessionId: string): Promise<MessageV2[]> {
  const messages: MessageV2[] = [];
  const handle = "live-codex-resume-handle";
  const target = {
    engine: "codex" as const,
    session_id: sessionId,
    cwd: dir,
    path: join(dir, `${sessionId}.jsonl`),
    mtime: Date.now(),
  };
  const manager = new SessionResumeManager((m) => messages.push(m), {
    enumerator: {
      validateHandle: (h) => (h === handle ? target : null),
      registerForked: () => {
        throw new Error("codex resume must not register a fork");
      },
    },
    runners: { codex: new CodexResumeRunner() },
    turnTimeoutMs: 120_000,
  });
  manager.handleRequest({
    id: "live-codex-resume-message",
    ts: new Date().toISOString(),
    type: "session.resume.request",
    request_id: "live-codex-resume",
    handle,
    message: "What codeword did I ask you to remember earlier in this session? Reply with only the codeword. Do not use tools.",
  });
  await waitUntil(() => messages.some((m) => m.type === "session.turn.result"), 120_000, 250);
  return messages;
}

function codexSessionIdFromJsonl(out: string): string | null {
  for (const line of out.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as { session_id?: unknown; thread_id?: unknown; payload?: unknown };
      if (typeof parsed.session_id === "string" && parsed.session_id.length > 0) return parsed.session_id;
      // `codex exec --json` emits `thread_id` (= the resumable session UUID, matching the
      // rollout filename); there is no `session_id` field on the stream.
      if (typeof parsed.thread_id === "string" && parsed.thread_id.length > 0) return parsed.thread_id;
      const payload = parsed.payload && typeof parsed.payload === "object" ? (parsed.payload as { id?: unknown }) : null;
      if (typeof payload?.id === "string" && payload.id.length > 0) return payload.id;
    } catch {
      /* ignore non-json warnings */
    }
  }
  return null;
}

function newestCodexSessionIdForCwd(cwd: string, sinceMs: number): string | null {
  const root = join(homedir(), ".codex", "sessions");
  if (!existsSync(root)) return null;
  const files: Array<{ path: string; mtime: number }> = [];
  const scan = (dir: string, depth: number) => {
    if (depth > 12) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        scan(path, depth + 1);
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith(".jsonl")) continue;
      const st = statSync(path);
      if (st.mtimeMs >= sinceMs) files.push({ path, mtime: st.mtimeMs });
    }
  };
  scan(root, 0);
  files.sort((a, b) => b.mtime - a.mtime);
  for (const file of files) {
    const sessionId = codexSessionIdFromFile(file.path, cwd);
    if (sessionId) return sessionId;
  }
  return null;
}

function codexSessionIdFromFile(path: string, cwd: string): string | null {
  const match = /rollout-.+-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.jsonl$/.exec(path);
  try {
    const content = readFileSync(path, "utf8");
    for (const line of content.split(/\r?\n/).slice(0, 20)) {
      if (!line.trim()) continue;
      const parsed = JSON.parse(line) as { type?: unknown; payload?: unknown };
      const payload = parsed.payload && typeof parsed.payload === "object" ? (parsed.payload as { cwd?: unknown; id?: unknown }) : null;
      if (parsed.type === "session_meta" && payload?.cwd === cwd) {
        return typeof payload.id === "string" && payload.id.length > 0 ? payload.id : match?.[1] ?? null;
      }
    }
  } catch {
    return null;
  }
  return null;
}

async function main(): Promise<void> {
  console.log("=== hugind P2b real-CLI validation ===");
  const repo = join(SCRATCH, "repo");
  const stateDir = join(SCRATCH, "state");
  throwawayRepo(repo);

  // Finding: is the login logged in under host config, and does isolation keep it?
  const hostLogin = await selfCheckLogin({});
  if (!hostLogin.loggedIn) {
    console.log(`A1 claude login unavailable (${hostLogin.detail}) — skipping live Claude checks.`);
    process.exit(0);
  }
  check("A1 claude is logged in under host config", true);
  const iso = buildIsolation("config-dir", stateDir);
  const isoLogin = await selfCheckLogin(iso.env);
  console.log(`  [finding] config-dir isolation → login ${isoLogin.loggedIn ? "PRESERVED" : "LOST"} (${isoLogin.detail})`);
  iso.cleanup();

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

  console.log("\n[Track C] live Claude session resume");
  try {
    const sessionId = createRememberingClaudeSession(repo);
    const resumeMessages = await resumeRememberingClaudeSession(repo, sessionId);
    const sessionEvents = resumeMessages.filter((m): m is Extract<MessageV2, { type: "session.event" }> => m.type === "session.event");
    const turnResult = resumeMessages.find((m): m is Extract<MessageV2, { type: "session.turn.result" }> => m.type === "session.turn.result");
    check("C1 real claude resume streamed session.event messages", sessionEvents.length > 0);
    check("C2 real claude resume ended with turn.result status ok", turnResult?.status === "ok");
    check("C3 real claude resume final_message contains the remembered codeword", turnResult?.final_message.includes("ZZZ") === true);
  } catch (e) {
    console.log(`✗ C live claude resume failed: ${String((e as Error).message ?? e)}`);
    failures++;
  }

  console.log("\n[Track D] live Codex continue-only session resume");
  const codexDir = join(SCRATCH, "codex");
  const codexSession = createRememberingCodexSession(codexDir);
  if (codexSession.skipped) {
    console.log(`D live codex resume skipped (${codexSession.detail})`);
  } else {
    try {
      const resumeMessages = await resumeRememberingCodexSession(codexDir, codexSession.sessionId);
      const sessionEvents = resumeMessages.filter((m): m is Extract<MessageV2, { type: "session.event" }> => m.type === "session.event");
      const turnResult = resumeMessages.find((m): m is Extract<MessageV2, { type: "session.turn.result" }> => m.type === "session.turn.result");
      check("D1 real codex resume streamed session.event messages", sessionEvents.length > 0);
      check("D2 real codex resume ended with turn.result status ok", turnResult?.status === "ok");
      check("D3 real codex resume final_message contains the remembered codeword", turnResult?.final_message.includes("QQQ") === true);
      check("D4 real codex resume did not return a fork handle", turnResult?.new_session_handle === undefined);
    } catch (e) {
      console.log(`✗ D live codex resume failed: ${String((e as Error).message ?? e)}`);
      failures++;
    }
  }

  // --- Track B: live approval gate (guarded — validated only where it fires) ---
  console.log("\n[Track B] approval-gate live check");
  const gateStateDir = join(SCRATCH, "gate-state");
  rmSync(gateStateDir, { recursive: true, force: true });
  const gateIso = buildIsolation("config-dir", gateStateDir);
  const gate = await selfCheckGate(gateIso.env);
  console.log(`  [finding] gate self-check → ${gate.gateFires ? "LIVE" : "UNAVAILABLE"} (${gate.detail})`);
  if (!gate.gateFires) {
    gateIso.cleanup();
    console.log("  gate not reachable on this host (isolation drops the keychain login + no env-auth).");
    console.log("  → set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN (auth-spec §9) and re-run to validate deny→blocked.");
  } else {
    // A real write job, relay DENIES: the Write tool must route through the LIVE
    // bridge and be blocked. The manager accepts it because gateAvailable=true.
    let approvalTool: string | null = null;
    let gateResultSeen = false;
    const relayB = new MockRelay({
      approvalDecision: "deny",
      onApprovalRequest: (m) => {
        approvalTool = m.tool_name;
      },
      onResult: () => {
        gateResultSeen = true;
      },
      onAccept: (ctx) =>
        relayB.assign(ctx.ws, {
          job_id: "jg",
          attempt_id: "gate1",
          lease_id: "L1",
          prompt: "Use the Write tool to create a file named gate-test.txt containing HELLO.",
          repo_root: repo,
          sandbox: "workspace_write",
          approval_policy: "on_write",
        }),
    });
    const portB = await relayB.start();
    const engineB = new ClaudeEngine({ env: gateIso.env, allowlist: [repo], stateDir: gateStateDir, timeoutMs: 120_000 });
    const daemonB = new Daemon(
      loadConfig({ serverUrl: `ws://127.0.0.1:${portB}`, agentId: "agent-gate", dbPath: ":memory:", projectRoots: [repo] }),
      devSigner(),
      engineB,
      true, // gateAvailable — the self-check just passed
    );
    void daemonB.start().catch((e) => console.error("daemonB", e));
    await waitUntil(() => gateResultSeen, 120_000);
    check("B1 real claude routed a tool through the LIVE approval bridge (approval.request forwarded)", approvalTool !== null);
    check("B2 denied gated job reached a terminal result (deny handled, not hung)", gateResultSeen);
    console.log(`  routed tool: ${approvalTool ?? "(none)"} — manual: confirm gate-test.txt was NOT written to the attempt worktree.`);
    daemonB.stop();
    await relayB.stop();
    gateIso.cleanup();
    await sleep(100);
  }

  console.log(`\n${failures === 0 ? "ALL REAL-CLI CHECKS PASS" : `${failures} failure(s)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
