/**
 * Approval spike runner (v2).
 *
 *   npm run spike:approval
 *
 * v1 finding: the host's global ~/.claude (allow:[Write(*),Bash(*)...] +
 * dontAsk) silently pre-approves every tool, so the permission prompt never
 * fires and --permission-prompt-tool is never called.
 *
 * v2 fixes:
 *   - ISOLATE: spawn claude with HOME pointed at a throwaway dir whose
 *     .claude/settings.json has an EMPTY allow-list + permissionMode "default".
 *     (Auth via macOS keychain is per-user, so login should survive HOME swap.)
 *   - FORCE a tool that must be approved: run a Bash command (not on any
 *     allow-list once isolated) so the gate has to fire.
 *   - VERIFY file *contents*, track timedOut/signal separately, add an H4
 *     verdict, and capture the MCP tools/list to tell "no prompt needed" from
 *     "flag ignored".
 *
 * Requires: claude installed + logged in. Makes real model calls.
 */

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(HERE, "..", "..");
const TSX_BIN = join(PROJECT_ROOT, "node_modules", ".bin", "tsx");
const SERVER = join(HERE, "mcp-server.ts");
const OUT_DIR = join(HERE, "out");
const TARGET = "spike.txt";
const EXPECT = "hello";
// Force the Bash tool specifically: once HOME is isolated it is no longer
// allow-listed, so `default` mode must route it through the prompt tool.
const PROMPT = `Use the Bash tool to create a file. Run exactly this command and nothing else: printf '${EXPECT}' > ${TARGET}`;
const TIMEOUT_MS = 120_000;

type Scenario = "allow" | "deny";

interface RunResult {
  scenario: Scenario;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  toolListed: boolean; // MCP served tools/list (server reachable)
  toolCallCount: number; // permission_prompt invoked
  capturedArgs: unknown | null; // raw delegation argument shape (H2)
  fileContentOk: boolean; // file exists AND content === EXPECT (H3)
  approvalInStream: boolean; // prompt tool visible in stream-json (H4)
  streamTypes: Record<string, number>;
  error?: string;
}

function runScenario(scenario: Scenario): Promise<RunResult> {
  const root = join(OUT_DIR, scenario);
  const workdir = join(root, "workspace");
  const home = join(root, "home");
  const capFile = join(root, "captured.ndjson");
  const rawFile = join(root, "claude-stream.ndjson");

  rmSync(root, { recursive: true, force: true });
  mkdirSync(workdir, { recursive: true });
  mkdirSync(join(home, ".claude"), { recursive: true });
  writeFileSync(capFile, "");

  // Isolated settings: empty allow-list, gate live.
  writeFileSync(
    join(home, ".claude", "settings.json"),
    JSON.stringify({ permissions: { allow: [], defaultMode: "default" } }, null, 2),
  );

  const mcpConfig = {
    mcpServers: {
      approval: {
        command: TSX_BIN,
        args: [SERVER],
        env: { HUGIN_SPIKE_OUT: capFile, HUGIN_SPIKE_DECISION: scenario },
      },
    },
  };
  const configPath = join(root, "mcp-config.json");
  writeFileSync(configPath, JSON.stringify(mcpConfig, null, 2));

  const args = [
    "-p", PROMPT,
    "--output-format", "stream-json",
    "--verbose",
    "--mcp-config", configPath,
    "--permission-prompt-tool", "mcp__approval__permission_prompt",
    "--permission-mode", "default",
  ];

  // Isolate HOME so the host allow-list/dontAsk is not inherited. Drop
  // CLAUDE_CONFIG_DIR (it would override HOME and re-introduce host settings).
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home };
  delete env.CLAUDE_CONFIG_DIR;

  return new Promise<RunResult>((resolve) => {
    // stdin "ignore": -p takes the prompt via argv; leaving stdin open makes
    // claude wait for piped input ("no stdin data received in 3s").
    const child = spawn("claude", args, { cwd: workdir, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, TIMEOUT_MS);

    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));

    child.on("error", (err) => {
      clearTimeout(timer);
      resolve(blank(scenario, `spawn failed: ${err.message}`));
    });

    child.on("close", (code, signal) => {
      clearTimeout(timer);
      writeFileSync(rawFile, stdout);

      const streamTypes: Record<string, number> = {};
      let approvalInStream = false;
      for (const line of stdout.split("\n")) {
        const t = line.trim();
        if (!t) continue;
        try {
          const obj = JSON.parse(t) as { type?: string };
          streamTypes[obj.type ?? "<no-type>"] = (streamTypes[obj.type ?? "<no-type>"] ?? 0) + 1;
          if (t.includes("permission_prompt") || t.includes("mcp__approval")) approvalInStream = true;
        } catch {
          /* non-JSON line */
        }
      }

      const captured = existsSync(capFile)
        ? readFileSync(capFile, "utf8").split("\n").filter(Boolean)
        : [];
      const firstCall = captured.find((l) => l.startsWith("CALL"));
      const fileOk =
        existsSync(join(workdir, TARGET)) &&
        readFileSync(join(workdir, TARGET), "utf8").trim() === EXPECT;

      resolve({
        scenario,
        exitCode: code,
        signal,
        timedOut,
        toolListed: captured.some((l) => l.startsWith("LIST")),
        toolCallCount: captured.filter((l) => l.startsWith("CALL")).length,
        capturedArgs: firstCall ? safeJson(firstCall.slice(firstCall.indexOf(" ") + 1)) : null,
        fileContentOk: fileOk,
        approvalInStream,
        streamTypes,
        error: timedOut ? "timed out" : code === 0 ? undefined : stderr.split("\n").filter(Boolean).slice(-2).join(" | "),
      });
    });
  });
}

function blank(scenario: Scenario, error: string): RunResult {
  return {
    scenario, exitCode: null, signal: null, timedOut: false, toolListed: false,
    toolCallCount: 0, capturedArgs: null, fileContentOk: false, approvalInStream: false,
    streamTypes: {}, error,
  };
}
function safeJson(s: string): unknown {
  try { return JSON.parse(s); } catch { return s; }
}

function report(results: RunResult[]) {
  console.log("\n================ APPROVAL SPIKE REPORT (v2) ================\n");
  for (const r of results) {
    console.log(`### scenario: ${r.scenario}`);
    console.log(`  exit / signal     : ${r.exitCode} / ${r.signal}${r.timedOut ? " (TIMED OUT)" : ""}`);
    console.log(`  MCP tools/list    : ${r.toolListed ? "served" : "NOT served"}`);
    console.log(`  H1 tool delegated : ${r.toolCallCount > 0 ? "YES" : "NO"} (called ${r.toolCallCount}x)`);
    console.log(`  H2 captured args  : ${r.capturedArgs ? JSON.stringify(r.capturedArgs) : "—"}`);
    console.log(`  H3 file == "${EXPECT}"  : ${r.fileContentOk ? "YES" : "NO"}`);
    console.log(`  H4 in stream-json : ${r.approvalInStream ? "YES" : "NO"}`);
    console.log(`     stream types   : ${JSON.stringify(r.streamTypes)}`);
    if (r.error) console.log(`  error             : ${r.error}`);
    console.log("");
  }

  const allow = results.find((r) => r.scenario === "allow");
  const deny = results.find((r) => r.scenario === "deny");
  const delegated = results.some((r) => r.toolCallCount > 0);
  console.log("---------------- verdict ----------------");
  console.log(`H1 delegation works : ${delegated ? "✅" : results.some((r) => r.toolListed) ? "❌ (server reachable, but gate never fired)" : "❌ (server unreachable)"}`);
  console.log(`H2 arg shape known  : ${results.some((r) => r.capturedArgs) ? "✅ (see above)" : "❌"}`);
  console.log(`H3 gate controls run: ${allow?.fileContentOk && deny && !deny.fileContentOk ? "✅ allow→wrote, deny→blocked" : "❌ / inconclusive"}`);
  console.log(`H4 visible in stream: ${results.some((r) => r.approvalInStream) ? "✅" : "❌ / inconclusive"}`);
  console.log(`\nRaw captures + streams under: ${OUT_DIR}\n`);
}

async function main() {
  mkdirSync(OUT_DIR, { recursive: true });
  const results: RunResult[] = [];
  for (const scenario of ["allow", "deny"] as Scenario[]) {
    console.log(`\n>>> running scenario: ${scenario} ...`);
    results.push(await runScenario(scenario));
  }
  report(results);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
