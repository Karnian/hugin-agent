/**
 * Real approval bridge (Track B): wires Claude Code's `--permission-prompt-tool`
 * to the daemon's `onApprovalRequest` / `resolveApproval` seam (src/engine/types.ts).
 *
 * Two halves in one file:
 *   1. `ApprovalBridge` (daemon-side, in-process): a per-run UNIX-domain-socket
 *      server — NO TCP port, so the outbound-only / no-inbound-port invariant holds
 *      (the socket is a 0600 file, not a network listener). When the permission
 *      subprocess relays a tool prompt it fires `onRequest({requestId,toolName,
 *      input})`; `resolve(requestId,decision,reason)` writes the decision back over
 *      the same connection.
 *   2. The permission MCP server (SUBPROCESS, spawned by claude via `--mcp-config`):
 *      a stdio MCP server exposing `permission_prompt`. On a tool call it CACHES the
 *      original input, relays `{tool_name,input}` to the daemon over the socket,
 *      BLOCKS for the decision, then returns `{behavior:"allow",updatedInput:<cached>}`
 *      / `{behavior:"deny",message}`. Fail-closed: a missing/broken channel => deny.
 *
 * The claude-facing request/response shape is the community / de-facto contract —
 * Anthropic has not published it (CC 2.1.170; see spikes/approval-prompt-tool):
 * args `{tool_name,input,tool_use_id?}` -> content JSON `{behavior,updatedInput|message}`.
 * The daemon-side socket protocol below is OURS and fully unit-tested (via an MCP
 * client stand-in); the claude-facing shape is validated on a suitable host with
 * the guarded `e2e:claude`. permission.ts imports the MCP SDK LAZILY (only in the
 * subprocess), so importing `ApprovalBridge` into the daemon stays SDK-free.
 */

import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { connect, createServer, type Server, type Socket } from "node:net";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ApprovalDecision, ApprovalRequest } from "./types";

const NL = "\n";

/** Subprocess -> daemon: a tool wants permission. */
interface ReqLine {
  t: "req";
  id: string;
  tool_name: string;
  input: unknown;
}
/** Daemon -> subprocess: the remote decision for `id`. */
interface DecisionLine {
  t: "decision";
  id: string;
  decision: ApprovalDecision;
  reason?: string;
}

// ---------------------------------------------------------------------------
// Daemon-side bridge
// ---------------------------------------------------------------------------

export class ApprovalBridge {
  private server: Server | null = null;
  private closed = false;
  private onReq: ((req: ApprovalRequest) => void) | null = null;
  /** requestId -> the connection that raised it (to route the decision back). */
  private readonly pending = new Map<string, Socket>();
  /** Every live connection, so close() can destroy them (else server.close hangs). */
  private readonly sockets = new Set<Socket>();

  constructor(readonly socketPath: string) {}

  /** Bind the UNIX socket (0600). Resolves once listening. */
  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      rmSync(this.socketPath, { force: true }); // clear a stale socket
      mkdirSync(dirname(this.socketPath), { recursive: true });
      const server = createServer((sock) => this.onConnection(sock));
      this.server = server;
      server.on("error", reject);
      server.listen(this.socketPath, () => {
        try {
          chmodSync(this.socketPath, 0o600);
        } catch {
          /* best effort — the socket dir is daemon-owned */
        }
        resolve();
      });
    });
  }

  /** Register the callback fired when the subprocess relays a tool prompt. */
  onRequest(cb: (req: ApprovalRequest) => void): void {
    this.onReq = cb;
  }

  private onConnection(sock: Socket): void {
    this.sockets.add(sock);
    let buf = "";
    sock.on("data", (d: Buffer) => {
      buf += d.toString("utf8");
      let nl: number;
      while ((nl = buf.indexOf(NL)) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let m: ReqLine | undefined;
        try {
          m = JSON.parse(line) as ReqLine;
        } catch {
          continue; // ignore a malformed line
        }
        if (m?.t !== "req" || typeof m.id !== "string") continue;
        this.pending.set(m.id, sock);
        this.onReq?.({ requestId: m.id, toolName: String(m.tool_name ?? "unknown"), input: m.input });
      }
    });
    sock.on("error", () => {});
    sock.on("close", () => {
      this.sockets.delete(sock);
      // Drop any pending requests owned by this connection (their resolve no-ops).
      for (const [id, s] of this.pending) if (s === sock) this.pending.delete(id);
    });
  }

  /** Deliver the remote decision to the subprocess awaiting `requestId`. A stale
   *  id (already answered / connection gone) is a no-op. */
  resolve(requestId: string, decision: ApprovalDecision, reason?: string): void {
    const sock = this.pending.get(requestId);
    if (!sock) return;
    this.pending.delete(requestId);
    const line: DecisionLine = { t: "decision", id: requestId, decision, reason };
    try {
      sock.write(JSON.stringify(line) + NL);
    } catch {
      /* subprocess already gone */
    }
  }

  /** Close the server + unlink the socket. Idempotent; destroys any live
   *  connection first so `server.close()` can't hang on a lingering client. */
  close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.closed) return resolve();
      this.closed = true;
      this.pending.clear();
      for (const s of this.sockets) {
        try {
          s.destroy();
        } catch {
          /* already gone */
        }
      }
      this.sockets.clear();
      const server = this.server;
      this.server = null;
      if (!server) {
        rmSync(this.socketPath, { force: true });
        return resolve();
      }
      server.close(() => {
        rmSync(this.socketPath, { force: true });
        resolve();
      });
    });
  }
}

/** How claude should launch the permission MCP server (for `--mcp-config`). Runs
 *  this file under `tsx` (dev); a compiled deploy would point at the built .js. */
export function permissionServerLaunch(): { command: string; args: string[] } {
  const self = fileURLToPath(import.meta.url);
  const tsxBin = fileURLToPath(new URL("../../node_modules/.bin/tsx", import.meta.url));
  return { command: tsxBin, args: [self] };
}

/** The `--permission-prompt-tool` value addressing this server's tool. */
export const PERMISSION_PROMPT_TOOL = "mcp__hugin__permission_prompt";

/** The `--mcp-config` `mcpServers` object wiring claude to this permission server
 *  over `socketPath`. Shared by ClaudeEngine + the startup gate self-check so the
 *  two can't drift on the config shape. */
export function permissionMcpServers(socketPath: string): Record<string, unknown> {
  const launch = permissionServerLaunch();
  return { hugin: { type: "stdio", command: launch.command, args: launch.args, env: { HUGIN_APPROVAL_SOCK: socketPath } } };
}

/** Create a fresh PER-RUN directory (mode 0700 — owner-only) to hold the approval
 *  socket + mcp-config, so no other local user can reach the socket or tamper with
 *  the config. Short path (unix socket sun_path is length-capped; the daemon's
 *  stateDir can be long). The caller removes it on cleanup. */
export function approvalRunDir(): string {
  return mkdtempSync(join(tmpdir(), "hg-appr-"));
}

// ---------------------------------------------------------------------------
// Subprocess: the stdio MCP permission server
// ---------------------------------------------------------------------------

const DENY_BROKEN = { decision: "deny" as ApprovalDecision, reason: "approval channel unavailable (fail-closed)" };

/** Open a fresh connection to the daemon socket, relay the prompt, and resolve
 *  with the decision. Fail-closed: any error / early close => deny. */
function requestDecision(socketPath: string, toolName: string, input: unknown): Promise<{ decision: ApprovalDecision; reason?: string }> {
  return new Promise((resolve) => {
    const id = randomUUID();
    let settled = false;
    const done = (r: { decision: ApprovalDecision; reason?: string }) => {
      if (settled) return;
      settled = true;
      resolve(r);
    };
    const sock = connect(socketPath);
    let buf = "";
    sock.on("connect", () => sock.write(JSON.stringify({ t: "req", id, tool_name: toolName, input } satisfies ReqLine) + NL));
    sock.on("data", (d: Buffer) => {
      buf += d.toString("utf8");
      let nl: number;
      while ((nl = buf.indexOf(NL)) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line) continue;
        try {
          const m = JSON.parse(line) as DecisionLine;
          if (m.t === "decision" && m.id === id) {
            sock.end();
            done({ decision: m.decision, reason: m.reason });
            return;
          }
        } catch {
          /* skip a malformed line */
        }
      }
    });
    sock.on("error", () => done(DENY_BROKEN));
    sock.on("close", () => done(DENY_BROKEN)); // closed before a decision => fail-closed
  });
}

async function runPermissionServer(): Promise<void> {
  const socketPath = process.env.HUGIN_APPROVAL_SOCK;
  const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  const { CallToolRequestSchema, ListToolsRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");

  const server = new Server({ name: "hugin-approval", version: "1.0.0" }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "permission_prompt",
        description: "Gate a tool invocation through the remote approver.",
        inputSchema: { type: "object", additionalProperties: true },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    const toolName = String(args.tool_name ?? args.toolName ?? "unknown");
    const input = args.input ?? {};
    let payload: Record<string, unknown>;
    if (!socketPath) {
      payload = { behavior: "deny", message: "no approval socket configured (fail-closed)" };
    } else {
      const d = await requestDecision(socketPath, toolName, input);
      payload =
        d.decision === "allow"
          ? { behavior: "allow", updatedInput: input }
          : { behavior: "deny", message: d.reason ?? "denied by remote approver" };
    }
    return { content: [{ type: "text", text: JSON.stringify(payload) }] };
  });

  await server.connect(new StdioServerTransport());
  process.stderr.write("[hugin-approval] permission server ready\n");
}

/** True iff this module is the entry script (claude-spawned subprocess), not an
 *  import (the daemon importing ApprovalBridge). Mirrors gen-vectors.ts. */
function invokedDirectly(): boolean {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  try {
    return fileURLToPath(import.meta.url) === realpathSync(argv1);
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  runPermissionServer().catch((e) => {
    process.stderr.write(`[hugin-approval] fatal: ${String(e)}\n`);
    process.exit(1);
  });
}
