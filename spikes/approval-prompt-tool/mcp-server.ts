/**
 * Mock MCP "permission prompt" server for the approval spike.
 *
 * Claude Code's `--permission-prompt-tool mcp__approval__permission_prompt`
 * routes every tool-permission decision (in non-interactive `-p` mode) to this
 * tool. We do NOT validate the input — the whole point is to CAPTURE whatever
 * shape Claude actually sends, because that contract is undocumented.
 *
 * Behavior:
 *   - dump every call's raw arguments to stderr + $HUGIN_SPIKE_OUT
 *   - return allow/deny based on $HUGIN_SPIKE_DECISION (default: allow)
 *
 * Response shape follows the community-known contract:
 *   allow -> { "behavior": "allow", "updatedInput": <input> }
 *   deny  -> { "behavior": "deny",  "message": "..." }
 * If that shape is wrong, the spike's allow/deny scenarios will diverge from
 * the observed file side-effects and we'll know.
 */

import { appendFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const OUT = process.env.HUGIN_SPIKE_OUT;
const DECISION = process.env.HUGIN_SPIKE_DECISION === "deny" ? "deny" : "allow";

function capture(label: string, data: unknown) {
  const line = `${label} ${JSON.stringify(data)}`;
  process.stderr.write(`[spike-mcp] ${line}\n`);
  if (OUT) appendFileSync(OUT, line + "\n");
}

const server = new Server(
  { name: "hugin-spike-approval", version: "0.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  // capture LIST so the runner can tell "server reachable" from "gate skipped"
  capture("LIST", {});
  return {
    tools: [
      {
        name: "permission_prompt",
        description: "Spike: approve or deny a tool invocation.",
        // Deliberately permissive so we observe Claude's real argument shape.
        inputSchema: { type: "object", additionalProperties: true },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  capture("CALL", { name: req.params.name, arguments: req.params.arguments });

  const input = (req.params.arguments as Record<string, unknown> | undefined)?.input ?? {};
  const payload =
    DECISION === "allow"
      ? { behavior: "allow", updatedInput: input }
      : { behavior: "deny", message: "spike: denied by HUGIN_SPIKE_DECISION=deny" };

  capture("REPLY", payload);
  return { content: [{ type: "text", text: JSON.stringify(payload) }] };
});

await server.connect(new StdioServerTransport());
process.stderr.write(`[spike-mcp] ready (decision=${DECISION})\n`);
