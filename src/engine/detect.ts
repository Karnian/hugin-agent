import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Message } from "../../protocol/v1/index";

export type EngineCapabilities = Extract<Message, { type: "hello" }>["capabilities"]["engines"];

export interface EngineDetectOpts {
  claudeCommand?: string;
  codexCommand?: string;
  timeoutMs?: number;
}

export async function detectEngineCapabilities(opts: EngineDetectOpts = {}): Promise<EngineCapabilities> {
  const [claude, codex] = await Promise.all([
    detectCommand(opts.claudeCommand ?? "claude", opts.timeoutMs),
    detectCommand(opts.codexCommand ?? "codex", opts.timeoutMs),
  ]);

  return {
    claude,
    codex: { ...codex, logged_in: existsSync(join(homedir(), ".codex", "auth.json")) },
  };
}

function detectCommand(command: string, timeoutMs = 5_000): Promise<EngineCapabilities["claude"]> {
  return new Promise((resolve) => {
    execFile(command, ["--version"], { timeout: timeoutMs, windowsHide: true }, (err, stdout, stderr) => {
      if (err) {
        resolve({ installed: false });
        return;
      }
      const version = parseVersion(`${stdout}\n${stderr}`);
      resolve(version ? { installed: true, version } : { installed: true });
    });
  });
}

function parseVersion(output: string): string | undefined {
  return output.match(/\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/)?.[0];
}
