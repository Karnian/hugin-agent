/**
 * `hugin-agent connect` — pair this device with a browser-minted hpk1 token.
 *
 * Generates an Ed25519 device key (private key -> OS keychain), proves
 * possession to the pairing endpoint, and persists the non-secret pairing config
 * after browser fingerprint confirmation. The private key never leaves the host.
 */

import { connect, connectSimple } from "./auth/connect";
import { log } from "./log";
import { canonicalizeDevOrigin, simplePairingGateEnabled } from "./simple-pairing-dev";

const MAX_TOKEN_BYTES = 1024;
const MAX_RELAY_URL_PROMPTS = 3;
const SIMPLE_PAIRING_DISABLED_ERROR = "simple pairing is disabled; set HUGIN_SIMPLE_PAIRING=1 for dev, or omit --url for rev2";
const SIMPLE_PAIRING_NEEDS_URL_NON_TTY_ERROR = "simple pairing needs --url when input is not a terminal";
const SIMPLE_PAIRING_URL_ERROR = "simple pairing relay URL is invalid; provide a canonical dev ws(s):// relay origin";

interface Args {
  config?: string;
  url?: string;
  help: boolean;
  valid: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { help: false, valid: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--config" || a === "-c") {
      const value = argv[++i];
      if (!value) args.valid = false;
      else args.config = value;
    } else if (a === "--url") {
      const value = argv[++i];
      if (!value) args.valid = false;
      else args.url = value;
    } else if (a === "--help" || a === "-h") args.help = true;
    else if (a?.startsWith("--config=")) args.config = a.slice("--config=".length);
    else if (a?.startsWith("--url=")) {
      const value = a.slice("--url=".length);
      if (!value) args.valid = false;
      else args.url = value;
    }
    else if (a) {
      log.error("unknown argument; pairing tokens are read from hidden stdin");
      args.valid = false;
    }
  }
  return args;
}

const USAGE = `hugin-agent connect — pair this device with a Hugin relay

  hugin-agent connect [--config <path>] [--url <origin>]

  --config, -c   Config-file path override (default: ~/.config/hugin-agent/config.json
                 or $HUGIND_CONFIG / $HUGIND_CONFIG_DIR / $XDG_CONFIG_HOME).
  --url          Dev-only simple pairing origin. Optional when HUGIN_SIMPLE_PAIRING=1
                 and stdin is an interactive terminal.
  --help,   -h   Show this help.

Paste the hpk1 pairing token from your browser when prompted. Input is hidden.
With HUGIN_SIMPLE_PAIRING=1, provide the relay URL first, then paste the simple
device code when prompted.`;

function stripOneTrailingLineEnding(s: string): string {
  if (s.endsWith("\r\n")) return s.slice(0, -2);
  if (s.endsWith("\n") || s.endsWith("\r")) return s.slice(0, -1);
  return s;
}

function tooLargeError(): Error {
  return new Error("pairing token is too large; re-copy the token");
}

async function readPipedToken(): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > MAX_TOKEN_BYTES) {
      throw tooLargeError();
    }
    chunks.push(buf);
  }
  return stripOneTrailingLineEnding(Buffer.concat(chunks).toString("utf8"));
}

function canPromptInteractively(): boolean {
  return Boolean(process.stdin.isTTY && typeof process.stdin.setRawMode === "function");
}

async function readPromptedInput(prompt: string, opts: { echo: boolean }): Promise<string> {
  if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
    return readPipedToken();
  }

  process.stderr.write(prompt);
  return new Promise<string>((resolve, reject) => {
    const stdin = process.stdin;
    const wasRaw = Boolean(stdin.isRaw);
    let token = "";
    let bytes = 0;
    let settled = false;

    const cleanup = () => {
      stdin.off("data", onData);
      stdin.setRawMode(wasRaw);
      stdin.pause();
      process.stderr.write("\n");
    };
    const finish = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(token);
    };
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };
    const appendByte = (byte: number) => {
      const ch = String.fromCharCode(byte);
      const nextBytes = bytes + Buffer.byteLength(ch, "utf8");
      if (nextBytes > MAX_TOKEN_BYTES) {
        fail(tooLargeError());
        return;
      }
      token += ch;
      bytes = nextBytes;
      if (opts.echo) process.stderr.write(ch);
    };
    const onData = (chunk: Buffer) => {
      for (const byte of chunk) {
        if (byte === 3) {
          fail(new Error("pairing cancelled"));
          return;
        }
        if (byte === 4 || byte === 10 || byte === 13) {
          finish();
          return;
        }
        if (byte === 8 || byte === 127) {
          if (token.length > 0) {
            const removed = token.at(-1) ?? "";
            token = token.slice(0, -1);
            bytes -= Buffer.byteLength(removed, "utf8");
            if (opts.echo) process.stderr.write("\b \b");
          }
          continue;
        }
        appendByte(byte);
        if (settled) return;
      }
    };

    stdin.setRawMode(true);
    stdin.resume();
    stdin.on("data", onData);
  });
}

async function readHiddenToken(prompt = "Paste pairing token: "): Promise<string> {
  return readPromptedInput(prompt, { echo: false });
}

async function promptForRelayUrl(): Promise<string> {
  if (!canPromptInteractively()) {
    throw new Error(SIMPLE_PAIRING_NEEDS_URL_NON_TTY_ERROR);
  }

  for (let attempt = 1; attempt <= MAX_RELAY_URL_PROMPTS; attempt++) {
    const entered = await readPromptedInput("Relay URL (ws(s)://host[:port]): ", { echo: true });
    const canonical = canonicalizeDevOrigin(entered);
    if (canonical !== null) return canonical;
    if (attempt < MAX_RELAY_URL_PROMPTS) {
      process.stderr.write(`${SIMPLE_PAIRING_URL_ERROR}\n`);
    }
  }
  throw new Error(SIMPLE_PAIRING_URL_ERROR);
}

async function resolveSimpleRelayUrl(argUrl: string | undefined): Promise<string> {
  if (argUrl !== undefined) {
    const canonical = canonicalizeDevOrigin(argUrl);
    if (canonical === null) throw new Error(SIMPLE_PAIRING_URL_ERROR);
    return canonical;
  }
  return promptForRelayUrl();
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.valid) {
    console.log(USAGE);
    process.exit(args.help ? 0 : 1);
  }

  try {
    const simpleMode = simplePairingGateEnabled(process.env.HUGIN_SIMPLE_PAIRING);
    if (args.url !== undefined && !simpleMode) {
      throw new Error(SIMPLE_PAIRING_DISABLED_ERROR);
    }

    const serverUrl = simpleMode ? await resolveSimpleRelayUrl(args.url) : "";
    const hidden = await readHiddenToken(simpleMode ? "Paste device code: " : "Paste pairing token: ");
    const res = simpleMode
      ? await connectSimple({
          deviceCode: hidden,
          serverUrl,
          configPath: args.config,
        })
      : await connect({
          token: hidden,
          configPath: args.config,
          onFingerprint: (fp) => {
            console.log(`\nFingerprint:\n  ${fp}\n\nConfirm this fingerprint in your browser to finish.\n`);
          },
        });
    console.log(
      `paired ✓  agent_id=${res.agentId}  key_id=${res.keyId}  tenant_id=${res.tenantId}\n` +
        `  relay:  ${res.serverUrl}\n` +
        `  config: ${res.configPath} (non-secret)\n` +
        `  device private key stored in the OS keychain — start the daemon with: npm run hugind`,
    );
  } catch (e) {
    log.error("pairing failed", { err: e instanceof Error ? e.message : "unknown error" });
    process.exit(1);
  }
}

main().catch((e) => {
  log.error("fatal", { err: String(e) });
  process.exit(1);
});
