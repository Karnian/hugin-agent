/**
 * `hugin-agent connect --server <url>` — pair this device (auth-pairing-spec §3).
 *
 *   npm run connect -- --server https://relay.example.com
 *
 * Generates an Ed25519 device key (private key → OS keychain), runs the
 * device-code flow, and on approval persists the non-secret pairing config
 * (agent_id/key_id/tenant_id/serverUrl). The private key never leaves the host.
 */

import { connect } from "./auth/connect";
import { log } from "./log";

interface Args {
  server?: string;
  config?: string;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--server" || a === "-s") args.server = argv[++i];
    else if (a === "--config" || a === "-c") args.config = argv[++i];
    else if (a === "--help" || a === "-h") args.help = true;
    else if (a?.startsWith("--server=")) args.server = a.slice("--server=".length);
    else if (a?.startsWith("--config=")) args.config = a.slice("--config=".length);
    else if (a) {
      log.error("unknown argument", { arg: a });
      args.help = true;
    }
  }
  return args;
}

const USAGE = `hugin-agent connect — pair this device with a Hugin relay

  hugin-agent connect --server <url> [--config <path>]

  --server, -s   Pairing server base URL (https:// in production).
  --config, -c   Config-file path override (default: ~/.config/hugin-agent/config.json
                 or $HUGIND_CONFIG / $HUGIND_CONFIG_DIR / $XDG_CONFIG_HOME).
  --help,   -h   Show this help.`;

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.server) {
    console.log(USAGE);
    process.exit(args.help ? 0 : 1);
  }

  try {
    const res = await connect({
      serverUrl: args.server,
      configPath: args.config,
      onUserCode: (i) => {
        console.log(`\n  To finish pairing, visit:\n    ${i.verificationUri}\n  and enter code:  ${i.userCode}\n`);
      },
    });
    console.log(
      `paired ✓  agent_id=${res.agentId}  key_id=${res.keyId}  tenant_id=${res.tenantId}\n` +
        `  relay:  ${res.serverUrl}\n` +
        `  config: ${res.configPath} (non-secret)\n` +
        `  device private key stored in the OS keychain — start the daemon with: npm run hugind`,
    );
  } catch (e) {
    log.error("pairing failed", { err: String(e) });
    process.exit(1);
  }
}

main().catch((e) => {
  log.error("fatal", { err: String(e) });
  process.exit(1);
});
