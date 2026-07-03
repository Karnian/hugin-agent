/**
 * Standalone mock pairing server — a LOCAL stand-in for the Python C2, so you
 * can exercise the real `hugin-agent connect` flow without a cloud relay.
 * DEV / SMOKE-TEST ONLY, not production.
 *
 * Two terminals:
 *   1)  npm run mock-pairing          # prints an hpk1 token; keeps serving /pair
 *   2)  npm run connect               # paste the token when prompted (input is HIDDEN)
 *
 * Simple mode:
 *   1)  npm run mock-pairing -- --simple
 *   2)  HUGIN_SIMPLE_PAIRING=1 npm run connect
 *       # answer the visible relay URL prompt with ws://127.0.0.1:8787
 *       # then paste the printed device code when the hidden prompt appears
 *       # --url ws://127.0.0.1:8787 is still accepted for scripts/CI
 *
 * The mock auto-confirms activation after the client's first status poll
 * (confirmAfterStatusPolls: 1) — this stands in for the human browser
 * fingerprint confirmation. On success, `connect` persists the pairing config
 * (~/.config/hugin-agent/config.json) and stores the device seed in the OS
 * keychain, exactly as it would against a real C2.
 *
 * Override the port with PORT=... (default 8787).
 */

import { MockPairingServer } from "../mock-relay/pairing-server";

const port = Number(process.env.PORT ?? 8787);
const simpleMode = process.argv.includes("--simple") || process.env.PAIRING_MODE === "simple";

async function main(): Promise<void> {
  const server = new MockPairingServer({
    tenantId: "dev-tenant",
    createdByUserId: "dev-user",
    agentId: "dev-agent-01",
    keyId: "dev-key-01",
    // Auto-activate after the client's first status poll (stands in for the
    // browser fingerprint confirm). Set to 0 issues to keep it hands-free.
    confirmAfterStatusPolls: 1,
    // Generous TTLs so you aren't rushed to paste.
    tokenTtlMs: 60 * 60_000,
    pendingTtlMs: 60 * 60_000,
    simplePairing: simpleMode,
  });

  await server.start(port);
  const token = simpleMode ? "" : server.mint();
  const deviceCode = simpleMode ? server.mintSimpleDeviceCode() : "";

  console.log(`\n  mock pairing server: ${server.baseUrl()}  (dev stand-in for the Python C2 — NOT production)\n`);
  if (simpleMode) {
    console.log(`  Simple pairing capability is enabled.`);
    console.log(`  Run: HUGIN_SIMPLE_PAIRING=1 npm run connect`);
    console.log(`  Relay URL prompt: ws://127.0.0.1:${port}`);
    console.log(`  Or for scripts/CI: HUGIN_SIMPLE_PAIRING=1 npm run connect -- --url ws://127.0.0.1:${port}`);
    console.log(`  Paste this device code at the hidden prompt (paste, then press Enter):\n`);
    console.log(`      ${deviceCode}\n`);
  } else {
    console.log(`  Paste this token into \`npm run connect\` (input is hidden — paste, then press Enter):\n`);
    console.log(`      ${token}\n`);
    console.log(`  It auto-confirms after the client's first status poll (≈2s).`);
  }
  console.log(`  On success, connect persists ~/.config/hugin-agent/config.json + a keychain seed.`);
  console.log(`  Ctrl-C to stop.\n`);

  process.on("SIGINT", () => {
    void server.stop().then(() => process.exit(0));
  });
}

main().catch((e) => {
  console.error("mock-pairing failed:", e instanceof Error ? e.message : e);
  process.exit(1);
});
