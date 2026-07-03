/**
 * Standalone mock pairing server — a LOCAL stand-in for the (not-yet-built)
 * Python C2, so you can exercise the real `hugin-agent connect` (rev2) flow
 * end-to-end without a cloud relay. DEV / SMOKE-TEST ONLY, not production.
 *
 * Two terminals:
 *   1)  npm run mock-pairing          # prints an hpk1 token; keeps serving /pair
 *   2)  npm run connect               # paste the token when prompted (input is HIDDEN)
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
  });

  await server.start(port);
  const token = server.mint();

  console.log(`\n  mock pairing server: ${server.baseUrl()}  (dev stand-in for the Python C2 — NOT production)\n`);
  console.log(`  Paste this token into \`npm run connect\` (input is hidden — paste, then press Enter):\n`);
  console.log(`      ${token}\n`);
  console.log(`  It auto-confirms after the client's first status poll (≈2s).`);
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
