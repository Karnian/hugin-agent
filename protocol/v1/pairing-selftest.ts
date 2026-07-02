/**
 * Pairing PoP conformance self-test — `npm run pairing:check`.
 *
 * Verifies the COMMITTED `pairing-test-vectors.json` against the contract code
 * (`pairing.ts` + `ed25519.ts` + `origin.ts`), exactly like `selftest.ts` does
 * for the frozen F4 auth vectors:
 *   - positives: recomputed transcript is byte-identical, deterministic
 *     re-sign matches, strict verify passes, origin is frozen-canonical,
 *     fingerprint matches;
 *   - negatives: the presented transcript rebuilds byte-identically and
 *     strict verification of the stated signature/key MUST fail.
 *
 * Also regenerates the vectors in-memory and diffs them against the committed
 * JSON, so the committed file can never drift from the generator.
 */

import { readFileSync } from "node:fs";
import { createHash, sign } from "node:crypto";
import {
  buildPairingTranscript,
  keyFingerprint,
  PAIRING_DOMAIN_TAG,
  REJECTED_TEST_PUBLIC_HEX,
  validateB64u32,
} from "./pairing";
import { buildPairingVectors, type PairingVectorsFile } from "./gen-pairing-vectors";
import { PROTOCOL_VERSION } from "./messages";
import { b64u, deriveKeypairFromSeed, verifyTranscript } from "./ed25519";
import { canonicalizeServerOrigin } from "./origin";

const committed: PairingVectorsFile = JSON.parse(
  readFileSync(new URL("./pairing-test-vectors.json", import.meta.url), "utf8"),
);

const checks: Array<[string, boolean]> = [];
const check = (label: string, ok: boolean) => checks.push([label, ok]);

check("schema is 1", committed.schema === 1);
check("domain_tag matches contract", committed.domain_tag === PAIRING_DOMAIN_TAG);
check("protocol_version matches", committed.protocol_version === PROTOCOL_VERSION);
check("rejected test key matches contract", committed.rejected_test_public_hex === REJECTED_TEST_PUBLIC_HEX);
check(
  "committed vectors match the generator (no drift)",
  JSON.stringify(committed) === JSON.stringify(buildPairingVectors()),
);

for (const v of committed.positives) {
  const tag = `pairing+ ${v.label}`;
  const publicRaw = Buffer.from(v.ed25519_public_hex, "hex");
  const transcript = buildPairingTranscript({
    secret: v.secret,
    publicRaw,
    server_origin: v.canonical_server_origin,
    protocol_version: v.protocol_version,
  });
  check(`${tag}: secret is canonical`, validateB64u32(v.secret));
  check(`${tag}: origin is frozen-canonical`, canonicalizeServerOrigin(v.canonical_server_origin) === v.canonical_server_origin);
  check(`${tag}: transcript bytes match`, transcript.toString("hex") === v.transcript_hex);
  check(
    `${tag}: secret_sha256 is over the UTF-8 string`,
    createHash("sha256").update(v.secret, "utf8").digest("hex") === v.secret_sha256_hex,
  );
  const kp = deriveKeypairFromSeed(Buffer.from(v.ed25519_seed_hex, "hex"));
  check(`${tag}: deterministic signature matches`, b64u(sign(null, transcript, kp.privateKey)) === v.expected_pop_signature_base64url);
  check(`${tag}: signature verifies`, verifyTranscript(publicRaw, transcript, v.expected_pop_signature_base64url));
  check(`${tag}: fingerprint matches`, keyFingerprint(publicRaw) === v.fingerprint_base64url);
  check(`${tag}: public_key_base64url matches raw`, v.public_key_base64url === b64u(publicRaw));
}

for (const v of committed.negatives) {
  const tag = `pairing- ${v.label} (${v.failure_mode})`;
  switch (v.failure_mode) {
    case "parse":
      check(`${tag}: rejected at the input gate`, !validateB64u32(v.value!));
      break;
    case "signature": {
      const publicRaw = Buffer.from(v.ed25519_public_hex!, "hex");
      const transcript = buildPairingTranscript({
        secret: v.secret!,
        publicRaw,
        server_origin: v.canonical_server_origin!,
        protocol_version: v.protocol_version!,
      });
      check(`${tag}: presented transcript rebuilds`, transcript.toString("hex") === v.transcript_hex);
      check(`${tag}: rejected`, !verifyTranscript(publicRaw, transcript, v.expected_pop_signature_base64url!));
      break;
    }
    case "policy":
      // The vector pins the key registration must refuse; implementations gate
      // on equality with the published constant (crypto for this key is valid).
      check(`${tag}: pins the published test key`, v.ed25519_public_hex === REJECTED_TEST_PUBLIC_HEX
        && v.public_key_base64url === b64u(Buffer.from(REJECTED_TEST_PUBLIC_HEX, "hex")));
      break;
  }
}

let failures = 0;
for (const [label, ok] of checks) {
  console.log(ok ? `✓ ${label}` : `✗ ${label}`);
  if (!ok) failures++;
}
if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log(`\nAll ${checks.length} pairing checks passed.`);
