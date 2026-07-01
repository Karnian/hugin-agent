/**
 * F4 — cross-language auth test vectors (generator).
 * ==================================================
 *
 *   tsx protocol/v1/gen-vectors.ts      # (re)writes ./test-vectors.json
 *
 * Emits DETERMINISTIC Ed25519 signing vectors (fixed 32-byte seed) so a Go/Rust
 * verifier can confirm byte-identical transcript construction (auth-pairing-spec
 * §5) and signature verification, independent of this TypeScript implementation.
 *
 * `selftest.ts` imports the helpers below (no side effect on import — the file
 * write is guarded to direct invocation) and verifies the COMMITTED JSON:
 * positives must recompute the same transcript and verify; negatives must fail
 * exactly as documented (schema parse-reject, canonicalization reject, or
 * signature-verify fail).
 *
 * Transcript (auth-pairing-spec §5):
 *   LP(x)      := uint32_be(byte_length(x)) || x        # UTF-8 unless noted
 *   transcript := LP(domain_tag) || LP(challenge_id) || nonce_raw  # nonce: RAW 32B, NO LP
 *              || LP(agent_id) || LP(key_id) || LP(protocol_version)
 *              || LP("ed25519") || LP(tenant_id) || LP(server_origin)
 */

import { sign } from "node:crypto";
import { realpathSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { PROTOCOL_VERSION } from "./messages";
import { ALG, DOMAIN_TAG, buildTranscript, lp } from "./transcript";
import { b64u, deriveKeypairFromSeed } from "./ed25519";
import { canonicalizeServerOrigin, validateTenantId } from "./origin";

// Ed25519 key mechanics (deriveKeypairFromSeed, publicKeyFromRaw, b64u) live in
// ./ed25519 — shared contract code so production signing/verification never
// imports this test generator and the two can never drift. server_origin
// canonicalization + tenant_id grammar live in ./origin (both imported above).

// ---------------------------------------------------------------------------
// Vector shapes
// ---------------------------------------------------------------------------

export interface PositiveVector {
  label: string;
  challenge_id: string;
  nonce_base64url: string;
  nonce_raw_hex: string;
  agent_id: string;
  key_id: string;
  protocol_version: string;
  tenant_id: string;
  input_server_origin: string;
  canonical_server_origin: string;
  domain_tag_hex: string;
  alg_lp_hex: string;
  transcript_hex: string;
  ed25519_seed_hex: string;
  ed25519_public_hex: string;
  expected_signature_base64url: string;
}

export type FailureMode = "parse" | "origin" | "tenant" | "signature";

export interface NegativeVector {
  label: string;
  reason: string;
  failure_mode: FailureMode;
  // failure_mode "parse": embed `value` into `wire_message`.`field` → Message.parse must reject.
  wire_message?: "auth.challenge" | "hello";
  field?: string;
  value?: string;
  // failure_mode "origin": canonicalizeServerOrigin(input_server_origin) must return null.
  input_server_origin?: string;
  // failure_mode "tenant": validateTenantId(tenant_id) must be false.
  tenant_id?: string;
  // failure_mode "signature": rebuild transcript from these fields → verify(expected_sig) must FAIL.
  challenge_id?: string;
  nonce_raw_hex?: string;
  agent_id?: string;
  key_id?: string;
  protocol_version?: string;
  canonical_server_origin?: string;
  ed25519_seed_hex?: string;
  ed25519_public_hex?: string;
  transcript_hex?: string;
  expected_signature_base64url?: string;
}

export interface VectorsFile {
  _comment: string;
  domain_tag: string;
  alg: string;
  ed25519_seed_hex: string;
  ed25519_public_hex: string;
  positives: PositiveVector[];
  negatives: NegativeVector[];
}

// ---------------------------------------------------------------------------
// Fixed inputs
// ---------------------------------------------------------------------------

const SEED_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"; // bytes 0x01..0x20
const NONCE_RAW_HEX = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"; // bytes 0x20..0x3f

const kp = deriveKeypairFromSeed(Buffer.from(SEED_HEX, "hex"));
const PUB_HEX = kp.publicRaw.toString("hex");
const nonceRaw = Buffer.from(NONCE_RAW_HEX, "hex");
const NONCE_B64U = b64u(nonceRaw); // 43 chars

type PositiveOverrides = Partial<
  Pick<
    PositiveVector,
    "challenge_id" | "agent_id" | "key_id" | "protocol_version" | "tenant_id" | "input_server_origin"
  >
>;

function positive(label: string, over: PositiveOverrides): PositiveVector {
  const challenge_id = over.challenge_id ?? "ch-v6-0001";
  const agent_id = over.agent_id ?? "agent-abc";
  const key_id = over.key_id ?? "key-1";
  const protocol_version = over.protocol_version ?? PROTOCOL_VERSION;
  const tenant_id = over.tenant_id ?? "acme";
  const input_server_origin = over.input_server_origin ?? "wss://relay.example.com";

  const canonical = canonicalizeServerOrigin(input_server_origin);
  if (canonical === null) throw new Error(`positive ${label}: non-canonical origin "${input_server_origin}"`);
  if (!validateTenantId(tenant_id)) throw new Error(`positive ${label}: invalid tenant_id`);

  const transcript = buildTranscript({
    challenge_id, nonce_raw: nonceRaw, agent_id, key_id, protocol_version, tenant_id, server_origin: canonical,
  });
  const signature = sign(null, transcript, kp.privateKey);

  return {
    label,
    challenge_id,
    nonce_base64url: NONCE_B64U,
    nonce_raw_hex: NONCE_RAW_HEX,
    agent_id,
    key_id,
    protocol_version,
    tenant_id,
    input_server_origin,
    canonical_server_origin: canonical,
    domain_tag_hex: lp(DOMAIN_TAG).toString("hex"),
    alg_lp_hex: lp(ALG).toString("hex"),
    transcript_hex: transcript.toString("hex"),
    ed25519_seed_hex: SEED_HEX,
    ed25519_public_hex: PUB_HEX,
    expected_signature_base64url: b64u(signature),
  };
}

/** Negative whose signature was computed over a DIFFERENT protocol_version than
 *  the one presented — proves the transcript binds protocol_version. */
function signatureMismatchNegative(): NegativeVector {
  const challenge_id = "ch-v6-0001";
  const agent_id = "agent-abc";
  const key_id = "key-1";
  const tenant_id = "acme";
  const canonical = "wss://relay.example.com";
  const presentedPv = "1.7.0-draft"; // differs from PROTOCOL_VERSION (the signed value)

  const signedTranscript = buildTranscript({
    challenge_id, nonce_raw: nonceRaw, agent_id, key_id, protocol_version: PROTOCOL_VERSION, tenant_id, server_origin: canonical,
  });
  const signature = sign(null, signedTranscript, kp.privateKey);
  const presentedTranscript = buildTranscript({
    challenge_id, nonce_raw: nonceRaw, agent_id, key_id, protocol_version: presentedPv, tenant_id, server_origin: canonical,
  });

  return {
    label: "protocol_version-signature-mismatch",
    reason: "signature computed over protocol_version != presented (transcript binding)",
    failure_mode: "signature",
    challenge_id,
    nonce_raw_hex: NONCE_RAW_HEX,
    agent_id,
    key_id,
    protocol_version: presentedPv,
    tenant_id,
    canonical_server_origin: canonical,
    ed25519_seed_hex: SEED_HEX,
    ed25519_public_hex: PUB_HEX,
    transcript_hex: presentedTranscript.toString("hex"),
    expected_signature_base64url: b64u(signature),
  };
}

/** Strict-Ed25519 negative: sign the baseline transcript, then mutate the
 *  signature (or override the public key) so a ZIP-215-strict verifier MUST
 *  reject it. Node's `crypto.verify` is strict enough to reject all of these
 *  (empirically: tampered, wrong length, non-canonical S, low-order key). */
function strictSigNegative(
  label: string,
  reason: string,
  mutate: (sig: Buffer) => Buffer,
  pubOverride?: Buffer,
): NegativeVector {
  const challenge_id = "ch-v6-0001";
  const agent_id = "agent-abc";
  const key_id = "key-1";
  const tenant_id = "acme";
  const canonical = "wss://relay.example.com";
  const transcript = buildTranscript({
    challenge_id, nonce_raw: nonceRaw, agent_id, key_id,
    protocol_version: PROTOCOL_VERSION, tenant_id, server_origin: canonical,
  });
  const sig = sign(null, transcript, kp.privateKey);
  const pub = pubOverride ?? kp.publicRaw;
  return {
    label,
    reason,
    failure_mode: "signature",
    challenge_id,
    nonce_raw_hex: NONCE_RAW_HEX,
    agent_id,
    key_id,
    protocol_version: PROTOCOL_VERSION,
    tenant_id,
    canonical_server_origin: canonical,
    ed25519_seed_hex: SEED_HEX,
    ed25519_public_hex: pub.toString("hex"),
    transcript_hex: transcript.toString("hex"),
    expected_signature_base64url: b64u(mutate(sig)),
  };
}

/** S' = S + L (group order): the same scalar mod L, but a non-canonical encoding
 *  (S' >= L). A strict verifier MUST reject; a lenient (reduce-mod-L) one accepts. */
function nonCanonicalS(sig: Buffer): Buffer {
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const R = sig.subarray(0, 32);
  const Sb = sig.subarray(32, 64);
  let S = 0n;
  for (let i = 31; i >= 0; i--) S = (S << 8n) | BigInt(Sb[i]!);
  const Sn = S + L;
  if (Sn >= 2n ** 256n) throw new Error("non-canonical S overflows 32 bytes for this seed");
  const out = Buffer.alloc(32);
  let t = Sn;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(t & 0xffn);
    t >>= 8n;
  }
  return Buffer.concat([R, out]);
}

/** The Ed25519 identity point (y=1) — a low-order public key. */
const LOW_ORDER_POINT = Buffer.from(`01${"00".repeat(31)}`, "hex");

export function buildVectors(): VectorsFile {
  const positives: PositiveVector[] = [
    positive("baseline", {}),
    positive("tenant-id-max-128", { tenant_id: "t".repeat(128) }),
  ];

  const negatives: NegativeVector[] = [
    // --- schema parse rejects (wire-level) ---
    { label: "nonce-42-chars", reason: "nonce shorter than 43 chars", failure_mode: "parse", wire_message: "auth.challenge", field: "nonce", value: "A".repeat(42) },
    { label: "nonce-44-chars", reason: "nonce longer than 43 chars", failure_mode: "parse", wire_message: "auth.challenge", field: "nonce", value: "A".repeat(44) },
    { label: "nonce-padded", reason: "padded base64url nonce ('=' rejected)", failure_mode: "parse", wire_message: "auth.challenge", field: "nonce", value: `${"A".repeat(42)}=` },
    { label: "agent_id-non-ascii", reason: "non-ASCII agent_id (UTF-16-vs-byte signature-mismatch defense)", failure_mode: "parse", wire_message: "hello", field: "agent_id", value: "agent-café" },
    { label: "agent_id-invalid-charset", reason: "agent_id with '@' is outside AuthId charset", failure_mode: "parse", wire_message: "hello", field: "agent_id", value: "agent@host" },
    { label: "protocol_version-over-64", reason: "protocol_version exceeds 64 chars (SemVer .max(64))", failure_mode: "parse", wire_message: "hello", field: "protocol_version", value: `1.0.0-${"a".repeat(60)}` },
    // --- server_origin canonicalization rejects ---
    { label: "origin-uppercase-host", reason: "uppercase host is non-canonical", failure_mode: "origin", input_server_origin: "wss://Relay.Example.com" },
    { label: "origin-explicit-default-port", reason: "explicit :443 default port is non-canonical", failure_mode: "origin", input_server_origin: "wss://relay.example.com:443" },
    { label: "origin-trailing-dot", reason: "trailing-dot host is non-canonical", failure_mode: "origin", input_server_origin: "wss://relay.example.com." },
    { label: "origin-raw-idn", reason: "raw IDN host must be ASCII punycode", failure_mode: "origin", input_server_origin: "wss://café.example.com" },
    { label: "origin-invalid-dns-label", reason: "host with '_' is not a valid DNS label", failure_mode: "origin", input_server_origin: "wss://relay_example.com" },
    { label: "nonce-invalid-alphabet", reason: "nonce has a non-base64url char ('+')", failure_mode: "parse", wire_message: "auth.challenge", field: "nonce", value: `${"A".repeat(42)}+` },
    { label: "nonce-noncanonical-padbits", reason: "43-char base64url with non-zero trailing pad bits (non-canonical)", failure_mode: "parse", wire_message: "auth.challenge", field: "nonce", value: `${"A".repeat(42)}B` },
    // --- tenant_id grammar reject ---
    { label: "tenant-id-129-chars", reason: "tenant_id exceeds 128 chars", failure_mode: "tenant", tenant_id: "t".repeat(129) },
    // --- signature / strict-Ed25519 verifier negatives (F4 nit; verifier MUST reject) ---
    signatureMismatchNegative(),
    strictSigNegative("signature-wrong-length", "Ed25519 signature is not 64 bytes (also schema-rejected: Ed25519Sig.length(86))", (sig) => sig.subarray(0, 63)),
    strictSigNegative("signature-non-canonical-s", "S >= group order L (malleable, non-canonical); strict verifier MUST reject", nonCanonicalS),
    strictSigNegative("signature-low-order-pubkey", "public key is a low-order point (identity); strict verifier MUST reject", (sig) => sig, LOW_ORDER_POINT),
  ];

  return {
    _comment:
      "F4 cross-language auth test vectors (auth-pairing-spec §5). DO NOT EDIT BY HAND — regenerate with: tsx protocol/v1/gen-vectors.ts. Verified by protocol/v1/selftest.ts (npm run protocol:check).",
    domain_tag: DOMAIN_TAG,
    alg: ALG,
    ed25519_seed_hex: SEED_HEX,
    ed25519_public_hex: PUB_HEX,
    positives,
    negatives,
  };
}

// ---------------------------------------------------------------------------
// Write only when invoked directly (no side effect when imported by selftest).
// ---------------------------------------------------------------------------

/** True iff this module is the entry script. Compares realpaths (not file URLs)
 *  so a symlinked `tsx`/script invocation still resolves to this module; when
 *  selftest imports it the paths differ → no write (Codex P2 review). */
function invokedDirectly(): boolean {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return fileURLToPath(import.meta.url) === realpathSync(argv1);
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  const out = new URL("./test-vectors.json", import.meta.url);
  const data = buildVectors();
  writeFileSync(out, `${JSON.stringify(data, null, 2)}\n`);
  console.log(`wrote ${fileURLToPath(out)} (${data.positives.length} positive, ${data.negatives.length} negative)`);
}
