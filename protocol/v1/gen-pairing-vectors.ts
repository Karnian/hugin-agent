/**
 * Pairing PoP test vectors (generator) — Pairing Ceremony rev2 §8.
 * ================================================================
 *
 *   tsx protocol/v1/gen-pairing-vectors.ts   # (re)writes ./pairing-test-vectors.json
 *
 * Deterministic Ed25519 vectors for the pairing proof-of-possession, so the
 * Python C2 verifier can confirm byte-identical `pairing_transcript`
 * construction and strict signature verification independent of this TS
 * implementation. Mirrors `gen-vectors.ts` (F4); the frozen
 * `test-vectors.json` is NOT touched.
 *
 * The seed is the same fixed, PUBLIC test constant as the auth vectors — one
 * well-known test key to blocklist in production (`/pair/complete` MUST refuse
 * to register its public key). A second fixed seed provides the "attacker key"
 * for the tampered-pubkey negative.
 *
 * `pairing-selftest.ts` verifies the COMMITTED JSON: positives must recompute
 * the same transcript, re-sign to the same signature, and verify; negatives
 * must FAIL verification exactly as documented.
 */

import { createHash, sign } from "node:crypto";
import { realpathSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { PROTOCOL_VERSION } from "./messages";
import {
  buildPairingTranscript,
  keyFingerprint,
  PAIRING_DOMAIN_TAG,
  REJECTED_TEST_PUBLIC_HEX,
} from "./pairing";
import { lp, DOMAIN_TAG as HANDSHAKE_DOMAIN_TAG } from "./transcript";
import { b64u, deriveKeypairFromSeed, type Keypair } from "./ed25519";
import { canonicalizeServerOrigin } from "./origin";

// ---------------------------------------------------------------------------
// Vector shapes (open decision 2 of ceremony rev2 §11 — proposed schema)
// ---------------------------------------------------------------------------

export interface PairingPositiveVector {
  label: string;
  /** The 43-char unpadded-base64url secret STRING exactly as signed. */
  secret: string;
  /** Raw bytes the secret decodes to — informational only (the STRING is signed). */
  secret_raw_hex: string;
  /** SHA-256 over the exact UTF-8 secret STRING — what C2 stores/looks up. */
  secret_sha256_hex: string;
  /** `public_key` as it appears in the /pair/complete POST body. */
  public_key_base64url: string;
  ed25519_seed_hex: string;
  ed25519_public_hex: string;
  canonical_server_origin: string;
  protocol_version: string;
  domain_tag_lp_hex: string;
  transcript_hex: string;
  expected_pop_signature_base64url: string;
  /** Full 43-char fingerprint (rev2 M2) the daemon CLI and browser must both show. */
  fingerprint_base64url: string;
}

/** Three negative classes:
 *  - "parse":     the field value must be REJECTED at the input gate (canonical
 *                 43-char base64url of 32 bytes), before any crypto;
 *  - "signature": rebuild the PRESENTED transcript from the fields and
 *                 strict-verify — it MUST fail;
 *  - "policy":    valid crypto that registration must still REFUSE (the
 *                 published test key). */
export interface PairingNegativeVector {
  label: string;
  reason: string;
  failure_mode: "parse" | "signature" | "policy";
  // parse
  field?: "secret" | "public_key";
  value?: string;
  // signature
  secret?: string;
  canonical_server_origin?: string;
  protocol_version?: string;
  transcript_hex?: string;
  expected_pop_signature_base64url?: string;
  // signature + policy
  ed25519_public_hex?: string;
  public_key_base64url?: string;
}

export interface PairingVectorsFile {
  _comment: string;
  schema: 1;
  domain_tag: string;
  alg: "ed25519";
  protocol_version: string;
  /** Normative: what `sha256(secret)` hashes. */
  secret_hash_rule: string;
  /** Normative: registration MUST refuse this public key (published test seed). */
  rejected_test_public_hex: string;
  positives: PairingPositiveVector[];
  negatives: PairingNegativeVector[];
}

// ---------------------------------------------------------------------------
// Fixed inputs (deterministic — never derived from time or randomness)
// ---------------------------------------------------------------------------

/** Same PUBLIC test seed as the auth vectors — one key to blocklist. */
const SEED = Buffer.from([...Array(32)].map((_, i) => i + 1));
const SEED_HEX = SEED.toString("hex");
/** A second fixed test key — the "attacker" key for tampered-pubkey. */
const SEED2 = Buffer.from([...Array(32)].map((_, i) => i + 0x21));

const kp: Keypair = deriveKeypairFromSeed(SEED);
const kp2: Keypair = deriveKeypairFromSeed(SEED2);
const PUB_HEX = kp.publicRaw.toString("hex");

/** Baseline secret: b64u of raw bytes 0x40..0x5f (43 chars). */
const SECRET_RAW = Buffer.from([...Array(32)].map((_, i) => i + 0x40));
const SECRET = b64u(SECRET_RAW);
/** A different, equally well-formed secret for the wrong-secret negative. */
const OTHER_SECRET = b64u(Buffer.from([...Array(32)].map((_, i) => i + 0x60)));

const ORIGIN = "wss://relay.example.com";

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

function positive(label: string, over: Partial<{ secret: string; origin: string }> = {}): PairingPositiveVector {
  const secret = over.secret ?? SECRET;
  const origin = over.origin ?? ORIGIN;
  if (canonicalizeServerOrigin(origin) !== origin) {
    throw new Error(`positive origin must be frozen-canonical: ${origin}`);
  }
  const transcript = buildPairingTranscript({
    secret, publicRaw: kp.publicRaw, server_origin: origin, protocol_version: PROTOCOL_VERSION,
  });
  return {
    label,
    secret,
    secret_raw_hex: Buffer.from(secret, "base64url").toString("hex"),
    secret_sha256_hex: createHash("sha256").update(secret, "utf8").digest("hex"),
    public_key_base64url: b64u(kp.publicRaw),
    ed25519_seed_hex: SEED_HEX,
    ed25519_public_hex: PUB_HEX,
    canonical_server_origin: origin,
    protocol_version: PROTOCOL_VERSION,
    domain_tag_lp_hex: lp(PAIRING_DOMAIN_TAG).toString("hex"),
    transcript_hex: transcript.toString("hex"),
    expected_pop_signature_base64url: b64u(sign(null, transcript, kp.privateKey)),
    fingerprint_base64url: keyFingerprint(kp.publicRaw),
  };
}

/** Sign over the BASELINE fields (or an explicitly WRONG byte layout), present
 *  the correctly-built transcript with ONE field swapped (or a mutated
 *  signature / overridden pubkey) — strict verify MUST fail. */
function negative(
  label: string,
  reason: string,
  opts: {
    presented?: Partial<{ secret: string; origin: string; pv: string; publicRaw: Buffer }>;
    /** Sign over these exact bytes instead of the baseline transcript — used
     *  to encode likely porting mistakes (wrong tag, LP'd pubkey, decoded secret). */
    signedTranscript?: Buffer;
    mutateSig?: (sig: Buffer) => Buffer;
    verifyPub?: Buffer; // public key to present/verify against (default: signer's)
  },
): PairingNegativeVector {
  const signedTranscript =
    opts.signedTranscript ??
    buildPairingTranscript({
      secret: SECRET, publicRaw: kp.publicRaw, server_origin: ORIGIN, protocol_version: PROTOCOL_VERSION,
    });
  const sig = sign(null, signedTranscript, kp.privateKey);

  const p = opts.presented ?? {};
  const presentedPub = p.publicRaw ?? opts.verifyPub ?? kp.publicRaw;
  const presentedTranscript = buildPairingTranscript({
    secret: p.secret ?? SECRET,
    publicRaw: presentedPub,
    server_origin: p.origin ?? ORIGIN,
    protocol_version: p.pv ?? PROTOCOL_VERSION,
  });

  return {
    label,
    reason,
    failure_mode: "signature",
    secret: p.secret ?? SECRET,
    canonical_server_origin: p.origin ?? ORIGIN,
    protocol_version: p.pv ?? PROTOCOL_VERSION,
    ed25519_public_hex: (opts.verifyPub ?? presentedPub).toString("hex"),
    transcript_hex: presentedTranscript.toString("hex"),
    expected_pop_signature_base64url: b64u((opts.mutateSig ?? ((s: Buffer) => s))(sig)),
  };
}

/** S' = S + L — non-canonical encoding a strict verifier MUST reject. */
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

/** The Ed25519 identity point — a low-order public key. */
const LOW_ORDER_POINT = Buffer.from(`01${"00".repeat(31)}`, "hex");

// ---------------------------------------------------------------------------

export function buildPairingVectors(): PairingVectorsFile {
  const positives: PairingPositiveVector[] = [
    positive("baseline"),
    positive("non-default-port", { origin: "wss://relay.example.com:8443" }),
    positive("loopback-dev-ws", { origin: "ws://localhost:8080" }),
  ];

  const negatives: PairingNegativeVector[] = [
    // --- input-gate rejects (canonical 43-char base64url of 32 bytes) ---
    { label: "secret-42-chars", reason: "secret shorter than 43 chars", failure_mode: "parse", field: "secret", value: "A".repeat(42) },
    { label: "secret-noncanonical-padbits", reason: "43-char base64url with non-zero trailing pad bits (alias of another string)", failure_mode: "parse", field: "secret", value: `${"A".repeat(42)}B` },
    { label: "pubkey-noncanonical-padbits", reason: "public_key base64url must round-trip decode→re-encode (canonical)", failure_mode: "parse", field: "public_key", value: `${"A".repeat(42)}B` },
    // --- verify-level rejects ---
    negative("pop-wrong-secret", "PoP signed over a different secret (transcript binds the invite)", {
      presented: { secret: OTHER_SECRET },
    }),
    negative("pop-wrong-origin", "PoP signed over a different origin (anti-relay binding)", {
      presented: { origin: "wss://evil.example.com" },
    }),
    negative("pop-wrong-protocol-version", "PoP signed over a different protocol_version", {
      presented: { pv: "1.1.0" },
    }),
    negative("pop-tampered-pubkey", "transcript/verify use a key the signer does not control", {
      presented: { publicRaw: kp2.publicRaw },
      verifyPub: kp2.publicRaw,
    }),
    negative("pop-wrong-domain-tag", "signature computed under the HANDSHAKE domain tag (cross-protocol replay MUST fail)", {
      signedTranscript: Buffer.concat([lp(HANDSHAKE_DOMAIN_TAG), lp(SECRET), kp.publicRaw, lp(ORIGIN), lp(PROTOCOL_VERSION)]),
    }),
    negative("pop-lp-pubkey-mistake", "porting mistake: public key length-prefixed instead of raw 32 bytes", {
      signedTranscript: Buffer.concat([lp(PAIRING_DOMAIN_TAG), lp(SECRET), lp(kp.publicRaw), lp(ORIGIN), lp(PROTOCOL_VERSION)]),
    }),
    negative("pop-decoded-secret-mistake", "porting mistake: secret decoded to raw bytes instead of signed as the UTF-8 string", {
      signedTranscript: Buffer.concat([lp(PAIRING_DOMAIN_TAG), lp(SECRET_RAW), kp.publicRaw, lp(ORIGIN), lp(PROTOCOL_VERSION)]),
    }),
    negative("pop-signature-wrong-length", "signature is not 64 bytes", {
      mutateSig: (s) => s.subarray(0, 63),
    }),
    negative("pop-signature-non-canonical-s", "S >= group order L; strict verifier MUST reject", {
      mutateSig: nonCanonicalS,
    }),
    negative("pop-signature-low-order-pubkey", "public key is a low-order point (identity); strict verifier MUST reject", {
      verifyPub: LOW_ORDER_POINT,
    }),
    // --- policy reject (crypto is VALID; registration must still refuse) ---
    {
      label: "test-key-registration-refused",
      reason: "the published test key's seed is public — /pair/complete MUST refuse to register it even with a valid PoP",
      failure_mode: "policy",
      ed25519_public_hex: REJECTED_TEST_PUBLIC_HEX,
      public_key_base64url: b64u(Buffer.from(REJECTED_TEST_PUBLIC_HEX, "hex")),
    },
  ];

  return {
    _comment:
      "Pairing PoP test vectors (ceremony rev2 §8). DO NOT EDIT BY HAND — regenerate with: tsx protocol/v1/gen-pairing-vectors.ts. Verified by protocol/v1/pairing-selftest.ts (npm run pairing:check). The seed is a fixed PUBLIC test constant; /pair/complete MUST refuse to register its public key.",
    schema: 1,
    domain_tag: PAIRING_DOMAIN_TAG,
    alg: "ed25519",
    protocol_version: PROTOCOL_VERSION,
    secret_hash_rule:
      "sha256 over the exact UTF-8 secret STRING (the 43-char canonical unpadded base64url text, NOT the decoded bytes); non-canonical aliases are rejected at the input gate",
    rejected_test_public_hex: REJECTED_TEST_PUBLIC_HEX,
    positives,
    negatives,
  };
}

// Write only on direct invocation (same guard as gen-vectors.ts).
const invokedDirectly = (() => {
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1] ?? "");
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  const file = buildPairingVectors();
  const out = new URL("./pairing-test-vectors.json", import.meta.url);
  writeFileSync(out, `${JSON.stringify(file, null, 2)}\n`);
  console.log(
    `wrote ${out.pathname}: ${file.positives.length} positives, ${file.negatives.length} negatives`,
  );
}
