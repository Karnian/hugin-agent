/**
 * Pairing PoP transcript (Pairing Ceremony rev2 §8) — CONTRACT code, shared by:
 *   - the daemon's `connect` pairing client (signs the PoP with the device key),
 *   - the relay's `/pair/complete` verifier (rebuilds + strict-verifies),
 *   - the pairing test-vector generator (`gen-pairing-vectors.ts`),
 *   - the pairing conformance self-test (`pairing-selftest.ts`).
 *
 * NON-WIRE: pairing runs over HTTPS before any WSS handshake; nothing here
 * touches the frozen v1.0.0 message shapes, handshake transcript, or
 * PROTOCOL_VERSION. The domain tag is DISTINCT from the handshake tag
 * (`hugin-agent/auth/v1`) so a pairing PoP can never be replayed as a
 * handshake signature or vice versa.
 *
 *   pairing_transcript :=
 *       LP("hugin-pair-pop-v1")      # domain tag
 *     || LP(secret)                  # 43-char base64url secret STRING, UTF-8
 *                                    #   (NOT its hash, NOT the decoded bytes)
 *     || public_raw                  # raw 32-byte Ed25519 public key, NO LP
 *     || LP(canonical_server_origin) # the wss:// origin carried in the token
 *     || LP(protocol_version)        # "1.0.0"
 *
 * `LP(x) = uint32_be(byte_length(x)) || x` — same framing as transcript.ts.
 */

import { createHash } from "node:crypto";
import { lp } from "./transcript";
import { b64u } from "./ed25519";

export const PAIRING_DOMAIN_TAG = "hugin-pair-pop-v1";

/** The 43-char unpadded-base64url grammar shared by the pairing secret, the
 *  POST-body `public_key`, and the key fingerprint (32 raw bytes each). Same
 *  shape as the handshake nonce. */
export const PAIRING_SECRET_RE = /^[A-Za-z0-9_-]{43}$/;

/** The PUBLIC test key (auth + pairing vectors share one seed). A production
 *  `/pair/complete` MUST refuse to register it — its seed is published, so
 *  anyone with the repo could sign for it. Mirrored in the Python reference. */
export const REJECTED_TEST_PUBLIC_HEX =
  "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";

/** Canonical 43-char unpadded base64url encoding exactly 32 bytes: charset,
 *  length, AND zero trailing pad bits (decode → re-encode must round-trip), so
 *  two distinct strings can never alias one value. Same rule as the handshake
 *  nonce; `sha256(secret)` is defined over the exact UTF-8 STRING, so C2 must
 *  reject non-canonical aliases at the door. */
export function validateB64u32(s: string): boolean {
  if (!PAIRING_SECRET_RE.test(s)) return false;
  const raw = Buffer.from(s, "base64url");
  return raw.length === 32 && b64u(raw) === s;
}

export interface PairingTranscriptFields {
  /** The token's 43-char unpadded-base64url secret — signed as the UTF-8
   *  STRING (never hashed or decoded before signing). */
  secret: string;
  /** Raw 32-byte Ed25519 public key being registered — inserted WITHOUT a
   *  length prefix (mirrors `nonce_raw` in the handshake transcript). */
  publicRaw: Buffer;
  /** Canonical `ws(s)://` server origin from the token (frozen canonical form —
   *  `canonicalizeServerOrigin(origin) === origin`; `ws://` is loopback-dev
   *  only, production minting policy is `wss://` + DNS host). */
  server_origin: string;
  protocol_version: string;
}

/** Canonical pairing-PoP signing bytes (ceremony rev2 §8). */
export function buildPairingTranscript(f: PairingTranscriptFields): Buffer {
  if (!validateB64u32(f.secret)) {
    throw new Error("pairing secret must be 43 canonical unpadded base64url chars (32 bytes)");
  }
  if (f.publicRaw.length !== 32) {
    throw new Error(`public key must be 32 raw bytes, got ${f.publicRaw.length}`);
  }
  return Buffer.concat([
    lp(PAIRING_DOMAIN_TAG),
    lp(f.secret),
    f.publicRaw, // RAW 32 bytes, NO length prefix
    lp(f.server_origin),
    lp(f.protocol_version),
  ]);
}

/** Device-key fingerprint (ceremony rev2 M2): full unpadded
 *  base64url(SHA-256(raw32 public key)) — 43 chars, NO truncation. Display
 *  grouping (e.g. 4-char groups) is presentation-only; the canonical value is
 *  the ungrouped 43-char string, and it MUST be byte-identical on the daemon
 *  CLI and in the C2 browser confirm screen. */
export function keyFingerprint(publicRaw: Buffer): string {
  if (publicRaw.length !== 32) {
    throw new Error(`public key must be 32 raw bytes, got ${publicRaw.length}`);
  }
  return b64u(createHash("sha256").update(publicRaw).digest());
}
