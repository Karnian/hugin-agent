/**
 * Ed25519 key mechanics (RFC 8032 / RFC 8410) — shared CONTRACT code, not a test
 * artifact. One no-drift source for every party that touches a device key:
 *   - the device keystore + handshake signer (`src/auth/keystore.ts`, production),
 *   - the relay's signature verifier (`mock-relay/server.ts`, cloud stand-in),
 *   - the cross-language test-vector generator (`gen-vectors.ts`),
 *   - the conformance self-test (`selftest.ts`).
 *
 * Extracted from `gen-vectors.ts` (same move as `transcript.ts`) so production
 * signing/verification never imports the test generator and the four can never
 * drift on key encoding or the sign/verify convention. Non-wire: nothing here
 * changes any message shape or `PROTOCOL_VERSION`.
 *
 * The sign/verify convention is fixed: Ed25519 is one-shot pure-EdDSA, so the
 * algorithm argument to node's `sign`/`verify` is `null`; the wire signature is
 * unpadded base64url over the raw 64-byte value.
 */

import { createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";

/** Unpadded base64url (Node's "base64url" alphabet omits `=`). */
export function b64u(buf: Buffer): string {
  return buf.toString("base64url");
}

/** PKCS8 v0 wrapper for an Ed25519 private key (RFC 8410): the 16-byte prefix
 *  precedes the raw 32-byte seed → a 48-byte DER that Node imports directly. */
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
/** SPKI wrapper for an Ed25519 public key: 12-byte prefix + raw 32-byte key. */
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface Keypair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** Raw 32-byte public key. */
  publicRaw: Buffer;
}

/** Derive a full Ed25519 keypair from its 32-byte seed. The seed IS the private
 *  key material (RFC 8032 §5.1.5); it never leaves the host (keychain-resident). */
export function deriveKeypairFromSeed(seed: Buffer): Keypair {
  if (seed.length !== 32) throw new Error(`Ed25519 seed must be 32 bytes, got ${seed.length}`);
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  der.fill(0); // scrub the transient DER copy of the seed
  // Derive the public key FROM the private KeyObject and read its raw bytes from
  // the PUBLIC JWK (which carries only `x`, never the private `d`). Exporting the
  // *private* key as JWK would materialize the seed a second time as `jwk.d` (an
  // immutable string that outlives any Buffer scrub) — this path never does.
  // Node accepts a private KeyObject here at runtime (RFC 8032: the public key is
  // derived from the private); @types/node omits KeyObject from the input union,
  // so cast to the parameter type.
  const publicKey = createPublicKey(privateKey as unknown as Parameters<typeof createPublicKey>[0]);
  const jwk = publicKey.export({ format: "jwk" });
  if (!jwk.x) throw new Error("Ed25519 public key JWK missing component 'x'");
  const publicRaw = Buffer.from(jwk.x, "base64url");
  return { privateKey, publicKey, publicRaw };
}

/** Reconstruct an Ed25519 public KeyObject from its raw 32 bytes — the path the
 *  relay (and any cross-language verifier) takes from a registered public key. */
export function publicKeyFromRaw(publicRaw: Buffer): KeyObject {
  if (publicRaw.length !== 32) throw new Error(`Ed25519 public key must be 32 bytes, got ${publicRaw.length}`);
  const spki = Buffer.concat([SPKI_ED25519_PREFIX, publicRaw]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

/** Sign the canonical transcript with an Ed25519 private key → unpadded base64url.
 *  The one place the production signer encodes a signature (auth-spec §5). */
export function signTranscript(privateKey: KeyObject, transcript: Buffer): string {
  return b64u(sign(null, transcript, privateKey));
}

/** Verify an unpadded-base64url Ed25519 signature over `transcript` against a raw
 *  32-byte public key. Returns false on any format/length/curve failure — never
 *  throws — so a malformed signature is a clean `bad_signature`, not a crash.
 *  Node's `crypto.verify` enforces strict (ZIP-215-style) Ed25519: non-canonical
 *  S, low-order keys, and the identity are rejected (see gen-vectors negatives). */
export function verifyTranscript(publicRaw: Buffer, transcript: Buffer, signatureB64u: string): boolean {
  // Wire-shape gate before the curve check: exactly 86 unpadded base64url chars
  // (= 64 bytes); reject padding / non-alphabet (auth-spec §5 "Ed25519 verification").
  if (!/^[A-Za-z0-9_-]{86}$/.test(signatureB64u)) return false;
  try {
    const sig = Buffer.from(signatureB64u, "base64url");
    if (sig.length !== 64) return false;
    const pub = publicKeyFromRaw(publicRaw);
    return verify(null, transcript, pub, sig);
  } catch {
    return false;
  }
}
