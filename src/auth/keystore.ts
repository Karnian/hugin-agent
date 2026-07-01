/**
 * Device-key store + production handshake signer (auth-pairing-spec §2).
 *
 * The device's Ed25519 private key lives ONLY on the host: the 32-byte seed is
 * held in the OS keychain (`@napi-rs/keyring`) and never leaves the machine —
 * pairing sends the **public** key, the handshake sends a **signature**, neither
 * ever carries the seed. `keychainSigner(keyId)` is the drop-in replacement for
 * the DEV `devSigner` (`src/conn/handshake.ts`): it loads the seed once at
 * startup, derives the private key, and signs the canonical transcript.
 *
 * The `@napi-rs/keyring` native module is LAZY-imported (only when a keychain
 * method actually runs) so a `memorySeedStore()`-backed signer — used by the
 * CI-safe e2e — works even where no OS keychain is present.
 *
 * Ed25519 mechanics (seed→key, sign) come from `protocol/v1/ed25519.ts` — the
 * same shared module the relay verifier and the F4 vectors use, so a signature
 * this signer produces is byte-verifiable by the relay with no drift.
 */

import { randomBytes } from "node:crypto";
import { b64u, deriveKeypairFromSeed, signTranscript } from "../../protocol/v1/ed25519";
import type { Signer } from "../conn/handshake";

/** Default keychain service (namespace) for hugin-agent device seeds. The
 *  keychain ACCOUNT is the server-assigned `key_id`, so rotation (auth-spec §7)
 *  can hold multiple seeds side by side under one service. */
export const KEYCHAIN_SERVICE = "com.contextualai.hugin-agent";

/**
 * Where a device private-key seed is persisted. The keychain impl is production;
 * `memorySeedStore()` is injected by tests to stay off the real OS keychain.
 * Seeds are handled as raw 32-byte Buffers at this boundary — the base64url
 * string form exists only transiently inside the keychain impl.
 */
export interface SeedStore {
  /** Store (upsert) the 32-byte device seed under `keyId`. */
  set(keyId: string, seed: Buffer): Promise<void>;
  /** Return the stored 32-byte seed, or null if none / malformed. */
  get(keyId: string): Promise<Buffer | null>;
  /** Delete the seed; resolves true iff one was removed. */
  delete(keyId: string): Promise<boolean>;
}

/** Fresh in-memory device key material — nothing is persisted yet. The seed is
 *  the secret; only `publicRaw` (registered at pairing) ever leaves the host. */
export interface DeviceKey {
  /** 32-byte Ed25519 seed (the private key material). */
  seed: Buffer;
  /** Raw 32-byte Ed25519 public key. */
  publicRaw: Buffer;
}

/** Mint a new Ed25519 device keypair in memory. The caller persists `seed` via a
 *  `SeedStore` under the server-assigned `key_id` and sends only `publicRaw`. */
export function newDeviceKey(): DeviceKey {
  const seed = randomBytes(32);
  const { publicRaw } = deriveKeypairFromSeed(seed); // validates the 32-byte seed
  return { seed, publicRaw };
}

/** OS-keychain-backed seed store. The native module is imported on first use so
 *  merely constructing this store is side-effect-free (CI-safe until touched). */
export function keychainSeedStore(service: string = KEYCHAIN_SERVICE): SeedStore {
  async function entry(keyId: string) {
    const { Entry } = await import("@napi-rs/keyring");
    return new Entry(service, keyId);
  }
  return {
    async set(keyId, seed) {
      if (seed.length !== 32) throw new Error(`device seed must be 32 bytes, got ${seed.length}`);
      (await entry(keyId)).setPassword(seed.toString("base64url"));
    },
    async get(keyId) {
      let stored: string | null;
      try {
        stored = (await entry(keyId)).getPassword();
      } catch {
        return null; // absent (some platforms throw instead of returning null)
      }
      if (!stored) return null;
      const seed = Buffer.from(stored, "base64url");
      return seed.length === 32 ? seed : null;
    },
    async delete(keyId) {
      try {
        return Boolean((await entry(keyId)).deletePassword());
      } catch {
        return false;
      }
    },
  };
}

/** Non-persistent seed store for tests/CI — never touches the OS keychain. */
export function memorySeedStore(): SeedStore {
  const seeds = new Map<string, Buffer>();
  return {
    async set(keyId, seed) {
      seeds.set(keyId, Buffer.from(seed)); // copy: caller may scrub its Buffer
    },
    async get(keyId) {
      const seed = seeds.get(keyId);
      return seed ? Buffer.from(seed) : null;
    },
    async delete(keyId) {
      return seeds.delete(keyId);
    },
  };
}

/**
 * Production `Signer`: load the device seed for `key_id` from the store, derive
 * the private key, and sign the canonical transcript. Loading is done ONCE (the
 * private `KeyObject` is retained); the raw seed Buffer is scrubbed immediately
 * after derivation. The `sign(transcript)` closure stays synchronous, so the
 * `performHandshake` caller is unchanged (Track A seam: transcript bytes + caller
 * do not change — only the key source does).
 *
 * Throws if no key is paired for `key_id` — the daemon must be paired first
 * (`hugin-agent connect`). Fail-closed: an unpaired daemon cannot handshake.
 */
export async function keychainSigner(
  keyId: string,
  store: SeedStore = keychainSeedStore(),
): Promise<Signer> {
  const seed = await store.get(keyId);
  if (seed === null) {
    throw new Error(`no device key for key_id "${keyId}" in the keychain — run \`hugin-agent connect\` to pair this device`);
  }
  const { privateKey } = deriveKeypairFromSeed(seed);
  seed.fill(0); // scrub the raw seed; the KeyObject retains the usable handle
  return {
    keyId,
    sign: (transcript: Buffer) => signTranscript(privateKey, transcript),
  };
}

// re-export so callers building the pairing flow have one import surface.
export { b64u };
