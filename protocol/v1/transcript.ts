/**
 * Canonical auth-transcript construction (auth-pairing-spec §5) — the byte layout
 * an Ed25519 `hello` signature covers. This is **contract code**, shared by:
 *   - the daemon's handshake signer (production + the MVP stub),
 *   - the cross-language test-vector generator (`gen-vectors.ts`),
 *   - the conformance self-test (`selftest.ts`).
 *
 * It lives in a normal protocol module (not the test generator) so production
 * handshake code never imports a test artifact and the two can never drift.
 * Non-wire: changing nothing here changes no message or PROTOCOL_VERSION.
 *
 *   LP(x)      := uint32_be(byte_length(x)) || x        # UTF-8 unless noted
 *   transcript := LP(domain_tag) || LP(challenge_id) || nonce_raw  # nonce: RAW 32B, NO LP
 *              || LP(agent_id) || LP(key_id) || LP(protocol_version)
 *              || LP("ed25519") || LP(tenant_id) || LP(server_origin)
 */

export const DOMAIN_TAG = "hugin-agent/auth/v1";
export const ALG = "ed25519";

/** Length-prefix: uint32_be(byte_length(x)) || x. Strings are UTF-8 encoded. */
export function lp(x: string | Buffer): Buffer {
  const body = Buffer.isBuffer(x) ? x : Buffer.from(x, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(body.length, 0);
  return Buffer.concat([len, body]);
}

export interface TranscriptFields {
  challenge_id: string;
  /** 32 raw nonce bytes — inserted into the transcript WITHOUT a length prefix. */
  nonce_raw: Buffer;
  agent_id: string;
  key_id: string;
  protocol_version: string;
  tenant_id: string;
  /** Canonical server origin (see canonicalizeServerOrigin in origin.ts). */
  server_origin: string;
}

/** Canonical signing bytes per auth-pairing-spec §5. `nonce_raw` is inserted as
 *  the raw 32 bytes with NO length prefix; every other field is LP()'d. */
export function buildTranscript(f: TranscriptFields): Buffer {
  return Buffer.concat([
    lp(DOMAIN_TAG),
    lp(f.challenge_id),
    f.nonce_raw, // RAW 32 bytes, NO length prefix
    lp(f.agent_id),
    lp(f.key_id),
    lp(f.protocol_version),
    lp(ALG),
    lp(f.tenant_id),
    lp(f.server_origin),
  ]);
}
