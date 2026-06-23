/**
 * Canonical result digest (auth-pairing-spec §5b) — contract code shared by the
 * daemon and the relay so a resent `job.result` yields an identical digest and
 * `job.result.ack{result_digest}` confirms the PAYLOAD, not merely the id.
 *
 *   result_digest := base64url( SHA-256( JCS(job.result minus id, ts) ) )
 *
 * JCS = RFC 8785 JSON Canonicalization Scheme. This is NOT `JSON.stringify`:
 * object keys are sorted (UTF-16 code-unit order), there is no insignificant
 * whitespace, and numbers/strings use the canonical ECMAScript serialization
 * (which `String(n)` / `JSON.stringify(s)` already produce). Both sides MUST
 * compute identical bytes or the digest-ack never matches and results pile up in
 * `pending_results` forever.
 */

import { createHash } from "node:crypto";

/** A high surrogate not followed by a low, or a low not preceded by a high —
 *  i.e. a lone surrogate (no UTF-8 encoding). Matched on UTF-16 code units (no
 *  `u` flag on purpose). */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** RFC 8785 JSON Canonicalization. Mirrors on-wire JSON semantics: object keys
 *  with `undefined` values are omitted; `undefined` array elements become null. */
export function jcsCanonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new Error("JCS: non-finite number");
      // ECMAScript Number-to-String == RFC 8785 number serialization.
      return String(value);
    case "string":
      // Lone surrogates have no UTF-8 encoding; a strict Go/Rust JCS impl would
      // error or substitute U+FFFD, diverging from Node and stranding the result
      // in pending_results forever. Reject to keep the digest cross-language
      // deterministic (Codex P0 review).
      if (LONE_SURROGATE.test(value)) throw new Error("JCS: string contains a lone surrogate");
      // JSON.stringify produces RFC 8785-compatible escaping (short escapes +
      // lowercase \u00xx for control chars).
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((el) => (el === undefined ? "null" : jcsCanonicalize(el))).join(",")}]`;
      }
      const obj = value as Record<string, unknown>;
      // Sort keys by UTF-16 code units (JS default string sort); drop undefined.
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${jcsCanonicalize(obj[k])}`).join(",")}}`;
    }
    default:
      // undefined / function / symbol / bigint are not valid JSON values here.
      throw new Error(`JCS: unsupported value type "${typeof value}"`);
  }
}

/** base64url(SHA-256(canonical bytes)) — unpadded, 43 chars for SHA-256. */
export function sha256Base64Url(canonical: string): string {
  return createHash("sha256").update(canonical, "utf8").digest("base64url");
}

/** Compute `result_digest` for a `job.result` message: drop the per-send envelope
 *  fields `id` and `ts` (they differ each send and must not affect identity),
 *  canonicalize the rest with JCS, then hash. */
export function resultDigest(jobResult: Record<string, unknown>): string {
  const { id: _id, ts: _ts, ...rest } = jobResult;
  void _id;
  void _ts;
  return sha256Base64Url(jcsCanonicalize(rest));
}
