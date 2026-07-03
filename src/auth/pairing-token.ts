import { z } from "zod";
import { PAIRING_SECRET_RE, validateB64u32 } from "../../protocol/v1/pairing";

const MAX_PAIRING_TOKEN_BYTES = 1024;
const TOKEN_PREFIX = "hpk1.";
const B64U_RE = /^[A-Za-z0-9_-]+$/;

const PairingTokenPayload = z.strictObject({
  v: z.literal("1.0.0"),
  origin: z.string(),
  secret: z.string().regex(PAIRING_SECRET_RE).refine(validateB64u32),
  exp: z.number().int(),
});

export interface ParsedPairingToken {
  origin: string;
  secret: string;
  exp: number;
}

function invalidToken(): never {
  throw new Error("invalid pairing token; re-copy the token");
}

function isCanonicalUnpaddedBase64url(s: string): boolean {
  if (!B64U_RE.test(s)) return false;
  if (s.length % 4 === 1) return false;
  try {
    const decoded = Buffer.from(s, "base64url");
    return decoded.toString("base64url") === s;
  } catch {
    return false;
  }
}

export function parsePairingToken(raw: string, now: number): ParsedPairingToken {
  if (Buffer.byteLength(raw, "utf8") > MAX_PAIRING_TOKEN_BYTES) {
    throw new Error("pairing token is too large; re-copy the token");
  }

  const segments = raw.split(".");
  if (segments.length !== 2 || !raw.startsWith(TOKEN_PREFIX) || !segments[1]) {
    invalidToken();
  }

  const payload = segments[1];
  if (!isCanonicalUnpaddedBase64url(payload)) {
    invalidToken();
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    invalidToken();
  }

  let parsed: z.infer<typeof PairingTokenPayload>;
  try {
    parsed = PairingTokenPayload.parse(decoded);
  } catch {
    invalidToken();
  }

  if (parsed.exp * 1000 < now) {
    throw new Error("pairing token expired; re-copy the token");
  }

  return { origin: parsed.origin, secret: parsed.secret, exp: parsed.exp };
}
