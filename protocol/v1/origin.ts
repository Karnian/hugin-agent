/**
 * Auth identifier validators — contract code (auth-pairing-spec §5 / §2) shared by
 * the daemon handshake, the cross-language test-vector generator, and the
 * conformance self-test. Kept out of the test generator (B9) so production code
 * never imports a test artifact.
 */

/** Returns the canonical `server_origin`, or `null` if `input` is
 *  non-canonical/invalid. A verifier REJECTS non-canonical input — it never
 *  silently normalizes. The canonical stored form has NO trailing slash
 *  (`wss://relay.example.com`). See auth-pairing-spec §5. */
export function canonicalizeServerOrigin(input: string): string | null {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null; // unparseable
  }
  const scheme = url.protocol; // "wss:" | "ws:" | ...
  const host = url.hostname; // URL lowercases + IDNA-punycodes; IPv6 keeps [..]
  const isLoopback =
    host === "localhost" || host === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(host);

  if (scheme !== "wss:" && scheme !== "ws:") return null; // ws/wss only
  if (scheme === "ws:" && !isLoopback) return null; // ws:// only for loopback dev
  if (url.username || url.password) return null; // no userinfo
  if (url.search || url.hash) return null; // no query/fragment
  if (url.pathname && url.pathname !== "/") return null; // no path
  if (url.port === "0") return null; // reject port 0
  if (host.endsWith(".")) return null; // trailing-dot host (URL keeps it)
  if (host.includes("%")) return null; // zone-id / percent-encoded authority

  const isIPv6 = host.startsWith("[");
  const isIPv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
  if ((isIPv6 || isIPv4) && !isLoopback) return null; // production = DNS-only
  if (!isLoopback) {
    // Production host must be a syntactically valid DNS name (RFC 1035 labels):
    // each label 1–63 chars, alphanumeric with internal hyphens, no empty label
    // (consecutive dots) / leading-or-trailing hyphen / underscore. IPs already rejected.
    const dnsLabel = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
    if (!host.split(".").every((label) => dnsLabel.test(label))) return null;
  }

  const portPart = url.port ? `:${url.port}` : "";
  const canonical = `${scheme}//${host}${portPart}`;
  if (canonical !== input) return null; // input must already be canonical
  return canonical;
}

/** tenant_id grammar (auth-pairing-spec §2/§11): 1*128(ALPHA / DIGIT / "-" / "_" / "."). */
const TENANT_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
export function validateTenantId(t: string): boolean {
  return TENANT_ID_RE.test(t);
}
