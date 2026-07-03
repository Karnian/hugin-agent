/**
 * Dev-only helpers for daemon-side simple pairing.
 *
 * This module intentionally lives outside protocol/v1. The v1 origin validator is
 * frozen production policy; simple-pairing dev mode needs a relaxed local policy
 * for trusted networks such as Tailscale.
 */

export function simplePairingGateEnabled(value: string | undefined): boolean {
  return value === "1" || value?.toLowerCase() === "true";
}

function ipv4OctetsValid(host: string): boolean {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return false;
  return host.split(".").every((part) => Number(part) <= 255);
}

/** Returns the canonical dev `server_origin`, or `null` if invalid.
 *
 * Same non-normalizing guards as the frozen production canonicalizer, except dev
 * mode allows both ws:// and wss:// to any host, including raw non-loopback IPs.
 */
export function canonicalizeDevOrigin(input: string): string | null {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }

  const scheme = url.protocol;
  const host = url.hostname;

  if (scheme !== "wss:" && scheme !== "ws:") return null;
  if (url.username || url.password) return null;
  if (url.search || url.hash) return null;
  if (url.pathname && url.pathname !== "/") return null;
  if (url.port === "0") return null;
  if (host.endsWith(".")) return null;
  if (host.includes("%")) return null;

  const isIPv6 = host.startsWith("[");
  const isIPv4Like = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
  if (isIPv4Like && !ipv4OctetsValid(host)) return null;
  if (!isIPv6 && !isIPv4Like) {
    const dnsLabel = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
    if (!host.split(".").every((label) => dnsLabel.test(label))) return null;
  }

  const portPart = url.port ? `:${url.port}` : "";
  const canonical = `${scheme}//${host}${portPart}`;
  if (canonical !== input) return null;
  return canonical;
}
