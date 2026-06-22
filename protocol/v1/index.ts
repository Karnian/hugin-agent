/**
 * Hugin Agent protocol v1 — public entrypoint.
 *
 * Both `hugind` (agent) and the cloud relay import from here so the wire
 * contract never drifts between the two codebases.
 */

export * from "./messages";
export { PROTOCOL_VERSION } from "./messages";

/**
 * Negotiate a protocol version at handshake time.
 *
 * Rules:
 *   - Prerelease/draft versions (e.g. "1.1.0-draft") are unstable and require
 *     an EXACT match, so a draft never silently negotiates against a different
 *     build (the old major-only check let "1.0.0-draft" match "1.999.0").
 *   - Stable versions: identical MAJOR is compatible (additive minor/patch
 *     only). Anything else is rejected rather than guessed.
 */
export function negotiateVersion(
  agentVersion: string,
  serverSupported: readonly string[],
): { ok: true; version: string } | { ok: false; reason: string } {
  const majorOf = (v: string) => (v.split("-")[0] ?? v).split(".")[0] ?? "";
  const preOf = (v: string) => v.split("-")[1] ?? null;

  if (preOf(agentVersion)) {
    const exact = serverSupported.find((v) => v === agentVersion);
    return exact
      ? { ok: true, version: exact }
      : { ok: false, reason: `prerelease ${agentVersion} requires exact server support` };
  }

  const want = majorOf(agentVersion);
  const match = serverSupported.find((v) => !preOf(v) && majorOf(v) === want);
  return match
    ? { ok: true, version: match }
    : { ok: false, reason: `stable major v${want} not in server-supported {${serverSupported.join(", ")}}` };
}
