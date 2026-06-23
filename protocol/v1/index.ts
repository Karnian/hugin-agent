/**
 * Hugin Agent protocol v1 — public entrypoint.
 *
 * Both `hugind` (agent) and the cloud relay import from here so the wire
 * contract never drifts between the two codebases.
 */

import { DIRECTION, HANDSHAKE_TYPES, SemVer, type Message } from "./messages";

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
  // Strict semver via the single SemVer SSOT from messages.ts (incl. its .max(64)
  // bound) so empty/malformed/over-long inputs ("", ".1.0", "1.x.y") can't match.
  const isSemVer = (v: string) => SemVer.safeParse(v).success;
  const majorOf = (v: string) => v.split(".")[0] ?? "";
  const preOf = (v: string) => v.split("-")[1] ?? null;

  if (!isSemVer(agentVersion)) {
    return { ok: false, reason: `malformed agent version "${agentVersion}"` };
  }
  // Ignore malformed entries the server may advertise.
  const supported = serverSupported.filter((v) => isSemVer(v));

  if (preOf(agentVersion)) {
    const exact = supported.find((v) => v === agentVersion);
    return exact
      ? { ok: true, version: exact }
      : { ok: false, reason: `prerelease ${agentVersion} requires exact server support` };
  }

  const want = majorOf(agentVersion);
  const match = supported.find((v) => !preOf(v) && majorOf(v) === want);
  return match
    ? { ok: true, version: match }
    : { ok: false, reason: `stable major v${want} not in server-supported {${serverSupported.join(", ")}}` };
}

/**
 * Enforce DIRECTION + handshake phase on an inbound, already-parsed message.
 * The `DIRECTION` constant alone is documentation; this is the enforcement
 * (Codex C3). Call after `parseMessage` on every received frame.
 */
export function validateInbound(
  msg: Message,
  opts: { receiver: "agent" | "server"; authed: boolean },
): { ok: true } | { ok: false; code: "bad_direction" | "bad_state" } {
  const dir = DIRECTION[msg.type];
  const allowed = opts.receiver === "agent" ? ["s2a", "both"] : ["a2s", "both"];
  if (!allowed.includes(dir)) return { ok: false, code: "bad_direction" };
  if (!opts.authed && !HANDSHAKE_TYPES.has(msg.type)) return { ok: false, code: "bad_state" };
  return { ok: true };
}
