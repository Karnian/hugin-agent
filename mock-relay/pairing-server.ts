/**
 * Mock rev2 pairing server for daemon e2e (auth-pairing-spec §3).
 *
 * This is intentionally single-process and in-memory, but it mirrors the rev2
 * pairing semantics that matter to the daemon: hpk1 minting, PoP verification,
 * issued→pending CAS, idempotent same-winner re-complete, opaque poll tokens,
 * and browser-confirm/reject hooks. It keeps request body/public-key audit
 * arrays so tests can assert the seed never crossed the wire.
 */

import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  PAIRING_SECRET_RE,
  REJECTED_TEST_PUBLIC_HEX,
  buildPairingTranscript,
  keyFingerprint,
  validateB64u32,
} from "../protocol/v1/pairing";
import { b64u, verifyTranscript } from "../protocol/v1/ed25519";
import { canonicalizeServerOrigin } from "../protocol/v1/origin";
import { SIMPLE_PAIRING_CAPABILITY_RESPONSE } from "../src/auth/simple-pairing-capability";

const PROTOCOL_VERSION = "1.0.0";
const CAPABILITY_SUFFIX = "/api/v1/hugin-agents/capability";
const COMPLETE_SUFFIX = "/api/v1/hugin-agents/pair/complete";
const STATUS_SUFFIX = "/api/v1/hugin-agents/pair/status";
const DEFAULT_BODY_LIMIT_BYTES = 4096;
const DEFAULT_TOKEN_TTL_MS = 5 * 60_000;
const DEFAULT_PENDING_TTL_MS = 10 * 60_000;
const DEFAULT_ACTIVE_POLL_TOKEN_TTL_MS = 30_000;
const DEFAULT_ATTEMPT_CAP = 10;
const DEFAULT_DEVICE_CAP = 10;
const DEFAULT_POLL_TOKEN_CAP = 5;
const POP_SIGNATURE_RE = /^[A-Za-z0-9_-]{86}$/;

type PairingState = "issued" | "pending" | "active" | "rejected" | "expired" | "burned";

export interface MockPairingOpts {
  tenantId?: string;
  /** Alias kept for older tests; `createdByUserId` is the rev2 row field. */
  userId?: string;
  createdByUserId?: string;
  agentId?: string;
  keyId?: string;
  tokenTtlMs?: number;
  pendingTtlMs?: number;
  activePollTokenTtlMs?: number;
  attemptCap?: number;
  deviceCap?: number;
  pollTokenCap?: number;
  bodyLimitBytes?: number;
  nowImpl?: () => number;
  /** Return pending for N status responses, then activate after the Nth response. */
  confirmAfterStatusPolls?: number;
  /* test-only */ forceValidStatus404s?: number;
  /* test-only */ forceWrongFingerprint?: boolean;
  /** Legacy option name accepted only so older call sites keep compiling. */
  pendingPolls?: number;
  relayUrl?: string;
  intervalMs?: number;
  expiresInMs?: number;
  /** Opt into the simple pairing variant on /pair/complete. Default stays rev2. */
  simplePairing?: boolean;
  /* test-only */ capabilityStatus?: number;
  /* test-only */ capabilityBody?: unknown;
  /* test-only */ simpleCompleteStatus?: number;
  /* test-only */ simpleCompleteBody?: unknown;
}

export interface MintOptions {
  tenantId?: string;
  createdByUserId?: string;
  userId?: string;
  tokenTtlMs?: number;
  pendingTtlMs?: number;
  /** Test seam for negative cases; omitted in normal use. */
  secret?: string;
}

export interface ConfirmResult {
  status: "active";
  agent_id: string;
  key_id: string;
  tenant_id: string;
}

interface PollTokenRow {
  hash: string;
  issuedAt: number;
  expiresAt: number;
  publicKeyB64u: string;
}

interface PairingRow {
  id: number;
  secretHash: string;
  expectedOrigin: string;
  tokenExp: number;
  pendingExp: number;
  tenantId: string;
  createdByUserId: string;
  state: PairingState;
  attempts: number;
  attemptCap: number;
  winningPublicKey?: Buffer;
  winningPublicKeyB64u?: string;
  fingerprint?: string;
  pollTokens: PollTokenRow[];
  statusPolls: number;
  agentId?: string;
  keyId?: string;
}

class BodyTooLargeError extends Error {}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

function randomB64u32(): string {
  const token = b64u(randomBytes(32));
  if (!PAIRING_SECRET_RE.test(token) || !validateB64u32(token)) {
    throw new Error("generated non-canonical 32-byte base64url token");
  }
  return token;
}

function pathEndsWith(reqUrl: string | undefined, suffix: string): boolean {
  const url = new URL(reqUrl ?? "/", "http://127.0.0.1");
  return url.pathname.endsWith(suffix);
}

function parseJsonObject(raw: string): Record<string, unknown> | null {
  try {
    const parsed = raw ? JSON.parse(raw) : {};
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // Normalize parse failures at the handler boundary.
  }
  return null;
}

function readBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const contentLength = req.headers["content-length"];
    if (typeof contentLength === "string" && Number(contentLength) > maxBytes) {
      req.resume();
      reject(new BodyTooLargeError());
      return;
    }

    const chunks: Buffer[] = [];
    let total = 0;
    let tooLarge = false;

    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        tooLarge = true;
        chunks.length = 0;
        return;
      }
      if (!tooLarge) chunks.push(chunk);
    });
    req.on("end", () => {
      if (tooLarge) reject(new BodyTooLargeError());
      else resolve(Buffer.concat(chunks).toString("utf8"));
    });
    req.on("error", reject);
  });
}

export class MockPairingServer {
  private server: Server | null = null;
  port = 0;
  /** Raw JSON bodies of accepted-size requests, used by seed-off-wire tests. */
  readonly requestBodies: string[] = [];
  /** Public keys that won first completion and were registered for activation. */
  readonly registeredPublicKeys: string[] = [];
  private readonly rowsBySecretHash = new Map<string, PairingRow>();
  private readonly rowsByPollTokenHash = new Map<string, PairingRow>();
  private readonly activeDeviceCounts = new Map<string, number>();
  private readonly semanticFailures: string[] = [];
  private readonly simpleDeviceCodes = new Set<string>();
  private forcedValidStatus404s = 0;
  private nextPairingId = 1;

  constructor(private readonly opts: MockPairingOpts = {}) {}

  baseUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  start(port = 0): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = createServer((req, res) => void this.handle(req, res).catch(() => this.send(res, 500, { error: "internal" })));
      this.server = server;
      server.on("error", reject);
      server.listen(port, "127.0.0.1", () => {
        const addr = server.address();
        this.port = typeof addr === "object" && addr ? addr.port : port;
        resolve(this.port);
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      const server = this.server;
      if (!server) return resolve();
      server.close(() => {
        this.server = null;
        resolve();
      });
    });
  }

  mint(opts: MintOptions = {}): string {
    if (this.port === 0) throw new Error("MockPairingServer.start() must complete before mint()");
    const now = this.now();
    const origin = `ws://127.0.0.1:${this.port}`;
    if (canonicalizeServerOrigin(origin) !== origin) {
      throw new Error(`mock pairing origin is not canonical: ${origin}`);
    }

    const secret = opts.secret ?? randomB64u32();
    if (!validateB64u32(secret)) throw new Error("mint secret must be 43 canonical unpadded base64url chars");

    const tokenTtlMs = opts.tokenTtlMs ?? this.opts.tokenTtlMs ?? DEFAULT_TOKEN_TTL_MS;
    const pendingTtlMs = opts.pendingTtlMs ?? this.opts.pendingTtlMs ?? DEFAULT_PENDING_TTL_MS;
    const exp = Math.floor((now + tokenTtlMs) / 1000);
    const tokenExp = exp * 1000;
    const tenantId = opts.tenantId ?? this.opts.tenantId ?? "acme";
    const createdByUserId = opts.createdByUserId ?? opts.userId ?? this.opts.createdByUserId ?? this.opts.userId ?? "user-42";
    const secretHash = sha256Hex(secret);
    const row: PairingRow = {
      id: this.nextPairingId++,
      secretHash,
      expectedOrigin: origin,
      tokenExp,
      pendingExp: now + pendingTtlMs,
      tenantId,
      createdByUserId,
      state: "issued",
      attempts: 0,
      attemptCap: this.opts.attemptCap ?? DEFAULT_ATTEMPT_CAP,
      pollTokens: [],
      statusPolls: 0,
    };
    this.rowsBySecretHash.set(secretHash, row);

    return `hpk1.${b64u(Buffer.from(JSON.stringify({ v: PROTOCOL_VERSION, origin, secret, exp }), "utf8"))}`;
  }

  mintSimpleDeviceCode(deviceCode = randomB64u32()): string {
    this.simpleDeviceCodes.add(deviceCode);
    return deviceCode;
  }

  confirm(): ConfirmResult | null {
    const row = this.firstPendingRow();
    if (!row) return null;
    return this.confirmRow(row);
  }

  reject(): boolean {
    const row = this.firstPendingRow();
    if (!row) return false;
    if (this.expireRowIfNeeded(row)) return false;
    if (row.state !== "pending") return false;
    row.state = "rejected";
    return true;
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let raw: string;
    try {
      raw = await readBody(req, this.opts.bodyLimitBytes ?? DEFAULT_BODY_LIMIT_BYTES);
    } catch (err) {
      if (err instanceof BodyTooLargeError) return this.send(res, 413, { error: "body_too_large" });
      throw err;
    }
    this.requestBodies.push(raw);

    if (req.method === "GET" && pathEndsWith(req.url, CAPABILITY_SUFFIX)) {
      return this.handleCapability(res);
    }
    if (req.method === "POST" && pathEndsWith(req.url, COMPLETE_SUFFIX)) {
      if (this.opts.simplePairing) return this.handleSimpleComplete(raw, res);
      return this.handleComplete(raw, res);
    }
    if (req.method === "POST" && pathEndsWith(req.url, STATUS_SUFFIX)) {
      return this.handleStatus(raw, res);
    }
    return this.send(res, 404, { error: "not_found" });
  }

  private handleCapability(res: ServerResponse): void {
    const status = this.opts.capabilityStatus ?? (this.opts.simplePairing ? 200 : 404);
    const body = this.opts.capabilityBody ?? (status === 200 ? SIMPLE_PAIRING_CAPABILITY_RESPONSE : { error: "not_found" });
    this.send(res, status, body);
  }

  private handleSimpleComplete(raw: string, res: ServerResponse): void {
    if (this.opts.simpleCompleteStatus !== undefined) {
      return this.send(res, this.opts.simpleCompleteStatus, this.opts.simpleCompleteBody ?? {});
    }

    const body = parseJsonObject(raw);
    if (!body) return this.failComplete(res, "bad_json");

    const keys = Object.keys(body).sort();
    const deviceCode = body.device_code;
    const publicKey = body.public_key;
    if (
      keys.length !== 2 ||
      keys[0] !== "device_code" ||
      keys[1] !== "public_key" ||
      typeof deviceCode !== "string" ||
      typeof publicKey !== "string" ||
      deviceCode.length === 0 ||
      deviceCode.length > 1024 ||
      !validateB64u32(publicKey) ||
      !this.simpleDeviceCodes.has(deviceCode)
    ) {
      return this.failComplete(res, "simple_schema_or_code_gate");
    }

    this.simpleDeviceCodes.delete(deviceCode);
    this.registeredPublicKeys.push(publicKey);
    return this.send(res, 200, {
      agent_id: this.opts.agentId ?? "agent-123",
      key_id: this.opts.keyId ?? "key-123",
      tenant_id: this.opts.tenantId ?? "acme",
    });
  }

  private handleComplete(raw: string, res: ServerResponse): void {
    const body = parseJsonObject(raw);
    if (!body) return this.failComplete(res, "bad_json");

    const secret = body.secret;
    const publicKey = body.public_key;
    const popSignature = body.pop_signature;

    if (
      typeof secret !== "string" ||
      typeof publicKey !== "string" ||
      typeof popSignature !== "string" ||
      !validateB64u32(secret) ||
      !validateB64u32(publicKey) ||
      !POP_SIGNATURE_RE.test(popSignature)
    ) {
      return this.failComplete(res, "schema_or_canonical_gate");
    }

    const secretHash = sha256Hex(secret);
    const row = this.rowsBySecretHash.get(secretHash);
    if (!row) return this.failComplete(res, "unknown_secret");
    this.expireRowIfNeeded(row);
    if (row.state === "expired" || row.state === "burned" || row.state === "rejected") {
      return this.failComplete(res, row.state);
    }

    const publicRaw = Buffer.from(publicKey, "base64url");
    if (publicRaw.toString("hex") === REJECTED_TEST_PUBLIC_HEX) {
      this.incrementAttemptOrBurn(row);
      return this.failComplete(res, "rejected_test_public_key");
    }

    let transcript: Buffer;
    try {
      transcript = buildPairingTranscript({
        secret,
        publicRaw,
        server_origin: row.expectedOrigin,
        protocol_version: PROTOCOL_VERSION,
      });
    } catch {
      this.incrementAttemptOrBurn(row);
      return this.failComplete(res, "transcript_build_failed");
    }

    if (!verifyTranscript(publicRaw, transcript, popSignature)) {
      this.incrementAttemptOrBurn(row);
      return this.failComplete(res, "bad_pop");
    }

    if (row.state === "issued") {
      if (row.attempts >= row.attemptCap) {
        row.state = "burned";
        return this.failComplete(res, "attempt_cap");
      }
      const fingerprint = keyFingerprint(publicRaw);
      const pollToken = this.mintPollToken(row, row.pendingExp, publicKey);
      row.state = "pending";
      row.winningPublicKey = Buffer.from(publicRaw);
      row.winningPublicKeyB64u = publicKey;
      row.fingerprint = fingerprint;
      this.registeredPublicKeys.push(publicKey);
      return this.send(res, 202, { status: "pending", fingerprint: this.responseFingerprint(fingerprint), poll_token: pollToken });
    }

    if (row.state === "pending" || row.state === "active") {
      if (!row.winningPublicKey || !row.winningPublicKey.equals(publicRaw) || !row.fingerprint) {
        return this.failComplete(res, "different_key_after_win");
      }
      const expiresAt = row.state === "active" ? this.now() + (this.opts.activePollTokenTtlMs ?? DEFAULT_ACTIVE_POLL_TOKEN_TTL_MS) : row.pendingExp;
      const pollToken = this.mintPollToken(row, expiresAt, publicKey);
      return this.send(res, 202, { status: "pending", fingerprint: this.responseFingerprint(row.fingerprint), poll_token: pollToken });
    }

    return this.failComplete(res, row.state);
  }

  private handleStatus(raw: string, res: ServerResponse): void {
    const body = parseJsonObject(raw);
    const pollToken = body?.poll_token;
    if (typeof pollToken !== "string") return this.send(res, 404, { error: "invalid_or_expired" });

    const pollTokenHash = sha256Hex(pollToken);
    const row = this.rowsByPollTokenHash.get(pollTokenHash);
    if (!row) return this.send(res, 404, { error: "invalid_or_expired" });

    const token = row.pollTokens.find((t) => t.hash === pollTokenHash);
    const now = this.now();
    if (!token || token.expiresAt <= now) {
      this.removePollToken(row, pollTokenHash);
      return this.send(res, 404, { error: "invalid_or_expired" });
    }

    this.expireRowIfNeeded(row, now);
    if (row.state === "expired" || row.state === "burned" || !row.winningPublicKeyB64u || token.publicKeyB64u !== row.winningPublicKeyB64u) {
      return this.send(res, 404, { error: "invalid_or_expired" });
    }

    const autoConfirmAfter = this.opts.confirmAfterStatusPolls ?? this.opts.pendingPolls;
    if (row.state === "pending" && autoConfirmAfter !== undefined && autoConfirmAfter <= 0) {
      this.confirmRow(row);
    }

    if (this.forceValidStatus404(row, pollTokenHash)) {
      return this.send(res, 404, { error: "invalid_or_expired" });
    }

    if (row.state === "pending" && autoConfirmAfter !== undefined) {
      row.statusPolls += 1;
      this.send(res, 200, { status: "pending" });
      if (row.statusPolls >= autoConfirmAfter) this.confirmRow(row);
      return;
    }

    if (row.state === "pending") return this.send(res, 200, { status: "pending" });
    if (row.state === "rejected") return this.send(res, 200, { status: "rejected" });
    if (row.state === "active" && row.agentId && row.keyId) {
      return this.send(res, 200, { status: "active", agent_id: row.agentId, key_id: row.keyId, tenant_id: row.tenantId });
    }
    return this.send(res, 404, { error: "invalid_or_expired" });
  }

  private send(res: ServerResponse, status: number, body: unknown): void {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
      "cache-control": "no-store",
      "content-type": "application/json",
    });
    res.end(payload);
  }

  private failComplete(res: ServerResponse, reason: string): void {
    this.semanticFailures.push(reason);
    this.send(res, 400, { error: "pairing_failed" });
  }

  private responseFingerprint(fingerprint: string): string {
    if (!this.opts.forceWrongFingerprint) return fingerprint;
    return `${fingerprint[0] === "A" ? "B" : "A"}${fingerprint.slice(1)}`;
  }

  private now(): number {
    return this.opts.nowImpl?.() ?? Date.now();
  }

  private expireRowIfNeeded(row: PairingRow, now = this.now()): boolean {
    if (row.state === "issued" && row.tokenExp <= now) {
      row.state = "expired";
      return true;
    }
    if (row.state === "pending" && row.pendingExp <= now) {
      row.state = "expired";
      return true;
    }
    return row.state === "expired";
  }

  private incrementAttemptOrBurn(row: PairingRow): void {
    if (row.state !== "issued" || this.expireRowIfNeeded(row)) return;
    row.attempts += 1;
    if (row.attempts >= row.attemptCap) row.state = "burned";
  }

  private mintPollToken(row: PairingRow, expiresAt: number, publicKeyB64u: string): string {
    const pollToken = randomB64u32();
    const tokenRow: PollTokenRow = {
      hash: sha256Hex(pollToken),
      issuedAt: this.now(),
      expiresAt,
      publicKeyB64u,
    };
    row.pollTokens.push(tokenRow);
    this.rowsByPollTokenHash.set(tokenRow.hash, row);

    const cap = this.opts.pollTokenCap ?? DEFAULT_POLL_TOKEN_CAP;
    while (row.pollTokens.length > cap) {
      const evicted = row.pollTokens.shift();
      if (evicted) this.rowsByPollTokenHash.delete(evicted.hash);
    }

    return pollToken;
  }

  private removePollToken(row: PairingRow, hash: string): void {
    row.pollTokens = row.pollTokens.filter((t) => t.hash !== hash);
    this.rowsByPollTokenHash.delete(hash);
  }

  private forceValidStatus404(row: PairingRow, hash: string): boolean {
    const cap = this.opts.forceValidStatus404s ?? 0;
    if (this.forcedValidStatus404s >= cap) return false;
    this.forcedValidStatus404s += 1;
    this.removePollToken(row, hash);
    return true;
  }

  private firstPendingRow(): PairingRow | null {
    for (const row of this.rowsBySecretHash.values()) {
      if (this.expireRowIfNeeded(row)) continue;
      if (row.state === "pending") return row;
    }
    return null;
  }

  private confirmRow(row: PairingRow): ConfirmResult | null {
    if (this.expireRowIfNeeded(row)) return null;
    if (row.state === "active" && row.agentId && row.keyId) {
      return { status: "active", agent_id: row.agentId, key_id: row.keyId, tenant_id: row.tenantId };
    }
    if (row.state !== "pending" || !row.winningPublicKey || !row.fingerprint) return null;

    const deviceCounterKey = `${row.tenantId}\0${row.createdByUserId}`;
    const activeCount = this.activeDeviceCounts.get(deviceCounterKey) ?? 0;
    if (activeCount >= (this.opts.deviceCap ?? DEFAULT_DEVICE_CAP)) return null;

    row.agentId = this.opts.agentId ?? `agent-${row.id}-${row.fingerprint.slice(0, 12)}`;
    row.keyId = this.opts.keyId ?? `key-${row.id}-${row.fingerprint.slice(13, 25)}`;
    row.state = "active";
    this.activeDeviceCounts.set(deviceCounterKey, activeCount + 1);
    return { status: "active", agent_id: row.agentId, key_id: row.keyId, tenant_id: row.tenantId };
  }
}
