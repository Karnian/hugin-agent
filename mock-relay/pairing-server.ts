/**
 * Minimal mock PAIRING server for hugind e2e (auth-pairing-spec §3) — the HTTP
 * device-code counterpart to `mock-relay/server.ts` (the WSS relay). It mints an
 * `agent_id`/`key_id`/`tenant_id`, registers the device PUBLIC key, and returns
 * the relay URL to dial. It also records every raw request body so a test can
 * prove the device PRIVATE key (seed) never crosses the wire.
 *
 * Not production: no real device-code UI, no persistence, single pending device.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

export interface MockPairingOpts {
  /** ws(s):// relay origin returned to the client on approval. */
  relayUrl: string;
  agentId?: string;
  keyId?: string;
  tenantId?: string;
  userId?: string;
  /** How many `/poll` calls return "pending" before "approved" (default 1). */
  pendingPolls?: number;
  intervalMs?: number;
  expiresInMs?: number;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export class MockPairingServer {
  private server: Server | null = null;
  port = 0;
  /** Raw JSON bodies of every request — the audit trail a test greps for the seed. */
  readonly requestBodies: string[] = [];
  /** base64url public keys received at `/v1/pair/start`. */
  readonly registeredPublicKeys: string[] = [];
  private polls = 0;
  private deviceCode = "dc-mock-0001";

  constructor(private readonly opts: MockPairingOpts) {}

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

  private send(res: ServerResponse, status: number, body: unknown): void {
    const payload = JSON.stringify(body);
    res.writeHead(status, { "content-type": "application/json" });
    res.end(payload);
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const raw = await readBody(req);
    this.requestBodies.push(raw);
    let body: Record<string, unknown> = {};
    try {
      body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
    } catch {
      return this.send(res, 400, { error: "bad_json" });
    }

    if (req.method === "POST" && req.url === "/v1/pair/start") {
      if (typeof body.public_key === "string") this.registeredPublicKeys.push(body.public_key);
      return this.send(res, 200, {
        device_code: this.deviceCode,
        user_code: "WXYZ-1234",
        verification_uri: `${this.baseUrl()}/verify`,
        interval_ms: this.opts.intervalMs ?? 10,
        expires_in_ms: this.opts.expiresInMs ?? 60_000,
      });
    }

    if (req.method === "POST" && req.url === "/v1/pair/poll") {
      if (body.device_code !== this.deviceCode) return this.send(res, 400, { error: "unknown_device_code" });
      this.polls += 1;
      if (this.polls <= (this.opts.pendingPolls ?? 1)) return this.send(res, 200, { status: "pending" });
      return this.send(res, 200, {
        status: "approved",
        agent_id: this.opts.agentId ?? "agent-mint-01",
        key_id: this.opts.keyId ?? "key-mint-01",
        tenant_id: this.opts.tenantId ?? "acme",
        user_id: this.opts.userId ?? "user-42",
        relay_url: this.opts.relayUrl,
      });
    }

    return this.send(res, 404, { error: "not_found" });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      const server = this.server;
      if (!server) return resolve();
      server.close(() => resolve());
    });
  }
}
