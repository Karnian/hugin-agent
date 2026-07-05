/**
 * hugind lifecycle: dial out → handshake → heartbeat + job dispatch → (on close)
 * reconnect with backoff. P2a adds the job path (registry/eventlog/engine) behind
 * the post-handshake message pump.
 */

import { join } from "node:path";
import type { Config } from "./config";
import type { MessageV2 } from "../protocol/v1/index";
import type { Engine } from "./engine/types";
import { RelayClient } from "./conn/client";
import { agentDrainingMsg, envelope } from "./conn/outbound";
import { performHandshake, type ResumeState, type Signer } from "./conn/handshake";
import { startHeartbeat } from "./conn/heartbeat";
import { backoffDelay, sleep } from "./conn/reconnect";
import { EventLog } from "./store/eventlog";
import { JobRegistry } from "./jobs/registry";
import { JobManager } from "./jobs/manager";
import { log } from "./log";
import type { SessionEnumerator, SessionListResult } from "./sessions/enumerator";
import { SessionResumeManager } from "./sessions/resume-manager";
import type { ResumeRunner, ResumeRunnerRegistry } from "./sessions/resume";

/** WS path the C2 serves the agent connection at — the sibling of the pairing
 *  HTTP endpoints (`/api/v1/hugin-agents/pair/complete`, `.../capability`). The
 *  frozen `server_origin` bound into the handshake transcript stays PATH-LESS
 *  (the bare `config.serverUrl` origin); this path is appended only at DIAL time.
 *  The mock relay accepts an upgrade on any path, so e2e never exercised it. */
export const RELAY_CONNECT_PATH = "/api/v1/hugin-agents/connect";

/** Build the WS dial URL by placing `RELAY_CONNECT_PATH` on the canonical relay
 *  origin. Uses the URL API so a `serverUrl` with a trailing slash still joins
 *  cleanly, and drops any stray query/hash. */
export function relayDialUrl(serverUrl: string): string {
  const u = new URL(serverUrl);
  u.pathname = RELAY_CONNECT_PATH;
  u.search = "";
  u.hash = "";
  return u.toString();
}

export class Daemon {
  private running = false;
  private lastEpoch = -1;
  /** The client used for OUTBOUND routing — set only after auth completes. */
  private activeClient: RelayClient | null = null;
  /** The current session's client (in-flight or active) — for stop() to close. */
  private sessionClient: RelayClient | null = null;
  private readonly abort = new AbortController();
  private readonly store: EventLog;
  private readonly registry: JobRegistry;
  private readonly manager: JobManager;
  private readonly resumeManager: SessionResumeManager;

  constructor(
    private readonly config: Config,
    private readonly signer: Signer,
    engine: Engine,
    /** Whether the approval gate is usable (startup isolation self-check). When
     *  false, gated (write/exec) jobs are rejected — fail closed. */
    gateAvailable = true,
    private readonly sessionEnumerator?: Pick<SessionEnumerator, "list" | "validateHandle" | "registerForked">,
    resumeRunners?: ResumeRunner | ResumeRunnerRegistry,
  ) {
    this.store = new EventLog(config.dbPath ?? join(config.stateDir, "eventlog.db"));
    // Registry + manager are DAEMON-level so live runs (and their lease/approval
    // state) survive reconnects; outbound routes to whichever client is current.
    this.registry = new JobRegistry(config.maxConcurrent);
    this.manager = new JobManager(
      this.registry,
      this.store,
      engine,
      (m) => this.safeSend(m),
      {
        events: config.maxUnackedEventsPerAttempt,
        bytes: config.maxUnackedBytesPerAttempt,
        conn: config.maxUnackedBytesPerConn,
      },
      gateAvailable,
      config.approvalTimeoutMs,
    );
    this.resumeManager = new SessionResumeManager((m) => this.safeSend(m), {
      enumerator: this.sessionEnumerator,
      runners: normalizeResumeRunners(resumeRunners),
      maxUnackedEvents: config.maxUnackedEventsPerAttempt,
      turnTimeoutMs: config.sessionTurnTimeoutMs,
    });
  }

  private safeSend(m: MessageV2): void {
    try {
      this.activeClient?.send(m);
    } catch (e) {
      log.warn("send failed", { err: String(e) });
    }
  }

  /** Monotonic `connection_epoch` gate (plan §5.1). */
  acceptEpoch(epoch: number): boolean {
    if (epoch <= this.lastEpoch) return false;
    this.lastEpoch = epoch;
    return true;
  }

  /** e2e/introspection: durable pending results + tracked attempts. */
  pendingResultCount(): number {
    return this.store.pendingResults().length;
  }
  activeAttemptCount(): number {
    return this.store.activeAttempts().length;
  }

  async start(): Promise<void> {
    this.running = true;
    let attempt = 0;
    while (this.running) {
      let established = false;
      try {
        established = await this.runSession();
      } catch (e) {
        log.warn("session error", { err: String(e) });
      }
      if (established) attempt = 0;
      if (!this.running) break;
      const delay = backoffDelay(attempt, 500, 10_000);
      attempt++;
      log.info("reconnecting", { delayMs: delay, attempt });
      await sleep(delay, this.abort.signal);
    }
    this.store.close();
    log.info("daemon stopped");
  }

  private async runSession(): Promise<boolean> {
    const client = new RelayClient();
    this.sessionClient = client;
    let established = false;
    const closed = new Promise<void>((resolve) => {
      client.onClose(() => resolve());
    });
    try {
      // Log the resolved dial URL (origin + connect path) so a path/upgrade
      // rejection is diagnosable — a bare `403` on the raw origin was exactly the
      // failure this surfaced. The transcript server_origin stays the bare origin.
      const dialUrl = relayDialUrl(this.config.serverUrl);
      log.info("dialing relay", { url: dialUrl });
      await client.connect(dialUrl);
      // Report our durable state so the server can issue resume directives.
      const resumeState: ResumeState = {
        activeJobs: this.store.activeJobsForResume() as ResumeState["activeJobs"],
        pendingResults: this.store.pendingResults().map((r) => ({
          job_id: r.job_id,
          attempt_id: r.attempt_id,
          lease_id: r.lease_id,
          final_status: r.final_status,
          result_digest: r.result_digest,
          result_size: r.result_size,
          last_emitted_seq: r.last_emitted_seq,
        })) as ResumeState["pendingResults"],
      };
      const hs = await performHandshake(client, this.config, this.signer, resumeState);
      if (!this.acceptEpoch(hs.connectionEpoch)) {
        log.warn("non-monotonic connection_epoch — closing", {
          epoch: hs.connectionEpoch,
          lastEpoch: this.lastEpoch,
        });
        client.close(1008);
        return false;
      }
      established = true;
      log.info("handshake ok", { negotiatedVersion: hs.negotiatedVersion, connectionEpoch: hs.connectionEpoch });

      // If stop() fired mid-handshake, bail: activeClient was null then, so stop()
      // couldn't target this in-flight client.
      if (!this.running) {
        client.close();
        return established;
      }

      // Only NOW route outbound to this client — before auth completes, a live
      // run's frames would be rejected pre-handshake (they stay durable + resume).
      this.activeClient = client;

      // Apply resume BEFORE draining buffered post-handshake messages (onMessage
      // drains pending synchronously): a stale resume lease must not overwrite a
      // newer lease.granted that arrived right after hello.accepted.
      if (hs.resume.length > 0) this.manager.applyResume(hs.resume);

      // Wire this connection's inbound pump (drains any buffered messages now).
      client.onMessage((m) => {
        switch (m.type) {
          case "job.assign":
            this.manager.handleAssign(m);
            break;
          case "stream.ack":
            this.manager.handleStreamAck(m);
            break;
          case "job.result.ack":
            this.manager.handleResultAck(m);
            break;
          case "job.cancel":
            this.manager.handleCancel(m);
            break;
          case "approval.response":
            this.manager.handleApprovalResponse(m);
            break;
          case "lease.revoke":
            this.manager.handleRevoke(m);
            break;
          case "lease.granted":
            this.manager.handleLeaseGranted(m);
            break;
          case "session.list.request":
            {
              let result: SessionListResult = { sessions: [], next_cursor: null, truncated: false };
              try {
                result = this.sessionEnumerator?.list({ filter: m.filter, page: m.page }) ?? result;
              } catch (e) {
                log.warn("session enumeration failed", { err: String(e) });
              }
              this.safeSend({
                ...envelope(),
                type: "session.list.response",
                request_id: m.request_id,
                sessions: result.sessions,
                next_cursor: result.next_cursor,
                truncated: result.truncated,
              });
            }
            break;
          case "session.resume.request":
            this.resumeManager.handleRequest(m);
            break;
          case "session.cancel":
            this.resumeManager.handleCancel(m);
            break;
          case "session.ack":
            this.resumeManager.handleAck(m);
            break;
          case "session.message":
            this.resumeManager.handleMessage(m);
            break;
          default:
            break; // others ignored
        }
      });

      const stopHeartbeat = startHeartbeat(client, hs.heartbeatIntervalMs);
      try {
        await closed;
      } finally {
        stopHeartbeat();
      }
    } finally {
      client.close();
      if (this.activeClient === client) this.activeClient = null;
      if (this.sessionClient === client) this.sessionClient = null;
    }
    return established;
  }

  stop(): void {
    this.running = false;
    this.abort.abort();
    // Graceful drain notice before we disconnect (best-effort; only if authed).
    if (this.activeClient) {
      try {
        this.activeClient.send(agentDrainingMsg("shutdown"));
      } catch {
        /* socket already gone */
      }
    }
    // Close whichever client this session holds — in-flight (pre-auth) or active —
    // so a stop() during the handshake doesn't leave the loop awaiting close.
    (this.sessionClient ?? this.activeClient)?.close();
  }
}

function normalizeResumeRunners(input?: ResumeRunner | ResumeRunnerRegistry): ResumeRunnerRegistry {
  if (!input) return {};
  if ("run" in input && typeof input.run === "function") return { claude: input };
  return input as ResumeRunnerRegistry;
}
