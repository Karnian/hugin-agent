/**
 * Durable per-attempt event log (SQLite / better-sqlite3, synchronous — writes
 * sit on the critical path before `stream.event` is sent). Owns:
 *  - attempts (idempotent create, keyed by attempt_id)
 *  - stream events (seq'd, persisted BEFORE send; GC'd once cumulative-acked)
 *  - terminal results (kept until digest-acked)
 *  - backpressure counters (unacked bytes/events per attempt + per connection)
 */

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS attempts (
  attempt_id   TEXT PRIMARY KEY,
  job_id       TEXT NOT NULL,
  lease_id     TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  status       TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  last_seq     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
  attempt_id TEXT NOT NULL,
  seq        INTEGER NOT NULL,
  event_id   TEXT NOT NULL,
  bytes      INTEGER NOT NULL,
  payload    TEXT NOT NULL,
  PRIMARY KEY (attempt_id, seq)
);
CREATE TABLE IF NOT EXISTS results (
  attempt_id      TEXT PRIMARY KEY,
  job_id          TEXT NOT NULL,
  lease_id        TEXT NOT NULL,
  final_status    TEXT NOT NULL,
  result_digest   TEXT NOT NULL,
  result_size     INTEGER NOT NULL,
  payload         TEXT NOT NULL,
  last_emitted_seq INTEGER NOT NULL
);
`;

export interface AttemptRow {
  attempt_id: string;
  job_id: string;
  lease_id: string;
  agent_run_id: string;
  status: string;
  created_at: string;
  /** Optional on create (DB DEFAULT 0); always present on read. */
  last_seq?: number;
}

/** Wire-shaped resume rows for `hello`. */
export interface ActiveJobRow {
  job_id: string;
  attempt_id: string;
  lease_id: string;
  status: string;
  last_emitted_seq: number;
}

export interface StoredResult {
  attempt_id: string;
  job_id: string;
  lease_id: string;
  final_status: string;
  result_digest: string;
  result_size: number;
  payload: string;
  last_emitted_seq: number;
}

export class EventLog {
  private db: Database.Database;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA);
  }

  /** Idempotent: returns true if a NEW attempt row was created, false if it
   *  already existed (duplicate `job.assign`). */
  createAttempt(a: AttemptRow): boolean {
    const info = this.db
      .prepare(
        "INSERT OR IGNORE INTO attempts (attempt_id, job_id, lease_id, agent_run_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(a.attempt_id, a.job_id, a.lease_id, a.agent_run_id, a.status, a.created_at);
    return info.changes === 1;
  }

  getAttempt(attemptId: string): AttemptRow | undefined {
    return this.db.prepare("SELECT * FROM attempts WHERE attempt_id = ?").get(attemptId) as
      | AttemptRow
      | undefined;
  }

  setAttemptStatus(attemptId: string, status: string): void {
    this.db.prepare("UPDATE attempts SET status = ? WHERE attempt_id = ?").run(status, attemptId);
  }

  /** Update the durable attempt lease (lease.granted rotation) so the post-terminal
   *  `leaseOk` fallback reflects the current generation. */
  setAttemptLease(attemptId: string, leaseId: string): void {
    this.db.prepare("UPDATE attempts SET lease_id = ? WHERE attempt_id = ?").run(leaseId, attemptId);
  }

  /** Re-stamp a stored pending result (resend_result across a rotation): the new
   *  lease changes the digest, so payload + digest + lease must move together to
   *  keep the eventual result.ack matchable. */
  updateResult(attemptId: string, leaseId: string, digest: string, payload: string): void {
    this.db
      .prepare("UPDATE results SET lease_id = ?, result_digest = ?, payload = ?, result_size = ? WHERE attempt_id = ?")
      .run(leaseId, digest, payload, Buffer.byteLength(payload, "utf8"), attemptId);
  }

  deleteAttempt(attemptId: string): void {
    this.db.prepare("DELETE FROM attempts WHERE attempt_id = ?").run(attemptId);
    this.db.prepare("DELETE FROM events WHERE attempt_id = ?").run(attemptId);
  }

  /** Persist a stream event BEFORE it is sent (durability + resend on resume).
   *  Also advances the attempt's high-water `last_seq` (survives ack GC of events,
   *  so `hello.active_jobs.last_emitted_seq` is correct after reconnect). */
  appendEvent(attemptId: string, seq: number, eventId: string, bytes: number, payload: string): void {
    this.db
      .prepare("INSERT INTO events (attempt_id, seq, event_id, bytes, payload) VALUES (?, ?, ?, ?, ?)")
      .run(attemptId, seq, eventId, bytes, payload);
    this.db.prepare("UPDATE attempts SET last_seq = ? WHERE attempt_id = ? AND last_seq < ?").run(seq, attemptId, seq);
  }

  /** Durable stream-event payloads with seq > afterSeq, in order (for resume_from). */
  eventsAfter(attemptId: string, afterSeq: number): string[] {
    const rows = this.db
      .prepare("SELECT payload FROM events WHERE attempt_id = ? AND seq > ? ORDER BY seq")
      .all(attemptId, afterSeq) as Array<{ payload: string }>;
    return rows.map((r) => r.payload);
  }

  /** Non-terminal attempts, shaped for `hello.active_jobs`. */
  activeJobsForResume(): ActiveJobRow[] {
    const rows = this.db
      .prepare(
        "SELECT job_id, attempt_id, lease_id, status, last_seq FROM attempts WHERE status IN ('accepted','starting','running','cancelling')",
      )
      .all() as Array<{ job_id: string; attempt_id: string; lease_id: string; status: string; last_seq: number }>;
    return rows.map((r) => ({
      job_id: r.job_id,
      attempt_id: r.attempt_id,
      lease_id: r.lease_id,
      status: r.status,
      last_emitted_seq: r.last_seq,
    }));
  }

  /** Cumulative ack → GC every event with seq <= ackSeq (server has it durably). */
  ackEvents(attemptId: string, ackSeq: number): void {
    this.db.prepare("DELETE FROM events WHERE attempt_id = ? AND seq <= ?").run(attemptId, ackSeq);
  }

  unackedEvents(attemptId: string): number {
    const r = this.db
      .prepare("SELECT COUNT(*) AS n FROM events WHERE attempt_id = ?")
      .get(attemptId) as { n: number };
    return r.n;
  }

  unackedBytes(attemptId: string): number {
    const r = this.db
      .prepare("SELECT COALESCE(SUM(bytes), 0) AS b FROM events WHERE attempt_id = ?")
      .get(attemptId) as { b: number };
    return r.b;
  }

  connUnackedBytes(): number {
    const r = this.db.prepare("SELECT COALESCE(SUM(bytes), 0) AS b FROM events").get() as { b: number };
    return r.b;
  }

  saveResult(r: StoredResult): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO results
         (attempt_id, job_id, lease_id, final_status, result_digest, result_size, payload, last_emitted_seq)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(r.attempt_id, r.job_id, r.lease_id, r.final_status, r.result_digest, r.result_size, r.payload, r.last_emitted_seq);
  }

  getResult(attemptId: string): StoredResult | undefined {
    return this.db.prepare("SELECT * FROM results WHERE attempt_id = ?").get(attemptId) as
      | StoredResult
      | undefined;
  }

  /** Digest-matched GC: delete the pending result only if the ack digest matches
   *  the stored one (confirms the PAYLOAD is durable, not merely the id). */
  ackResult(attemptId: string, digest: string): boolean {
    const stored = this.getResult(attemptId);
    if (!stored || stored.result_digest !== digest) return false;
    this.db.prepare("DELETE FROM results WHERE attempt_id = ?").run(attemptId);
    return true;
  }

  /** Unconditional result GC (resume ack_pending / abandon). */
  deleteResult(attemptId: string): void {
    this.db.prepare("DELETE FROM results WHERE attempt_id = ?").run(attemptId);
  }

  activeAttempts(): AttemptRow[] {
    return this.db.prepare("SELECT * FROM attempts").all() as AttemptRow[];
  }

  pendingResults(): StoredResult[] {
    return this.db.prepare("SELECT * FROM results").all() as StoredResult[];
  }

  close(): void {
    this.db.close();
  }
}
