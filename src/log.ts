/**
 * Minimal structured logger — one JSON object per line to stderr (stdout is
 * reserved so the daemon can stay pipe-friendly).
 */

type Level = "debug" | "info" | "warn" | "error";
type Fields = Record<string, unknown>;

function emit(level: Level, msg: string, fields?: Fields): void {
  // Envelope fields win over caller-supplied fields (no level/msg/t overwrite).
  const record: Fields = { ...fields, t: new Date().toISOString(), level, msg };
  process.stderr.write(`${JSON.stringify(record)}\n`);
}

export const log = {
  debug: (msg: string, fields?: Fields) => emit("debug", msg, fields),
  info: (msg: string, fields?: Fields) => emit("info", msg, fields),
  warn: (msg: string, fields?: Fields) => emit("warn", msg, fields),
  error: (msg: string, fields?: Fields) => emit("error", msg, fields),
};
