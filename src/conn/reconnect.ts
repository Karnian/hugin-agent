/**
 * Transport reconnect helpers (the loop itself lives in `daemon.ts`). Resume of
 * in-flight work from `active_jobs`/`pending_results` is P4.
 */

/** Exponential backoff with a cap: `min * 2^attempt`, clamped to `max`. */
export function backoffDelay(attempt: number, minMs: number, maxMs: number): number {
  return Math.min(maxMs, minMs * 2 ** attempt);
}

/** Promise sleep that resolves early if `signal` aborts. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const onAbort = () => {
      cleanup();
      resolve();
    };
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);
    timer.unref?.();
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
