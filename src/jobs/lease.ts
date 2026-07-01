/**
 * Lease validation (plan §5.4). P2a: an attempt has ONE current lease generation;
 * an inbound attempt-scoped message must carry it. Rotation overlap (accept both
 * old and new during a `lease.granted` window) is P4.
 */

export function leaseMatches(current: string, incoming: string): boolean {
  return current === incoming;
}
