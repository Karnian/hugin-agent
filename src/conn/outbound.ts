/**
 * Outbound message builders. Every message gets the shared envelope (`id`, `ts`)
 * stamped here. (Attempt-scoped `lease_id` + `seq` stamping lands in P2 with the
 * job path.)
 */

import type { Message } from "../../protocol/v1/index";
import { messageId } from "../util/ids";

export function envelope(): { id: string; ts: string } {
  return { id: messageId(), ts: new Date().toISOString() };
}

/** Liveness heartbeat (agent→server). P1: bare; `active_attempts`/`capacity`
 *  arrive with the job path (P2). */
export function heartbeatMsg(): Message {
  return { ...envelope(), type: "heartbeat" };
}
