// Orchestrates claim, delivery, and state transitions for outbox messages.
import { createDefaultOutboxProcessorDeps } from "./deps";
import { deliverClaimedOutboxEmail } from "./delivery";
import type { OutboxWorkerMessage } from "./message";
import {
  claimDueOutboxEmail,
  finalizeOutboxEmailSent,
  recordOutboxEmailFailure,
} from "./state";
import type { OutboxProcessResult, OutboxProcessorDeps } from "./types";

export async function processOutboxEmailMessage(
  message: OutboxWorkerMessage,
  deps: OutboxProcessorDeps = createDefaultOutboxProcessorDeps(),
  signal?: AbortSignal,
): Promise<OutboxProcessResult> {
  signal?.throwIfAborted();
  const claim = await claimDueOutboxEmail(message, deps);
  if (!claim) return { ok: true, outcome: "skipped" };

  try {
    if (signal?.aborted) return { ok: true, outcome: "stale" };
    await deliverClaimedOutboxEmail(claim.row, deps, signal);
    if (signal?.aborted) return { ok: true, outcome: "stale" };
    const finalized = await finalizeOutboxEmailSent(claim.row.id, claim.claimToken, deps);
    return { ok: true, outcome: finalized ? "sent" : "stale" };
  } catch (error) {
    if (signal?.aborted) return { ok: true, outcome: "stale" };
    const failure = await recordOutboxEmailFailure(claim.row, claim.claimToken, error, deps);
    const outcome = failure === "terminal" ? "failed" : failure;
    return { ok: true, outcome };
  }
}
