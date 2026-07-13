// Claim, finalize, retry, and failure transitions for outbox rows.
import type { OutboxWorkerMessage } from "./message";
import type {
  ClaimableOutboxEmailRow,
  OutboxClaim,
  OutboxProcessorDeps,
  OutboxStateDeps,
} from "./types";

export const CLAIM_LEASE_MS = 5 * 60 * 1000;
export const MAX_OUTBOX_ATTEMPTS = 5;

function addMilliseconds(date: Date, milliseconds: number): Date {
  return new Date(date.getTime() + milliseconds);
}

function getSafeErrorCode(error: unknown): string {
  if (error instanceof Error && error.message === "EMAIL_SEND_FAILED") {
    return "EMAIL_SEND_FAILED";
  }
  if (error instanceof Error && error.message === "EMAIL_SEND_TIMEOUT") {
    return "EMAIL_SEND_TIMEOUT";
  }
  if (error instanceof Error && error.message === "OUTBOX_RECIPIENT_NOT_FOUND") {
    return "OUTBOX_RECIPIENT_NOT_FOUND";
  }
  if (error instanceof Error && error.message === "OUTBOX_UNSUPPORTED_EVENT_TYPE") {
    return "OUTBOX_UNSUPPORTED_EVENT_TYPE";
  }
  if (error instanceof Error && error.message === "INVITE_DELIVERY_DECRYPT_FAILED") {
    return "INVITE_DELIVERY_DECRYPT_FAILED";
  }
  return "OUTBOX_DELIVERY_FAILED";
}

function calculateBackoff(attempts: number, now: Date, rowId: string): Date {
  const baseMinutes = Math.min(60, 2 ** Math.max(0, attempts - 1));
  const jitterSeed = [...rowId].reduce((sum, character) => sum + character.charCodeAt(0), attempts);
  const jitterRatio = (jitterSeed % 26) / 100;
  return addMilliseconds(now, baseMinutes * (1 + jitterRatio) * 60 * 1000);
}

export async function claimDueOutboxEmail(
  message: OutboxWorkerMessage,
  deps: OutboxProcessorDeps
): Promise<OutboxClaim | null> {
  return deps.db.$transaction(async (tx) => {
    const now = deps.now();
    const rows = await tx.queryClaimableOutboxEmails(message.id, now);
    const row = rows[0];
    if (!row) return null;

    const claimToken = deps.generateClaimToken();
    const result = await tx.updateOutboxEmailMany({
      where: { id: row.id, status: { in: ["PENDING", "CLAIMED"] } },
      data: {
        status: "CLAIMED",
        claimedAt: now,
        claimToken,
        leaseExpiresAt: addMilliseconds(now, CLAIM_LEASE_MS),
        lastErrorCode: null,
      },
    });

    if (result.count !== 1) return null;
    return { row, claimToken };
  });
}

export async function finalizeOutboxEmailSent(
  id: string,
  claimToken: string,
  deps: OutboxStateDeps
): Promise<boolean> {
  const now = deps.now();
  const result = await deps.db.updateOutboxEmailMany({
    where: { id, claimToken, status: "CLAIMED" },
    data: {
      status: "SENT",
      sentAt: now,
      claimToken: null,
      leaseExpiresAt: null,
      inviteCiphertext: null,
      keyVersion: null,
      clearedAt: now,
    },
  });

  return result.count === 1;
}

export async function recordOutboxEmailFailure(
  row: ClaimableOutboxEmailRow,
  claimToken: string,
  error: unknown,
  deps: OutboxStateDeps
): Promise<"terminal" | "retry" | "stale"> {
  const now = deps.now();
  const attempts = row.attempts + 1;
  const isTerminal = attempts >= MAX_OUTBOX_ATTEMPTS;
  const sharedData = {
    attempts,
    claimToken: null,
    leaseExpiresAt: null,
    lastErrorCode: getSafeErrorCode(error),
  };

  const data = isTerminal
    ? {
        ...sharedData,
        status: "FAILED" as const,
        failedAt: now,
        nextAttemptAt: null,
        inviteCiphertext: null,
        keyVersion: null,
        clearedAt: now,
      }
    : {
        ...sharedData,
        status: "PENDING" as const,
        nextAttemptAt: calculateBackoff(attempts, now, row.id),
      };

  const result = await deps.db.updateOutboxEmailMany({
    where: { id: row.id, claimToken, status: "CLAIMED" },
    data,
  });

  if (result.count !== 1) return "stale";
  return isTerminal ? "terminal" : "retry";
}
