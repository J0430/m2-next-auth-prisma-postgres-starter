// src/features/auth/server/invites/lookupInvite.ts
// Performs generic, side-effect-free invite lookup without exposing miss reasons.
import crypto from "node:crypto";
import { prisma } from "@/lib/prisma";
import {
  monotonicNow,
  padAdmissionTiming,
  remainingDeadlineMs,
  withinDeadline,
  type MonotonicClock,
} from "@/features/auth/server/admission";
import type { InviteLookupResult } from "./invite.types";
import { hashInviteToken, normalizeInviteEmail } from "./token";

const DECOY_INVITE_HASH = crypto
  .createHash("sha256")
  .update("manumu:invite-lookup-decoy")
  .digest();
const GENERIC_LOOKUP_FAILURE = {
  ok: false,
  status: 403,
  body: { ok: false, message: "Unable to complete this request." },
} as const;
const LOOKUP_TARGET_MS = 250;
const LOOKUP_DEPENDENCY_DEADLINE_MS = 75;

function toBuffer(value: Buffer | Uint8Array): Buffer {
  return Buffer.from(value);
}

function constantTimeHashMatches(candidateHash: Buffer, storedHash: Buffer | Uint8Array | null): boolean {
  const storedBytes = storedHash ? toBuffer(storedHash) : null;
  const hasValidStoredDigest = storedBytes?.length === 32;
  const comparableHash = hasValidStoredDigest ? storedBytes : DECOY_INVITE_HASH;
  return crypto.timingSafeEqual(candidateHash, comparableHash) && hasValidStoredDigest;
}

export async function lookupInviteByToken(
  rawToken: string,
  expectedEmail: string | null,
  clock: MonotonicClock = monotonicNow,
): Promise<InviteLookupResult> {
  const startedAtMs = clock();
  const finish = async <T>(result: T): Promise<T> => {
    const elapsedMs = clock() - startedAtMs;
    if (elapsedMs > LOOKUP_TARGET_MS) {
      console.error("security.invite_lookup_timing_parity_breach", {
        targetMs: LOOKUP_TARGET_MS,
        elapsedMs,
      });
      return result;
    }
    await padAdmissionTiming(startedAtMs, LOOKUP_TARGET_MS, clock);
    return result;
  };
  const tokenHash = hashInviteToken(rawToken);
  const dependencyDeadlineAtMs = startedAtMs + LOOKUP_DEPENDENCY_DEADLINE_MS;
  let invite = null;
  if (remainingDeadlineMs(dependencyDeadlineAtMs, clock) > 0) {
    try {
      invite = await withinDeadline(() => prisma.$transaction(
        (tx) => tx.invite.findUnique({
          where: { tokenHash },
          select: {
            id: true, tokenHash: true, normalizedEmail: true, status: true, expiresAt: true,
          },
        }),
        { maxWait: 20, timeout: 50 },
      ), dependencyDeadlineAtMs, clock);
    } catch {
      invite = null;
    }
  }

  const hashMatches = constantTimeHashMatches(tokenHash, invite?.tokenHash ?? null);
  const normalizedExpectedEmail =
    expectedEmail === null ? null : normalizeInviteEmail(expectedEmail);
  const emailMatches =
    normalizedExpectedEmail === null ||
    invite?.normalizedEmail === null ||
    invite?.normalizedEmail === normalizedExpectedEmail;

  if (
    !invite ||
    !hashMatches ||
    invite.status !== "ISSUED" ||
    invite.expiresAt <= new Date() ||
    !emailMatches
  ) {
    return finish(GENERIC_LOOKUP_FAILURE);
  }

  return finish({
    ok: true,
    invite: {
      id: invite.id,
      tokenHash: toBuffer(invite.tokenHash),
      normalizedEmail: invite.normalizedEmail,
      expiresAt: invite.expiresAt,
    },
  });
}
