// Runs bounded RegistrationSession cleanup on the existing outbox worker cadence.
import { prisma } from "@/lib/prisma";

export const REGISTRATION_SESSION_MAX_AGE_SECONDS = 600;
export const REGISTRATION_SESSION_CLEANUP_CADENCE_SECONDS = 60;
export const REGISTRATION_SESSION_CONSUMED_GRACE_SECONDS = 60;
export const REGISTRATION_SESSION_CLEANUP_SLO_SECONDS =
  REGISTRATION_SESSION_MAX_AGE_SECONDS + REGISTRATION_SESSION_CLEANUP_CADENCE_SECONDS;
export const REGISTRATION_SESSION_CLEANUP_BATCH_SIZE = 100;
export const REGISTRATION_SESSION_CLEANUP_MAX_BATCHES = 3;

export type RegistrationSessionCleanupArgs = {
  now: Date;
  consumedBefore: Date;
  limit: number;
};

export type RegistrationSessionCleanupDeps = {
  deleteEligibleRegistrationSessions(args: RegistrationSessionCleanupArgs): Promise<number>;
  now(): Date;
};

const DEFAULT_CLEANUP_DEPS: RegistrationSessionCleanupDeps = {
  now: () => new Date(),
  deleteEligibleRegistrationSessions: async ({ now, consumedBefore, limit }) => {
    const deleted = await prisma.$queryRaw<Array<{ id: string }>>`
      DELETE FROM "public"."registration_sessions"
      WHERE "id" IN (
        SELECT "id" FROM "public"."registration_sessions"
        WHERE "expiresAt" < (${now} AT TIME ZONE 'UTC')
           OR ("status" = 'CONSUMED' AND "consumedAt" < (${consumedBefore} AT TIME ZONE 'UTC'))
        ORDER BY "expiresAt" ASC, "id" ASC
        FOR UPDATE SKIP LOCKED
        LIMIT ${limit}
      )
      RETURNING "id"
    `;
    return deleted.length;
  },
};

export async function runRegistrationSessionCleanup(
  deps: RegistrationSessionCleanupDeps = DEFAULT_CLEANUP_DEPS,
): Promise<number> {
  const now = deps.now();
  const consumedBefore = new Date(
    now.getTime() - REGISTRATION_SESSION_CONSUMED_GRACE_SECONDS * 1000,
  );
  let deletedTotal = 0;
  for (let batch = 0; batch < REGISTRATION_SESSION_CLEANUP_MAX_BATCHES; batch += 1) {
    const deleted = await deps.deleteEligibleRegistrationSessions({
      now, consumedBefore, limit: REGISTRATION_SESSION_CLEANUP_BATCH_SIZE,
    });
    deletedTotal += deleted;
    if (deleted < REGISTRATION_SESSION_CLEANUP_BATCH_SIZE) return deletedTotal;
    console.warn("REGISTRATION_SESSION_CLEANUP_BATCH_FULL");
  }
  return deletedTotal;
}
