// Prisma adapter and SQL for claiming due transactional outbox rows.
import { prisma } from "@/lib/prisma";
import type {
  ClaimableOutboxEmailRow,
  OutboxDb,
  OutboxTransactionClient,
  OutboxUpdateManyArgs,
  OutboxUpdateResult,
  RecipientUser,
  InviteRecipient,
} from "./types";

export const CLAIM_DUE_OUTBOX_EMAIL_SQL = `
SELECT
  "id",
  "eventType",
  "aggregateId",
  "recipientUserId",
  "attempts",
  "inviteCiphertext",
  "keyVersion"
FROM "public"."outbox_emails"
WHERE "id" = $1
  AND "status" IN ('PENDING', 'CLAIMED')
  AND "availableAt" <= $2
  AND ("nextAttemptAt" IS NULL OR "nextAttemptAt" <= $2)
  AND ("leaseExpiresAt" IS NULL OR "leaseExpiresAt" <= $3)
ORDER BY "createdAt" ASC
FOR UPDATE SKIP LOCKED
LIMIT 1
`;

type PrismaOutboxClient = {
  $queryRawUnsafe<T = unknown>(query: string, ...values: unknown[]): Promise<T>;
  outboxEmail: {
    updateMany(args: OutboxUpdateManyArgs): Promise<OutboxUpdateResult>;
  };
  user: {
    findUnique(args: {
      where: { id: string };
      select: { id: true; email: true; name: true; status: true };
    }): Promise<RecipientUser | null>;
  };
  invite: {
    findUnique(args: {
      where: { id: string };
      select: { id: true; normalizedEmail: true; status: true; expiresAt: true };
    }): Promise<InviteRecipient | null>;
  };
};

function createPrismaTransactionClient(tx: PrismaOutboxClient): OutboxTransactionClient {
  return {
    queryClaimableOutboxEmails: (id, now) =>
      tx.$queryRawUnsafe<ClaimableOutboxEmailRow[]>(CLAIM_DUE_OUTBOX_EMAIL_SQL, id, now, now),
    updateOutboxEmailMany: (args) => tx.outboxEmail.updateMany(args),
    findRecipientUser: (id) =>
      tx.user.findUnique({
        where: { id },
        select: { id: true, email: true, name: true, status: true },
      }),
    findInviteRecipient: (id) => tx.invite.findUnique({
      where: { id },
      select: { id: true, normalizedEmail: true, status: true, expiresAt: true },
    }),
  };
}

export function createPrismaOutboxDb(): OutboxDb {
  const baseClient = createPrismaTransactionClient(prisma);
  return {
    ...baseClient,
    $transaction: (callback) =>
      prisma.$transaction((tx) => callback(createPrismaTransactionClient(tx))),
  };
}
