// Adapts the registration transaction to the invite redemption boundary.
import type { Prisma } from "@prisma/client";

import type {
  InviteTransactionClient,
  RedeemedInviteRecord,
} from "@/features/auth/server/invites/invite.types";
import {
  createInviteRedemptionContext,
  type InviteRedemptionContext,
} from "@/features/auth/server/invites/redeemInvite";

function toRedeemedInviteRecord(invite: {
  id: string;
  tokenHash: Uint8Array;
  normalizedEmail: string | null;
  status: string;
  expiresAt: Date;
  redeemedByUserId: string | null;
  redeemedAt: Date | null;
  revokedAt: Date | null;
} | null): RedeemedInviteRecord | null {
  if (!invite || invite.status !== "REDEEMED" || !invite.redeemedByUserId || !invite.redeemedAt) {
    return null;
  }

  return {
    ...invite,
    status: "REDEEMED",
    redeemedByUserId: invite.redeemedByUserId,
    redeemedAt: invite.redeemedAt,
  };
}

export function createInviteTransactionClient(
  tx: Prisma.TransactionClient,
  redeemerUserId: string,
  signalReuseDetected: (inviteId: string) => never,
): InviteRedemptionContext {
  const client: InviteTransactionClient = {
    redeemerUserId,
    invite: {
      updateMany: (args) => tx.invite.updateMany(args),
      findFirst: async (args) => toRedeemedInviteRecord(await tx.invite.findFirst(args)),
    },
  };
  return createInviteRedemptionContext(client, signalReuseDetected);
}
