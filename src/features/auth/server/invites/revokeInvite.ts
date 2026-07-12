// src/features/auth/server/invites/revokeInvite.ts
// Idempotently revokes issued invites without reopening terminal states.
import { prisma } from "@/lib/prisma";
import type {
  InviteRevocationTransactionClient,
  RevokeInviteInTxResult,
  RevokeInviteInput,
  RevokeInviteResult,
} from "./invite.types";

export async function revokeInviteInTx(
  tx: InviteRevocationTransactionClient,
  input: RevokeInviteInput,
  now = new Date(),
): Promise<RevokeInviteInTxResult> {
  const result = await tx.invite.updateMany({
    where: {
      id: input.inviteId,
      status: "ISSUED",
      expiresAt: { gt: now },
    },
    data: {
      status: "REVOKED",
      revokedAt: now,
    },
  });

  return { ok: true, revoked: result.count === 1 };
}

export async function revokeInvite(input: RevokeInviteInput): Promise<RevokeInviteResult> {
  await revokeInviteInTx(prisma, input);
  return { ok: true };
}
