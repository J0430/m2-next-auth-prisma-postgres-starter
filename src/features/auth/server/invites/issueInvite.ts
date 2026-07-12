// src/features/auth/server/invites/issueInvite.ts
// Issues hash-only, email-bound invite records with one-time raw tokens.
import { prisma } from "@/lib/prisma";
import { generateInviteToken, hashInviteToken, normalizeInviteEmail } from "./token";
import type {
  CreateInviteInput,
  CreateInviteResult,
  InviteIssuanceTransactionClient,
} from "./invite.types";

const DEFAULT_INVITE_TTL_DAYS = 7;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

export async function createInviteInTx(
  tx: InviteIssuanceTransactionClient,
  input: CreateInviteInput,
): Promise<CreateInviteResult> {
  const rawToken = generateInviteToken();
  const normalizedEmail = input.email === null ? null : normalizeInviteEmail(input.email);
  const expiresAt = new Date(Date.now() + DEFAULT_INVITE_TTL_DAYS * MS_PER_DAY);

  const invite = await tx.invite.create({
    data: {
      issuerUserId: input.issuerUserId,
      normalizedEmail,
      tokenHash: hashInviteToken(rawToken),
      expiresAt,
    },
    select: {
      id: true,
      normalizedEmail: true,
      expiresAt: true,
    },
  });

  return {
    inviteId: invite.id,
    rawToken,
    normalizedEmail: invite.normalizedEmail,
    expiresAt: invite.expiresAt,
  };
}

export async function createInvite(input: CreateInviteInput): Promise<CreateInviteResult> {
  return createInviteInTx(prisma, input);
}
