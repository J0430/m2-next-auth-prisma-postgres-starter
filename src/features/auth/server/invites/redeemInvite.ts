// src/features/auth/server/invites/redeemInvite.ts
// Conditionally redeems server-resolved invite identities inside a transaction.
import type {
  InviteTransactionClient,
  RedeemInviteResult,
  ResolvedInvite,
} from "./invite.types";
import { normalizeInviteEmail } from "./token";

export class InviteRedemptionContext {
  readonly redeemerUserId: string;
  readonly invite: InviteTransactionClient["invite"];
  readonly #signalReuseDetected: (inviteId: string) => void;

  private constructor(client: InviteTransactionClient, signalReuseDetected: (inviteId: string) => void) {
    this.redeemerUserId = client.redeemerUserId;
    this.invite = client.invite;
    this.#signalReuseDetected = signalReuseDetected;
  }

  static create(
    client: InviteTransactionClient,
    signalReuseDetected: (inviteId: string) => void,
  ): InviteRedemptionContext {
    return new InviteRedemptionContext(client, signalReuseDetected);
  }

  signalReuseDetected(inviteId: string): void {
    return this.#signalReuseDetected(inviteId);
  }
}

export function createInviteRedemptionContext(
  client: InviteTransactionClient,
  signalReuseDetected: (inviteId: string) => void,
): InviteRedemptionContext {
  return InviteRedemptionContext.create(client, signalReuseDetected);
}

function buildResolvedWhere(
  resolvedInvite: ResolvedInvite,
): { id?: string; tokenHash?: Buffer } {
  if ("tokenHash" in resolvedInvite) {
    return { tokenHash: resolvedInvite.tokenHash };
  }

  return { id: resolvedInvite.inviteId };
}

async function findRedeemedInviteReuse(
  tx: InviteRedemptionContext,
  where: { id?: string; tokenHash?: Buffer },
): Promise<string | null> {
  const invite = await tx.invite.findFirst({
    where: {
      ...where,
      status: "REDEEMED",
    },
    select: {
      id: true,
      tokenHash: true,
      normalizedEmail: true,
      status: true,
      expiresAt: true,
      redeemedByUserId: true,
      redeemedAt: true,
      revokedAt: true,
    },
  });

  return invite?.id ?? null;
}

export async function redeemInviteInTx(
  tx: InviteRedemptionContext,
  resolvedInvite: ResolvedInvite,
  expectedNormalizedEmail: string | null,
): Promise<RedeemInviteResult> {
  const normalizedEmail = expectedNormalizedEmail === null
    ? null
    : normalizeInviteEmail(expectedNormalizedEmail);

  const now = new Date();
  const where = buildResolvedWhere(resolvedInvite);
  const redeemed = await tx.invite.updateMany({
    where: {
      ...where,
      status: "ISSUED",
      expiresAt: { gt: now },
      normalizedEmail,
    },
    data: {
      status: "REDEEMED",
      redeemedAt: now,
      redeemedByUserId: tx.redeemerUserId,
    },
  });

  if (redeemed.count !== 1) {
    const reuseInviteId = await findRedeemedInviteReuse(tx, where);
    if (reuseInviteId) {
      tx.signalReuseDetected(reuseInviteId);
    }
    return { ok: false };
  }

  const invite = await tx.invite.findFirst({
    where: {
      ...where,
      status: "REDEEMED",
    },
    select: {
      id: true,
      tokenHash: true,
      normalizedEmail: true,
      status: true,
      expiresAt: true,
      redeemedByUserId: true,
      redeemedAt: true,
      revokedAt: true,
    },
  });

  if (!invite || invite.status !== "REDEEMED" || !invite.redeemedAt) {
    throw new Error("INVITE_REDEMPTION_INVARIANT");
  }

  return { ok: true, invite };
}
