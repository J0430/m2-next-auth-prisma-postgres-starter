// src/features/auth/server/invites/invite.types.ts
// Shared types for the Packet 02 invite lifecycle service.
export interface CreateInviteInput {
  issuerUserId: string;
  email: string | null;
}

export interface CreateInviteResult {
  inviteId: string;
  rawToken: string;
  normalizedEmail: string | null;
  expiresAt: Date;
}

export interface RevokeInviteInput {
  inviteId: string;
}

export interface RevokeInviteResult {
  ok: true;
}

export interface RevokeInviteInTxResult extends RevokeInviteResult {
  revoked: boolean;
}

export type InviteLookupResult =
  | {
      ok: true;
      invite: {
        id: string;
        tokenHash: Buffer;
        normalizedEmail: string | null;
        expiresAt: Date;
      };
    }
  | {
      ok: false;
      status: 403;
      body: { ok: false; message: "Unable to complete this request." };
    };

export type ResolvedInvite =
  | { tokenHash: Buffer }
  | { inviteId: string };

export interface RedeemedInviteRecord {
  id: string;
  tokenHash: Buffer | Uint8Array;
  normalizedEmail: string | null;
  status: "REDEEMED";
  expiresAt: Date;
  redeemedByUserId: string;
  redeemedAt: Date;
  revokedAt: Date | null;
}

export type RedeemInviteResult =
  | { ok: true; invite: RedeemedInviteRecord }
  | { ok: false };

export interface InviteIssuanceTransactionClient {
  invite: {
    create(args: {
      data: {
        issuerUserId: string;
        normalizedEmail: string | null;
        tokenHash: Buffer;
        expiresAt: Date;
      };
      select: { id: true; normalizedEmail: true; expiresAt: true };
    }): Promise<{ id: string; normalizedEmail: string | null; expiresAt: Date }>;
  };
}

export interface InviteRevocationTransactionClient {
  invite: {
    updateMany(args: {
      where: {
        id: string;
        status: "ISSUED";
        expiresAt: { gt: Date };
      };
      data: {
        status: "REVOKED";
        revokedAt: Date;
      };
    }): Promise<{ count: number }>;
  };
}

export interface InviteTransactionClient {
  redeemerUserId: string;
  invite: {
    updateMany(args: {
      where: {
        id?: string;
        tokenHash?: Buffer;
        status: "ISSUED";
        expiresAt: { gt: Date };
        normalizedEmail: string | null;
      };
      data: {
        status: "REDEEMED";
        redeemedAt: Date;
        redeemedByUserId: string;
      };
    }): Promise<{ count: number }>;
    findFirst(args: {
      where: {
        id?: string;
        tokenHash?: Buffer;
        status?: "REDEEMED";
      };
      select: {
        id: true;
        tokenHash: true;
        normalizedEmail: true;
        status: true;
        expiresAt: true;
        redeemedByUserId: true;
        redeemedAt: true;
        revokedAt: true;
      };
    }): Promise<RedeemedInviteRecord | null>;
  };
}

export interface InviteReuseAlertPayload {
  inviteId: string;
  status: "REDEEMED";
  auditPersisted: boolean;
}

export type InviteReuseAlertHandler = (
  payload: InviteReuseAlertPayload,
) => void | Promise<void>;
