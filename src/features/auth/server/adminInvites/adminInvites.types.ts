// Public and dependency contracts for least-privilege admin invite operations.
import type { Prisma } from "@prisma/client";
import type { AdminCapability, AdminSession, ElevationGrant } from "../adminElevation/adminElevation.types";

export type AdminInviteMutationInput = {
  session: AdminSession | null;
  reason: string;
  requestId: string;
};

export type IssueAdminInviteInput = AdminInviteMutationInput & { email: string };
export type ExistingAdminInviteInput = AdminInviteMutationInput & { inviteId: string };

export type AdminInviteListItem = {
  id: string;
  maskedEmail: string | null;
  status: "ISSUED" | "REDEEMED" | "REVOKED" | "EXPIRED";
  expiresAt: Date;
  createdAt: Date;
};

export type AdminInviteService = {
  issue(input: IssueAdminInviteInput): Promise<{ ok: true; inviteId: string | null }>;
  revoke(input: ExistingAdminInviteInput): Promise<{ ok: true }>;
  resend(input: ExistingAdminInviteInput): Promise<{ ok: true; inviteId: string | null }>;
  list(session: AdminSession | null): Promise<AdminInviteListItem[]>;
};

export type AdminInviteTx = {
  invite: Pick<Prisma.TransactionClient["invite"], "findFirst" | "findMany" | "create" | "updateMany">;
  outboxEmail: Pick<Prisma.TransactionClient["outboxEmail"], "create">;
  auditEvent: Pick<Prisma.TransactionClient["auditEvent"], "create">;
  user: Pick<Prisma.TransactionClient["user"], "findUnique" | "update">;
  adminMfaFactor: Pick<Prisma.TransactionClient["adminMfaFactor"], "findFirst" | "findUnique" | "create" | "update" | "updateMany">;
  adminCapabilityGrant: Pick<Prisma.TransactionClient["adminCapabilityGrant"], "findFirst" | "createMany">;
};

export type AdminInviteServiceDeps = {
  transaction<T>(callback: (tx: AdminInviteTx) => Promise<T>): Promise<T>;
  authorize(context: { session: AdminSession | null; tx: AdminInviteTx }, capability: AdminCapability, denialAction: string, now?: Date): Promise<ElevationGrant>;
  encryptToken(rawToken: string, keyHex: string): Uint8Array;
  deliveryKey: { keyHex: string; version: number };
  now(): Date;
};
