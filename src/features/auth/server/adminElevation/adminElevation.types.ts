// Shared types for the admin MFA elevation contract consumed by TASK-024 / TASK-026.
import type { Prisma } from "@prisma/client";

// Least-privilege capabilities gated by admin MFA elevation. Role alone never suffices.
export type AdminCapability =
  | "admin:invite:issue"
  | "admin:invite:revoke"
  | "admin:user:create"
  | "admin:mfa:manage";

// Resolved admin session claim (server-trusted role/version are re-checked against the DB).
export type AdminSession = {
  userId: string;
  role: "USER" | "ADMIN";
  sessionVersion: number;
};

// Minimal interactive-transaction surface the guard/services touch. A real
// Prisma.TransactionClient is structurally assignable to this Pick.
export type AdminElevationTx = {
  user: Pick<Prisma.TransactionClient["user"], "findUnique" | "update">;
  adminMfaFactor: Pick<
    Prisma.TransactionClient["adminMfaFactor"],
    "findFirst" | "findUnique" | "create" | "update" | "updateMany"
  >;
  adminCapabilityGrant: Pick<Prisma.TransactionClient["adminCapabilityGrant"], "findFirst" | "createMany">;
  auditEvent: Pick<Prisma.TransactionClient["auditEvent"], "create">;
};

// Context handed to requireAdminElevation from INSIDE the caller's mutation transaction.
export type AdminElevationContext = {
  session: AdminSession | null;
  tx: AdminElevationTx;
};

// Grant returned only when every precondition + freshness holds.
export type ElevationGrant = {
  actorId: string;
  capability: AdminCapability;
  grantedAt: Date;
};
