// Public service contracts for admin TOTP enrollment and assertions.
import type { AdminElevationTx } from "../adminElevation/adminElevation.types";

export type AdminMfaServiceInput = {
  tx: AdminElevationTx;
  actorId: string;
  now: Date;
};

export type VerifyAdminMfaInput = AdminMfaServiceInput & {
  factorId: string;
  code: string;
  auditAction: "admin.mfa.verify" | "admin.elevation.refresh";
};

export type EnrollAdminMfaInput = AdminMfaServiceInput & {
  accountName: string;
  issuer: string;
};
