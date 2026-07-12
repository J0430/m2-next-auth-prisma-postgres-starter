// Verifies the Packet 02 admin MFA and elevation security contract.
import { beforeEach, describe, expect, it, vi } from "vitest";

const tx = {
  user: { findUnique: vi.fn(), update: vi.fn() },
  adminMfaFactor: { findFirst: vi.fn(), findUnique: vi.fn(), create: vi.fn(), update: vi.fn(), updateMany: vi.fn() },
  adminCapabilityGrant: { findFirst: vi.fn(), createMany: vi.fn() },
  auditEvent: { create: vi.fn() },
};
const durableTx = { auditEvent: { create: vi.fn() } };

vi.mock("@/lib/prisma", () => ({ prisma: { $transaction: vi.fn((run) => run(durableTx)) } }));
vi.mock("@/lib/env", () => ({
  env: {
    ADMIN_ELEVATION_MAX_AGE_SECONDS: 300,
    ADMIN_MFA_SECRET_ENCRYPTION_KEYS: {
      "1": "11".repeat(32),
      "2": "22".repeat(32),
    },
    ADMIN_MFA_SECRET_KEY_VERSION: "2",
  },
}));

import { decryptTotpSecret, encryptTotpSecret, validateStoredAdminMfaKeyVersions } from "@/features/auth/server/adminMfa/secretCrypto";
import { totp } from "@/features/auth/server/adminMfa/totp";
import { enrollAdminMfaFactor, verifyAdminMfaFactor } from "@/features/auth/server/adminMfa/adminMfaService";
import { authorizeAdminElevationForDomainMutation, requireAdminElevation } from "@/features/auth/server/adminElevation/requireAdminElevation";

describe("admin MFA elevation", () => {
  beforeEach(() => vi.clearAllMocks());

  it("decrypts by the row key version after write-key rotation", () => {
    const encrypted = encryptTotpSecret("JBSWY3DPEHPK3PXP");
    expect(encrypted.keyVersion).toBe(2);
    expect(decryptTotpSecret(encrypted.cipher, encrypted.keyVersion)).toBe("JBSWY3DPEHPK3PXP");
    expect(() => decryptTotpSecret(encrypted.cipher, 1)).toThrow("ADMIN_MFA_SECRET_DECRYPT_FAILED");
  });

  it("activates PENDING only after a real TOTP assertion and advances freshness", async () => {
    const now = new Date("2026-07-12T12:00:00.000Z");
    const secret = "JBSWY3DPEHPK3PXP";
    const encrypted = encryptTotpSecret(secret);
    tx.adminMfaFactor.findUnique.mockResolvedValue({
      id: "factor-1", userId: "admin-1", status: "PENDING",
      secretCipher: encrypted.cipher, keyVersion: encrypted.keyVersion, lastUsedStep: null,
    });
    tx.adminMfaFactor.updateMany.mockResolvedValue({ count: 1 });
    await verifyAdminMfaFactor({ tx, actorId: "admin-1", factorId: "factor-1", code: totp(secret, now.getTime()), auditAction: "admin.mfa.verify", now });
    expect(tx.adminMfaFactor.updateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: "ACTIVE", activatedAt: now, lastUsedAt: now }),
    }));
    expect(tx.user.update).toHaveBeenCalledWith({ where: { id: "admin-1" }, data: { lastStrongAuthAt: now, mfaEnrolledAt: now } });
    expect(tx.auditEvent.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ action: "admin.mfa.verify" }),
    }));
  });

  it("rejects replay of an already-used TOTP time step", async () => {
    const now = new Date("2026-07-12T12:00:00.000Z");
    const secret = "JBSWY3DPEHPK3PXP";
    const encrypted = encryptTotpSecret(secret);
    tx.adminMfaFactor.findUnique.mockResolvedValue({ id: "factor-1", userId: "admin-1", status: "ACTIVE", secretCipher: encrypted.cipher, keyVersion: encrypted.keyVersion, lastUsedStep: BigInt(Math.floor(now.getTime() / 30_000)) });
    tx.adminMfaFactor.updateMany.mockResolvedValue({ count: 0 });
    await expect(verifyAdminMfaFactor({ tx, actorId: "admin-1", factorId: "factor-1", code: totp(secret, now.getTime()), auditAction: "admin.elevation.refresh", now })).rejects.toThrow("ADMIN_MFA_FORBIDDEN");
    expect(tx.user.update).not.toHaveBeenCalled();
  });

  it("replacement enrollment invalidates elevation and current sessions with one domain success audit", async () => {
    const now = new Date("2026-07-12T12:00:00.000Z");
    tx.adminMfaFactor.findFirst.mockResolvedValue({ id: "active-factor" });
    tx.adminMfaFactor.updateMany.mockResolvedValue({ count: 1 });
    tx.adminMfaFactor.create.mockResolvedValue({ id: "replacement-factor" });

    await enrollAdminMfaFactor({ tx, actorId: "admin-1", accountName: "admin@example.test", issuer: "Example", now });

    expect(tx.user.update).toHaveBeenCalledWith({
      where: { id: "admin-1" },
      data: { lastStrongAuthAt: null, sessionVersion: { increment: 1 } },
    });
    expect(tx.auditEvent.create).toHaveBeenCalledTimes(1);
    expect(tx.auditEvent.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ action: "admin.mfa.enroll" }),
    }));
  });

  it("requires current session, explicit capability, ACTIVE factor, and <=300s freshness", async () => {
    const now = new Date("2026-07-12T12:00:00.000Z");
    tx.user.findUnique.mockResolvedValue({ role: "ADMIN", sessionVersion: 4, status: "ACTIVE", lastStrongAuthAt: new Date(now.getTime() - 299_000) });
    tx.adminMfaFactor.findFirst.mockResolvedValue({ id: "factor-1" });
    tx.adminCapabilityGrant.findFirst.mockResolvedValue({ id: "grant-1" });
    const grant = await requireAdminElevation({ session: { userId: "admin-1", role: "ADMIN", sessionVersion: 4 }, tx }, "admin:user:create", now);
    expect(grant).toEqual({ actorId: "admin-1", capability: "admin:user:create", grantedAt: now });
    expect(tx.auditEvent.create).toHaveBeenCalledTimes(1);
  });

  it("denies stale freshness generically and persists denial in a separate transaction", async () => {
    const now = new Date("2026-07-12T12:00:00.000Z");
    tx.user.findUnique.mockResolvedValue({ role: "ADMIN", sessionVersion: 4, status: "ACTIVE", lastStrongAuthAt: new Date(now.getTime() - 301_000) });
    tx.adminMfaFactor.findFirst.mockResolvedValue({ id: "factor-1" });
    tx.adminCapabilityGrant.findFirst.mockResolvedValue({ id: "grant-1" });
    await expect(requireAdminElevation({ session: { userId: "admin-1", role: "ADMIN", sessionVersion: 4 }, tx }, "admin:user:create", now)).rejects.toMatchObject({ name: "GenericForbiddenError" });
    expect(durableTx.auditEvent.create).toHaveBeenCalledTimes(1);
    expect(tx.auditEvent.create).not.toHaveBeenCalled();
  });

  it("denies an ADMIN role when no explicit active capability grant exists", async () => {
    const now = new Date("2026-07-12T12:00:00.000Z");
    tx.user.findUnique.mockResolvedValue({ role: "ADMIN", sessionVersion: 4, status: "ACTIVE", lastStrongAuthAt: now });
    tx.adminMfaFactor.findFirst.mockResolvedValue({ id: "factor-1" });
    tx.adminCapabilityGrant.findFirst.mockResolvedValue(null);
    await expect(requireAdminElevation({ session: { userId: "admin-1", role: "ADMIN", sessionVersion: 4 }, tx }, "admin:user:create", now)).rejects.toMatchObject({ name: "GenericForbiddenError" });
  });

  it("lets a domain mutation own the sole success audit and emits one named denial", async () => {
    const now = new Date("2026-07-12T12:00:00.000Z");
    tx.user.findUnique.mockResolvedValue({ role: "ADMIN", sessionVersion: 4, status: "ACTIVE", lastStrongAuthAt: now });
    tx.adminMfaFactor.findFirst.mockResolvedValue({ id: "factor-1" });
    tx.adminCapabilityGrant.findFirst.mockResolvedValue({ id: "grant-1" });
    const context = { session: { userId: "admin-1", role: "ADMIN" as const, sessionVersion: 4 }, tx };

    await authorizeAdminElevationForDomainMutation(context, "admin:mfa:manage", "admin.mfa.enroll.denied", now);
    expect(tx.auditEvent.create).not.toHaveBeenCalled();

    tx.adminCapabilityGrant.findFirst.mockResolvedValue(null);
    await expect(authorizeAdminElevationForDomainMutation(context, "admin:mfa:manage", "admin.mfa.enroll.denied", now))
      .rejects.toMatchObject({ name: "GenericForbiddenError" });
    expect(durableTx.auditEvent.create).toHaveBeenCalledTimes(1);
    expect(durableTx.auditEvent.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ action: "admin.mfa.enroll.denied" }),
    }));
  });

  it("denies a future strong-auth timestamp", async () => {
    const now = new Date("2026-07-12T12:00:00.000Z");
    tx.user.findUnique.mockResolvedValue({ role: "ADMIN", sessionVersion: 4, status: "ACTIVE", lastStrongAuthAt: new Date(now.getTime() + 1) });
    tx.adminMfaFactor.findFirst.mockResolvedValue({ id: "factor-1" });
    tx.adminCapabilityGrant.findFirst.mockResolvedValue({ id: "grant-1" });
    await expect(requireAdminElevation({ session: { userId: "admin-1", role: "ADMIN", sessionVersion: 4 }, tx }, "admin:user:create", now)).rejects.toMatchObject({ name: "GenericForbiddenError" });
  });

  it("fails readiness when a stored factor key version is absent", async () => {
    const reader = { adminMfaFactor: { findMany: vi.fn().mockResolvedValue([{ keyVersion: 3 }]) } };
    await expect(validateStoredAdminMfaKeyVersions(reader)).rejects.toThrow("ADMIN_MFA_SECRET_KEY_VERSION_UNKNOWN");
  });
});
