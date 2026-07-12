// Owns the PENDING -> verified ACTIVE lifecycle for encrypted admin TOTP factors.
import { decryptTotpSecret, encryptTotpSecret } from "./secretCrypto";
import { buildOtpauthUri, generateTotpSecret, matchingTotpStep } from "./totp";
import type { EnrollAdminMfaInput, VerifyAdminMfaInput } from "./adminMfa.types";

export async function enrollAdminMfaFactor(input: EnrollAdminMfaInput) {
  const active = await input.tx.adminMfaFactor.findFirst({
    where: { userId: input.actorId, status: "ACTIVE" },
    select: { id: true },
  });
  if (active) {
    await input.tx.user.update({
      where: { id: input.actorId },
      data: { lastStrongAuthAt: null, sessionVersion: { increment: 1 } },
    });
  }
  const secret = generateTotpSecret();
  const encrypted = encryptTotpSecret(secret);
  const factor = await input.tx.adminMfaFactor.create({
    data: {
      userId: input.actorId,
      kind: "TOTP",
      status: "PENDING",
      secretCipher: encrypted.cipher,
      keyVersion: encrypted.keyVersion,
    },
    select: { id: true },
  });
  await input.tx.auditEvent.create({
    data: { actorUserId: input.actorId, action: "admin.mfa.enroll", targetType: "AdminMfaFactor", targetId: factor.id, metadata: { outcome: "SUCCESS" } },
  });
  return {
    factorId: factor.id,
    provisioningUri: buildOtpauthUri({ secretBase32: secret, accountName: input.accountName, issuer: input.issuer }),
  };
}

export async function verifyAdminMfaFactor(input: VerifyAdminMfaInput): Promise<void> {
  const factor = await input.tx.adminMfaFactor.findUnique({
    where: { id: input.factorId },
    select: { id: true, userId: true, status: true, secretCipher: true, keyVersion: true, lastUsedStep: true },
  });
  if (!factor || factor.userId !== input.actorId || factor.status === "REVOKED") throw new Error("ADMIN_MFA_FORBIDDEN");
  const secret = decryptTotpSecret(factor.secretCipher, factor.keyVersion);
  const step = matchingTotpStep(input.code, secret, { atMs: input.now.getTime() });
  if (step === null) throw new Error("ADMIN_MFA_FORBIDDEN");
  const claimed = await input.tx.adminMfaFactor.updateMany({
    where: {
      id: factor.id,
      userId: input.actorId,
      status: factor.status,
      OR: [{ lastUsedStep: null }, { lastUsedStep: { lt: BigInt(step) } }],
    },
    data: { status: "ACTIVE", activatedAt: factor.status === "PENDING" ? input.now : undefined, lastUsedAt: input.now, lastUsedStep: BigInt(step) },
  });
  if (claimed.count !== 1) throw new Error("ADMIN_MFA_FORBIDDEN");
  if (factor.status === "PENDING") {
    await input.tx.adminMfaFactor.updateMany({
      where: { userId: input.actorId, id: { not: factor.id }, status: "ACTIVE" },
      data: { status: "REVOKED", revokedAt: input.now },
    });
  }
  await input.tx.user.update({ where: { id: input.actorId }, data: { lastStrongAuthAt: input.now, mfaEnrolledAt: input.now } });
  await input.tx.auditEvent.create({
    data: { actorUserId: input.actorId, action: input.auditAction, targetType: "AdminMfaFactor", targetId: factor.id, metadata: { outcome: "SUCCESS" } },
  });
}
