/**
 * Password reset token consumption
 *
 * Validates a reset token, hashes the new password, and atomically
 * updates the user's password while deleting all reset tokens for that email.
 *
 * @module auth/server/reset/consumeResetToken
 */

import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";

/**
 * Consumes a password reset token and updates the user's password
 *
 * Validation order matters for security:
 * 1. Token exists → fast indexed lookup
 * 2. Token expired → cheap date comparison
 * 3. User exists → prevents timing-based email enumeration
 * 4. Hash password → expensive operation, only if all checks pass
 *
 * @param token - The reset token from the URL
 * @param newPassword - The user's new password (plain text)
 * @returns Discriminated union result
 */
export async function consumePasswordResetToken(token: string, newPassword: string) {
  // Find token in database
  const record = await prisma.passwordResetToken.findUnique({ where: { token } });
  if (!record) return { ok: false as const, reason: "not-found" as const };
  if (record.expires < new Date()) return { ok: false as const, reason: "expired" as const };

  // Find user by email
  const user = await prisma.user.findUnique({
    where: { email: record.identifier },
    select: { id: true },
  });
  if (!user) return { ok: false as const, reason: "not-found" as const };

  // Hash new password (bcrypt, 10 salt rounds — same as signup)
  const hash = await bcrypt.hash(newPassword, 10);

  // Atomic: update password + delete ALL tokens + invalidate all sessions
  await prisma.$transaction([
    prisma.user.update({
      where: { id: user.id },
      data: { passwordHash: hash, lastStrongAuthAt: null, sessionVersion: { increment: 1 } },
    }),
    prisma.passwordResetToken.deleteMany({ where: { identifier: record.identifier } }),
    prisma.session.deleteMany({ where: { userId: user.id } }),
  ]);

  return { ok: true as const };
}
