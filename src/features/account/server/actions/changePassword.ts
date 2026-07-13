// Server action for changing user password
"use server";

import bcrypt from 'bcryptjs';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/features/auth/server/options';
import { prisma } from '@/lib/prisma';
import { ChangePasswordSchema } from '@/lib/validation/account';
import { buildRateLimitKey, getClientIp, rateLimit } from '@/lib/rateLimit';
import { headers } from 'next/headers';
import type { AccountActionResult } from './types';

export async function changePassword(formData: FormData): Promise<AccountActionResult> {
  // Session validation
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) return { ok: false, errors: { formErrors: ['Unauthorized'] } };

  // Rate limiting
  const ip = getClientIp(await headers());
  const key = buildRateLimitKey({ scope: 'change-password', ip, email: session.user.email });
  const limit = await rateLimit(key);
  if (!limit.success) return { ok: false, errors: { formErrors: ['Too many requests. Please try again later.'] } };

  // Parse and validate
  const raw = {
    currentPassword: formData.get('currentPassword')?.toString(),
    newPassword: formData.get('newPassword')?.toString(),
    confirmPassword: formData.get('confirmPassword')?.toString(),
  };
  const parsed = ChangePasswordSchema.safeParse(raw);
  if (!parsed.success) {
    const flat = parsed.error.flatten();
    return { ok: false, errors: { formErrors: flat.formErrors, fieldErrors: flat.fieldErrors } };
  }
  const data = parsed.data;

  // Fetch user and verify current password
  try {
    const user = await prisma.user.findUnique({ where: { id: session.user.id }, select: { passwordHash: true } });
    if (!user?.passwordHash) return { ok: false, errors: { formErrors: ['No password set for this account'] } };

    const valid = await bcrypt.compare(data.currentPassword, user.passwordHash);
    if (!valid) return { ok: false, errors: { fieldErrors: { currentPassword: ['Current password is incorrect'] } } };

    // Hash and update
    const hash = await bcrypt.hash(data.newPassword, 10);
    await prisma.$transaction([
      prisma.user.update({
        where: { id: session.user.id },
        data: { passwordHash: hash, lastStrongAuthAt: null, sessionVersion: { increment: 1 } },
      }),
      prisma.session.deleteMany({ where: { userId: session.user.id } }),
    ]);
    return { ok: true };
  } catch {
    return { ok: false, errors: { formErrors: ['Failed to change password'] } };
  }
}
