/**
 * Server action: request password reset
 *
 * Validates email, rate-limits, generates reset token, and sends email.
 * Always returns success to prevent email enumeration attacks.
 *
 * @module auth/server/actions/requestPasswordReset
 */

"use server";

import { prisma } from "@/lib/prisma";
import { createGenericAdmissionFailure } from "@/features/auth/server/admission";
import { createPasswordResetToken } from "@/features/auth/server/reset/createResetToken";
import { sendPasswordResetEmail } from "@/features/auth/server/reset/sendResetEmail";
import { buildAdmissionRateLimitChecks, getClientIp, rateLimit } from "@/lib/rateLimit";
import { requestResetSchema } from "@/lib/validation/reset";
import { headers } from "next/headers";
import type { ActionResult } from "./types";

const genericAdmissionActionError = (): ActionResult => ({
  ok: false,
  errors: { formErrors: [createGenericAdmissionFailure().body.message] },
});

export async function requestPasswordReset(formData: FormData): Promise<ActionResult> {
  // 1. Validate input
  const parsed = requestResetSchema.safeParse({
    email: formData.get("email")?.toString(),
  });

  if (!parsed.success) {
    return { ok: false, errors: { formErrors: ["Invalid email address"] } };
  }

  const email = parsed.data.email.toLowerCase().trim();

  // 2. Rate limiting (prevents abuse)
  const ip = getClientIp(await headers());
  const checks = buildAdmissionRateLimitChecks({
    surface: "password-reset",
    ip,
    accountIdentifier: email,
  });
  for (const check of checks) {
    const limitResult = await rateLimit(check.key, check.policy);
    if (!limitResult.success) return genericAdmissionActionError();
  }

  // 3. Find user (always return success to prevent email enumeration)
  const user = await prisma.user.findUnique({
    where: { email },
    select: { name: true, password: true },
  });

  // SECURITY: No account or OAuth-only account → still return success
  if (!user || !user.password) {
    return { ok: true };
  }

  // 4. Create reset token + send email
  try {
    const { resetUrl, ttlMinutes } = await createPasswordResetToken(email);
    await sendPasswordResetEmail({
      to: email,
      resetUrl,
      name: user.name ?? undefined,
      ttlMinutes,
    });
  } catch {
    // Silent failure — don't reveal email status to client
    console.error("auth.password_reset_processing_failed", {
      code: "PASSWORD_RESET_PROCESSING_FAILED",
    });
  }

  return { ok: true };
}
