/**
 * Server action: reset password
 *
 * Validates token + new password, rate-limits by IP, consumes the reset token,
 * and updates the user's password atomically.
 *
 * @module auth/server/actions/resetPassword
 */

"use server";

import { headers } from "next/headers";
import { consumePasswordResetToken } from "@/features/auth/server/reset/consumeResetToken";
import { monotonicNow, padAdmissionTiming } from "@/features/auth/server/admission";
import { buildRateLimitKey, getClientIp, rateLimit } from "@/lib/rateLimit";
import { resetPasswordSchema } from "@/lib/validation/reset";
import type { ActionResult } from "./types";

const genericResetFailure = (): ActionResult => ({
  ok: false,
  errors: { formErrors: ["Unable to complete this request."] },
});

async function rejectWithParity(startedAtMs: number): Promise<ActionResult> {
  await padAdmissionTiming(startedAtMs);
  return genericResetFailure();
}

export async function resetPassword(formData: FormData): Promise<ActionResult> {
  const startedAtMs = monotonicNow();
  // 1. Validate input
  const parsed = resetPasswordSchema.safeParse({
    token: formData.get("token")?.toString(),
    password: formData.get("password")?.toString(),
    confirmPassword: formData.get("confirmPassword")?.toString(),
  });

  if (!parsed.success) {
    return rejectWithParity(startedAtMs);
  }

  const { token, password } = parsed.data;

  // 2. Rate limiting — prevents brute-force and CPU exhaustion via bcrypt
  const ip = getClientIp(await headers());
  const identifier = buildRateLimitKey({ scope: "password_reset_consume", ip });
  const limitResult = await rateLimit(identifier);

  if (!limitResult.success) {
    return rejectWithParity(startedAtMs);
  }

  // 3. Consume token + update password
  const result = await consumePasswordResetToken(token, password);

  if (!result.ok) {
    return rejectWithParity(startedAtMs);
  }

  return { ok: true };
}
