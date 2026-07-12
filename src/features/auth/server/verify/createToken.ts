// Verification token creation utilities for 6-digit OTP email verification.
import crypto from "crypto";
import { prisma } from "@/lib/prisma";
import { env } from "@/lib/env";

// Token expiration time in minutes (default from env, expected 10)
const TTL_MIN = env.VERIFY_TOKEN_TTL_MINUTES;

// Generate 6-digit numeric code (000000-999999)
function generateOtpCode(): string {
  const num = crypto.randomInt(0, 1_000_000);
  return num.toString().padStart(6, "0");
}

// Hash the code for storage using HMAC-SHA256 keyed with OTP_HMAC_SECRET.
// Falls back to NEXTAUTH_SECRET in dev/test when OTP_HMAC_SECRET is absent.
// OTP_HMAC_SECRET is required in production via env validation (EnvSchemaProd).
export function hashOtpCode(code: string): string {
  const secret = env.OTP_HMAC_SECRET ?? env.NEXTAUTH_SECRET ?? "";
  return crypto.createHmac("sha256", secret).update(code, "utf8").digest("hex");
}

export async function createVerificationToken(email: string) {
  const identifier = email.toLowerCase().trim();
  const code = generateOtpCode();
  const token = hashOtpCode(code);
  const expires = new Date(Date.now() + TTL_MIN * 60 * 1000);

  await prisma.verificationToken.upsert({
    where: { identifier },
    create: { identifier, token, expires, attempts: 0 },
    update: { token, expires, attempts: 0 },
  });

  return { ok: true as const, code };
}
