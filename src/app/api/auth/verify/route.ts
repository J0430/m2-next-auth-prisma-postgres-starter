// API endpoint for verifying 6-digit email OTP codes.
import { NextResponse } from "next/server";
import { consumeVerificationToken } from "@/features/auth/server/verify/consumeToken";
import { createSessionToken, getSessionCookieName } from "@/features/auth/server/createSessionToken";
import { prisma } from "@/lib/prisma";
import { otpVerifySchema } from "@/lib/validation/verify";
import { buildAdmissionRateLimitChecks, getClientIp, rateLimit } from "@/lib/rateLimit";
import { monotonicNow, padAdmissionTiming } from "@/features/auth/server/admission";

const OTP_DENIAL_STATUS = 400;

async function rejectWithParity(startedAtMs: number): Promise<NextResponse> {
  await padAdmissionTiming(startedAtMs);
  return NextResponse.json(
    { ok: false, reason: "verification-failed" },
    { status: OTP_DENIAL_STATUS },
  );
}

export async function POST(req: Request) {
  const startedAtMs = monotonicNow();
  const body = await req.json().catch(() => ({}));
  const parsed = otpVerifySchema.safeParse(body);

  if (!parsed.success) {
    return rejectWithParity(startedAtMs);
  }

  const ip = getClientIp(req.headers);
  const checks = buildAdmissionRateLimitChecks({
    surface: "otp-verify",
    ip,
    accountIdentifier: parsed.data.email,
  });
  for (const check of checks) {
    const limitResult = await rateLimit(check.key, check.policy);
    if (!limitResult.success) {
      return NextResponse.json({ ok: false, reason: "rate-limited" }, { status: 429 });
    }
  }

  const result = await consumeVerificationToken(
    parsed.data.email,
    parsed.data.code,
    parsed.data.password
  );

  if (!result.ok) {
    return rejectWithParity(startedAtMs);
  }

  const normalizedEmail = parsed.data.email.toLowerCase().trim();
  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
    select: { id: true, email: true, name: true, role: true, status: true, sessionVersion: true },
  });

  if (!user || user.status !== "ACTIVE") {
    return rejectWithParity(startedAtMs);
  }

  const sessionToken = await createSessionToken(user);
  const response = NextResponse.json({ ok: true });
  response.cookies.set(getSessionCookieName(), sessionToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 30 * 24 * 60 * 60, // 30 days
  });
  return response;
}
