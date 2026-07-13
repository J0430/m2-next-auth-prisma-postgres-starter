// Non-redeeming fragment exchange endpoint for opaque registration sessions.
import { z } from "zod";

import { validateCsrf } from "@/features/auth/server/admission";
import {
  createOpaqueRegistrationHandle,
  exchangeInviteToken,
} from "@/features/auth/server/registration/exchangeInviteToken";
import { applyRegistrationSecurityHeaders } from "@/features/auth/server/registration/registrationSecurity";
import { REGISTRATION_SESSION_COOKIE_NAME } from "@/features/auth/server/registration/registerWithInvite";
import { env } from "@/lib/env";
import { getClientIp } from "@/lib/rateLimit";

const ExchangeSchema = z.object({
  token: z.string().min(1).max(256),
  csrfToken: z.string().min(1).max(128),
});

function expectedOrigin(): string {
  const configured = env.AUTH_URL ?? env.NEXTAUTH_URL ?? env.APP_URL;
  if (!configured) return "";
  try {
    return new URL(configured).origin;
  } catch {
    return "";
  }
}

function genericResponse(handle: string, nonce: string): Response {
  const headers = new Headers({
    Location: "/register",
    "Set-Cookie": `${REGISTRATION_SESSION_COOKIE_NAME}=${handle}; HttpOnly; Secure; SameSite=Strict; Path=/register; Max-Age=600`,
  });
  applyRegistrationSecurityHeaders(headers, "invite", nonce);
  return new Response(null, { status: 303, headers });
}

export async function POST(request: Request): Promise<Response> {
  const nonce = request.headers.get("x-nonce") ?? crypto.randomUUID();
  let payload: unknown = null;
  try {
    payload = await request.json();
  } catch {
    payload = null;
  }
  const parsed = ExchangeSchema.safeParse(payload);
  const csrf = validateCsrf({
    headers: request.headers,
    expectedOrigin: expectedOrigin(),
    sessionToken: request.headers.get("x-registration-csrf"),
    submittedToken: parsed.success ? parsed.data.csrfToken : null,
  });
  if (!parsed.success || !csrf.ok) {
    return genericResponse(createOpaqueRegistrationHandle(), nonce);
  }
  const result = await exchangeInviteToken({
    rawToken: parsed.data.token,
    ip: getClientIp(request.headers),
  });
  return genericResponse(result.handle, nonce);
}
