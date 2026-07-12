import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { buildRegistrationCsp } from "@/features/auth/server/registration/registrationSecurity";

const REGISTRATION_CSRF_COOKIE = "registration_csrf";

export function middleware(req: NextRequest) {
  const nonce = crypto.randomUUID();
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("x-nonce", nonce);
  const csrfToken = req.cookies.get(REGISTRATION_CSRF_COOKIE)?.value ?? crypto.randomUUID();
  requestHeaders.set("x-registration-csrf", csrfToken);
  const isDev = process.env.NODE_ENV !== "production";
  const profile = req.nextUrl.pathname === "/invite" || req.nextUrl.pathname.startsWith("/api/invitations/exchange")
    ? "invite"
    : req.nextUrl.pathname === "/register"
      ? "register"
      : null;

  // Baseline security headers for auth endpoints and public pages
  const contentSecurityPolicy = profile
    ? buildRegistrationCsp(profile, nonce)
    : [
      "default-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "img-src 'self' data: https:",
      isDev ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'" : "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      isDev ? "connect-src 'self' https: ws:" : "connect-src 'self' https:",
      "font-src 'self' data:",
    ].join("; ");
  requestHeaders.set("Content-Security-Policy", contentSecurityPolicy);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", contentSecurityPolicy);
  response.headers.set("Referrer-Policy", profile ? "no-referrer" : "strict-origin-when-cross-origin");
  if (profile) response.headers.set("Cache-Control", "no-store");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  if (!req.cookies.has(REGISTRATION_CSRF_COOKIE)) {
    response.cookies.set(REGISTRATION_CSRF_COOKIE, csrfToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: 600,
    });
  }

  // Only set HSTS in production (HTTPS required)
  if (process.env.NODE_ENV === "production" && req.nextUrl.protocol === "https:") {
    response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  }

  return response;
}

// (optional) Only run on real app paths, not Next internals
export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
