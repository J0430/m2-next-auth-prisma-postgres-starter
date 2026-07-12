// Creates a NextAuth-compatible JWT session token for post-verification auto-login.
import { encode } from "next-auth/jwt";
import { env } from "@/lib/env";

export interface SessionUser {
  id: string;
  email: string;
  name: string | null;
  role: "USER" | "ADMIN";
  status: "ACTIVE" | "INACTIVE" | "SUSPENDED" | "DELETED";
  sessionVersion: number;
}

/**
 * Builds a JWT token matching the structure produced by the jwt callback in options.ts.
 * Used after OTP verification to create a session without credentials sign-in.
 */
export async function createSessionToken(user: SessionUser): Promise<string> {
  if (user.status !== "ACTIVE") {
    throw new Error("SESSION_USER_NOT_ACTIVE");
  }

  const role = user.role === "ADMIN" ? "ADMIN" : "USER";
  const token = await encode({
    token: {
      sub: user.id,
      uid: user.id,
      email: user.email,
      name: user.name,
      role,
      sessionVersion: user.sessionVersion,
      lastAuthAt: Date.now(),
      authProvider: "credentials",
    },
    secret: env.NEXTAUTH_SECRET,
  });
  return token;
}

/**
 * Returns the session cookie name per environment.
 * Production uses __Secure- prefix (HTTPS-only).
 */
export function getSessionCookieName(): string {
  return process.env.NODE_ENV === "production"
    ? "__Secure-next-auth.session-token"
    : "next-auth.session-token";
}
