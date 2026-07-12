// Plans the Auth.js JWT cookie that replaces the invalidated linking session.
import { encode } from "next-auth/jwt";
import { env } from "@/lib/env";

const SESSION_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;
const SESSION_COOKIE_SALT = "";

interface LinkSession {
  user: {
    id: string;
    email?: string | null;
    name?: string | null;
    role?: "USER" | "ADMIN";
    sessionVersion: number;
  };
  authProvider?: string;
  lastAuthAt?: number;
}

interface LinkSessionRotation {
  token: string;
  cookieHeader: string;
}

function secureSessionCookie(): boolean {
  const base = env.APP_URL ?? env.AUTH_URL ?? env.NEXTAUTH_URL;
  return base ? new URL(base).protocol === "https:" : process.env.NODE_ENV === "production";
}

export async function planLinkSessionRotation(session: LinkSession): Promise<LinkSessionRotation> {
  const secure = secureSessionCookie();
  const cookieName = `${secure ? "__Secure-" : ""}next-auth.session-token`;
  const token = await encode({
    token: {
      sub: session.user.id,
      uid: session.user.id,
      email: session.user.email ?? undefined,
      name: session.user.name ?? undefined,
      role: session.user.role ?? "USER",
      sessionVersion: session.user.sessionVersion + 1,
      lastAuthAt: session.lastAuthAt,
      authProvider: session.authProvider,
      authRejected: false,
    },
    secret: env.NEXTAUTH_SECRET,
    salt: SESSION_COOKIE_SALT,
    maxAge: SESSION_MAX_AGE_SECONDS,
  });
  const attributes = [
    `${cookieName}=${encodeURIComponent(token)}`,
    "Path=/",
    `Max-Age=${SESSION_MAX_AGE_SECONDS}`,
    "HttpOnly",
    "SameSite=Lax",
    ...(secure ? ["Secure"] : []),
  ];
  return { token, cookieHeader: attributes.join("; ") };
}
