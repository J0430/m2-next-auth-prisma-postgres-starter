// HTTP boundary helpers for CSRF issuance and authenticated link initiation.
import crypto from "node:crypto";
import { getServerSession } from "next-auth";
import { cookies } from "next/headers";
import { authOptions } from "@/features/auth/server/options";
import { env } from "@/lib/env";
import { buildRateLimitKey, getClientIp, rateLimit } from "@/lib/rateLimit";
import { recordLinkDenied } from "./audit";
import { LINK_CSRF_COOKIE, LinkStartBodySchema } from "./linking.types";
import { startAccountLinkFlow } from "./startLinkFlow";

const RESPONSE_HEADERS = { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } as const;
const failure = () => Response.json({ error: "Account link failed" }, { status: 400, headers: RESPONSE_HEADERS });
const staleReauthFailure = () => Response.json(
  { error: "Account link failed", reason: "reauth_stale" },
  { status: 400, headers: RESPONSE_HEADERS },
);

function sameToken(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && crypto.timingSafeEqual(leftBytes, rightBytes);
}

export async function issueLinkCsrf(): Promise<Response> {
  const session = await getServerSession(authOptions);
  if (!session?.user.id) return failure();
  const token = crypto.randomBytes(32).toString("base64url");
  const base = env.APP_URL ?? env.AUTH_URL ?? env.NEXTAUTH_URL;
  if (!base) return failure();
  const secure = new URL(base).protocol === "https:" ? "; Secure" : "";
  return Response.json({ csrfToken: token }, { headers: {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Set-Cookie": `${LINK_CSRF_COOKIE}=${token}; Path=/api/account/link; Max-Age=300; HttpOnly${secure}; SameSite=Strict`,
  } });
}

export async function startLink(request: Request): Promise<Response> {
  const session = await getServerSession(authOptions);
  const parsed = LinkStartBodySchema.safeParse(await request.json().catch(() => null));
  const actorId = session?.user.id ?? null;
  if (!session?.user.id) {
    await recordLinkDenied(parsed.success ? parsed.data.provider : "unknown", "authentication_required", null);
    return failure();
  }
  if (!parsed.success) {
    await recordLinkDenied("unknown", "malformed_request", actorId);
    return failure();
  }
  const cookie = (await cookies()).get(LINK_CSRF_COOKIE)?.value;
  const base = env.APP_URL ?? env.AUTH_URL ?? env.NEXTAUTH_URL;
  if (!cookie || !sameToken(cookie, parsed.data.csrfToken)) {
    await recordLinkDenied(parsed.data.provider, "csrf_failed", actorId);
    return failure();
  }
  if (!base || request.headers.get("origin") !== new URL(base).origin) {
    await recordLinkDenied(parsed.data.provider, "origin_failed", actorId);
    return failure();
  }
  const limitKey = buildRateLimitKey({ scope: "account-link-start", ip: getClientIp(request.headers), email: actorId });
  if (!(await rateLimit(limitKey, "auth-sensitive")).success) {
    await recordLinkDenied(parsed.data.provider, "rate_limited", actorId);
    return failure();
  }
  const result = await startAccountLinkFlow({
    userId: session.user.id, provider: parsed.data.provider,
    currentPassword: parsed.data.currentPassword,
    lastAuthAtMs: typeof session.lastAuthAt === "number" ? session.lastAuthAt : null,
    currentAuthProvider: session.authProvider ?? null,
    sessionVersion: session.user.sessionVersion,
  }).catch(() => ({ ok: false as const, reason: "intent_persistence_failed" as const }));
  if (result.ok) return Response.json({ authorizationUrl: result.authorizationUrl }, { headers: RESPONSE_HEADERS });
  return result.reason === "reauth_stale" ? staleReauthFailure() : failure();
}
