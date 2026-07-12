// Issues the shared double-submit CSRF token to a current ACTIVE administrator.
import { getServerSession } from "next-auth";
import { issueCsrfToken } from "@/features/auth/server/admission";
import { authOptions } from "@/features/auth/server/options";
import { env } from "@/lib/env";
import { prisma } from "@/lib/prisma";
import { genericForbiddenResponse } from "../adminElevation/genericForbidden";

const CSRF_COOKIE = "admin_csrf";
const CSRF_MAX_AGE_SECONDS = 300;

function forbidden(): Response {
  const failure = genericForbiddenResponse();
  return Response.json(failure.body, { status: failure.status, headers: { "Cache-Control": "no-store" } });
}

export async function handleAdminCsrfIssue(): Promise<Response> {
  const session = await getServerSession(authOptions);
  const actorId = session?.user.id;
  if (!actorId) return forbidden();
  const user = await prisma.user.findUnique({
    where: { id: actorId },
    select: { role: true, status: true, sessionVersion: true },
  });
  if (!user || user.role !== "ADMIN" || user.status !== "ACTIVE" ||
      user.sessionVersion !== session.user.sessionVersion) return forbidden();

  const token = issueCsrfToken();
  const canonicalUrl = env.AUTH_URL ?? env.NEXTAUTH_URL;
  if (!canonicalUrl) return forbidden();
  const secure = new URL(canonicalUrl).protocol === "https:" ? "; Secure" : "";
  return Response.json({ csrfToken: token }, {
    headers: {
      "Cache-Control": "no-store",
      "Set-Cookie": `${CSRF_COOKIE}=${token}; Path=/api/admin; Max-Age=${CSRF_MAX_AGE_SECONDS}; HttpOnly${secure}; SameSite=Strict`,
    },
  });
}
