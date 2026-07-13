// Validates admin invite HTTP mutations before delegating to the transactional service.
import { z } from "zod";
import { validateCsrf } from "../admission/csrf";
import { buildAdmissionRateLimitChecks } from "@/lib/rateLimitAdmission";
import type { RateLimitPolicy } from "@/lib/rateLimit";
import type { AdminInviteService } from "./adminInvites.types";

const CommonSchema = z.object({
  csrfToken: z.string().min(1), reason: z.string().trim().min(3).max(500),
  requestId: z.string().uuid(),
});
const IssueSchema = CommonSchema.extend({ email: z.string().email().max(320) });
const ExistingSchema = CommonSchema.extend({ inviteId: z.string().trim().min(1).max(128) });

type HttpSession = { user: { id: string; role?: "USER" | "ADMIN"; sessionVersion: number } } | null;
type AdminInviteHttpDeps = {
  session(): Promise<HttpSession>;
  csrfCookie(): Promise<string | null>;
  limit(key: string, policy: RateLimitPolicy): Promise<{ success: boolean }>;
  service: AdminInviteService;
  expectedOrigin: string;
  clientIp(headers: Headers): string | null;
};

function forbidden(): Response {
  return Response.json({ ok: false, message: "Unable to complete this request." }, { status: 403, headers: { "Cache-Control": "no-store" } });
}

function sessionClaim(session: HttpSession) {
  if (!session || session.user.role !== "ADMIN") return null;
  return { userId: session.user.id, role: session.user.role, sessionVersion: session.user.sessionVersion } as const;
}

export function createAdminInviteHttpHandler(
  operation: "issue" | "revoke" | "resend", deps: AdminInviteHttpDeps,
): (request: Request) => Promise<Response> {
  return async (request) => {
    const session = await deps.session();
    const claim = sessionClaim(session);
    const json: unknown = await request.json().catch(() => null);
    const parsed = operation === "issue" ? IssueSchema.safeParse(json) : ExistingSchema.safeParse(json);
    if (!claim || !parsed.success) return forbidden();
    const csrf = validateCsrf({
      headers: request.headers, expectedOrigin: deps.expectedOrigin,
      sessionToken: await deps.csrfCookie(), submittedToken: parsed.data.csrfToken,
    });
    if (!csrf.ok) return forbidden();
    const ip = deps.clientIp(request.headers);
    const checks = buildAdmissionRateLimitChecks({ surface: "admin-operation", adminActorId: claim.userId, ip });
    for (const check of checks) if (!(await deps.limit(check.key, check.policy)).success) return forbidden();
    try {
      if (operation === "issue" && "email" in parsed.data) {
        await deps.service.issue({ session: claim, email: parsed.data.email, reason: parsed.data.reason, requestId: parsed.data.requestId });
      } else if ("inviteId" in parsed.data) {
        const input = { session: claim, inviteId: parsed.data.inviteId, reason: parsed.data.reason, requestId: parsed.data.requestId };
        if (operation === "revoke") await deps.service.revoke(input);
        else await deps.service.resend(input);
      } else return forbidden();
      return Response.json({ ok: true }, { headers: { "Cache-Control": "no-store" } });
    } catch { return forbidden(); }
  };
}
