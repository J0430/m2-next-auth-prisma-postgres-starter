// HTTP orchestration for CSRF/rate-limited, audited admin MFA mutations.
import { compare } from "bcryptjs";
import { getServerSession } from "next-auth";
import type { Session } from "next-auth";
import { cookies } from "next/headers";
import { z } from "zod";
import { authOptions } from "@/features/auth/server/options";
import { padAdmissionTiming, validateCsrf } from "@/features/auth/server/admission";
import { genericForbiddenResponse, isGenericForbiddenError } from "../adminElevation/genericForbidden";
import { authorizeAdminElevationForDomainMutation } from "../adminElevation/requireAdminElevation";
import { prisma } from "@/lib/prisma";
import { buildAdmissionRateLimitChecks, getClientIp, rateLimit } from "@/lib/rateLimit";
import { enrollAdminMfaFactor, verifyAdminMfaFactor } from "./adminMfaService";
import { env } from "@/lib/env";

const EnrollSchema = z.object({ csrfToken: z.string().min(1), currentPassword: z.string().min(1).max(256).nullable() });
const AssertSchema = z.object({ csrfToken: z.string().min(1), factorId: z.string().min(1), code: z.string().regex(/^\d{6}$/u) });
const CSRF_COOKIE = "admin_csrf";
const ADMIN_CANONICAL_ORIGIN = new URL(env.AUTH_URL ?? env.NEXTAUTH_URL ?? "http://localhost:3000").origin;

function response(body: unknown, status: number): Response {
  return Response.json(body, { status });
}

async function deny(actorId: string | null, action: string, startedAtMs: number): Promise<Response> {
  try {
    await prisma.$transaction((tx) => tx.auditEvent.create({
      data: { ...(actorId ? { actorUserId: actorId } : {}), action, targetType: "AdminMfaFactor", metadata: { outcome: "DENIAL" } },
    }));
  } catch {
    console.error("security.admin_mfa_denial_audit_unavailable", {
      code: "ADMIN_MFA_DENIAL_AUDIT_UNAVAILABLE",
    });
  }
  await padAdmissionTiming(startedAtMs);
  const failure = genericForbiddenResponse();
  return response(failure.body, failure.status);
}

async function forbiddenWithoutAudit(startedAtMs: number): Promise<Response> {
  await padAdmissionTiming(startedAtMs);
  const failure = genericForbiddenResponse();
  return response(failure.body, failure.status);
}

async function authorize(
  request: Request,
  csrfToken: string,
  session: Session | null,
  replacementFactorId?: string,
) {
  const actorId = session?.user.id || null;
  const csrfCookie = (await cookies()).get(CSRF_COOKIE)?.value ?? null;
  const csrf = validateCsrf({ headers: request.headers, expectedOrigin: ADMIN_CANONICAL_ORIGIN, sessionToken: csrfCookie, submittedToken: csrfToken });
  if (!actorId || !csrf.ok) return { ok: false as const, actorId };
  if (!session) return { ok: false as const, actorId };
  const checks = buildAdmissionRateLimitChecks({ surface: "admin-operation", ip: getClientIp(request.headers), adminActorId: actorId });
  for (const check of checks) if (!(await rateLimit(check.key, check.policy)).success) return { ok: false as const, actorId };
  const currentUser = await prisma.user.findUnique({
    where: { id: actorId },
    select: { role: true, status: true, sessionVersion: true },
  });
  if (!currentUser || currentUser.role !== "ADMIN" || currentUser.status !== "ACTIVE") return { ok: false as const, actorId };
  if (currentUser.sessionVersion !== session.user.sessionVersion) {
    const pendingReplacement = replacementFactorId && currentUser.sessionVersion === session.user.sessionVersion + 1
      ? await prisma.adminMfaFactor.findFirst({ where: { id: replacementFactorId, userId: actorId, status: "PENDING" }, select: { id: true } })
      : null;
    if (!pendingReplacement) return { ok: false as const, actorId };
  }
  return { ok: true as const, actorId, session: { userId: actorId, role: session.user.role ?? "USER", sessionVersion: session.user.sessionVersion } };
}

export async function handleAdminMfaEnroll(request: Request): Promise<Response> {
  const startedAtMs = Date.now();
  const session = await getServerSession(authOptions);
  const actorId = session?.user.id ?? null;
  const parsed = EnrollSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return deny(actorId, "admin.mfa.enroll.denied", startedAtMs);
  const auth = await authorize(request, parsed.data.csrfToken, session);
  if (!auth.ok) return deny(auth.actorId, "admin.mfa.enroll.denied", startedAtMs);
  try {
    const result = await prisma.$transaction(async (tx) => {
      const user = await tx.user.findUnique({ where: { id: auth.actorId }, select: { email: true, passwordHash: true, hasPasswordCredential: true } });
      const active = await tx.adminMfaFactor.findFirst({ where: { userId: auth.actorId, status: "ACTIVE" }, select: { id: true } });
      if (active) await authorizeAdminElevationForDomainMutation(
        { session: auth.session, tx }, "admin:mfa:manage", "admin.mfa.enroll.denied",
      );
      else if (!user?.hasPasswordCredential || !user.passwordHash || !parsed.data.currentPassword || !(await compare(parsed.data.currentPassword, user.passwordHash))) throw new Error("ADMIN_MFA_FORBIDDEN");
      if (!user) throw new Error("ADMIN_MFA_FORBIDDEN");
      return enrollAdminMfaFactor({ tx, actorId: auth.actorId, accountName: user.email, issuer: env.MFA_ISSUER, now: new Date() });
    });
    return response({ ok: true, ...result }, 201);
  } catch (error: unknown) {
    if (isGenericForbiddenError(error)) return forbiddenWithoutAudit(startedAtMs);
    return deny(auth.actorId, "admin.mfa.enroll.denied", startedAtMs);
  }
}

async function handleAssertion(request: Request, action: "verify" | "refresh"): Promise<Response> {
  const startedAtMs = Date.now();
  const denialAction = action === "refresh" ? "admin.elevation.refresh" : "admin.mfa.verify.denied";
  const session = await getServerSession(authOptions);
  const actorId = session?.user.id ?? null;
  const parsed = AssertSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return deny(actorId, denialAction, startedAtMs);
  const auth = await authorize(request, parsed.data.csrfToken, session, action === "verify" ? parsed.data.factorId : undefined);
  if (!auth.ok) return deny(auth.actorId, denialAction, startedAtMs);
  try {
    await prisma.$transaction((tx) => verifyAdminMfaFactor({
      tx, actorId: auth.actorId, factorId: parsed.data.factorId, code: parsed.data.code,
      auditAction: action === "refresh" ? "admin.elevation.refresh" : "admin.mfa.verify", now: new Date(),
    }));
    return response({ ok: true }, 200);
  } catch { return deny(auth.actorId, denialAction, startedAtMs); }
}

export const handleAdminMfaVerify = (request: Request) => handleAssertion(request, "verify");
export const handleAdminElevationRefresh = (request: Request) => handleAssertion(request, "refresh");
