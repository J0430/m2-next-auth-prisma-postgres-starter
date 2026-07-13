// Enforces current-session, explicit-capability, ACTIVE-factor, and freshness gates.
import { env } from "@/lib/env";
import { prisma } from "@/lib/prisma";
import { GenericForbiddenError } from "./genericForbidden";
import type { AdminCapability, AdminElevationContext, ElevationGrant } from "./adminElevation.types";

async function deny(actorId: string | null, capability: AdminCapability, action: string): Promise<never> {
  try {
    await prisma.$transaction(async (tx) => {
      await tx.auditEvent.create({
        data: { ...(actorId ? { actorUserId: actorId } : {}), action, targetType: "AdminCapability", metadata: { capability, outcome: "DENIAL" } },
      });
    });
  } catch {
    console.error("security.admin_elevation_denial_audit_unavailable", {
      code: "ADMIN_ELEVATION_DENIAL_AUDIT_UNAVAILABLE",
    });
  }
  throw new GenericForbiddenError();
}

async function evaluateAdminElevation(
  context: AdminElevationContext,
  capability: AdminCapability,
  now: Date,
  audit: Readonly<{ success: boolean; denialAction: string }>,
): Promise<ElevationGrant> {
  const actorId = context.session?.userId ?? null;
  if (!context.session) return deny(actorId, capability, audit.denialAction);
  const session = context.session;
  const user = await context.tx.user.findUnique({
    where: { id: session.userId },
    select: { role: true, status: true, sessionVersion: true, lastStrongAuthAt: true },
  });
  const activeFactor = await context.tx.adminMfaFactor.findFirst({ where: { userId: session.userId, status: "ACTIVE" }, select: { id: true } });
  const capabilityGrant = await context.tx.adminCapabilityGrant.findFirst({
    where: { userId: session.userId, capability, revokedAt: null },
    select: { id: true },
  });
  const maxAgeMs = env.ADMIN_ELEVATION_MAX_AGE_SECONDS * 1000;
  const freshnessAge = user?.lastStrongAuthAt ? now.getTime() - user.lastStrongAuthAt.getTime() : null;
  const fresh = freshnessAge !== null && freshnessAge >= 0 && freshnessAge <= maxAgeMs;
  if (!user || user.status !== "ACTIVE" || user.sessionVersion !== context.session.sessionVersion ||
      user.role !== "ADMIN" || !capabilityGrant || !activeFactor || !fresh) {
    return deny(actorId, capability, audit.denialAction);
  }
  if (audit.success) {
    await context.tx.auditEvent.create({
      data: { actorUserId: actorId, action: "admin.elevation.granted", targetType: "AdminCapability", metadata: { capability, outcome: "SUCCESS" } },
    });
  }
  return { actorId: session.userId, capability, grantedAt: now };
}

export function requireAdminElevation(
  context: AdminElevationContext,
  capability: AdminCapability,
  now = new Date(),
): Promise<ElevationGrant> {
  return evaluateAdminElevation(context, capability, now, { success: true, denialAction: "admin.elevation.denied" });
}

// Domain mutations own their sole SUCCESS audit; this helper only proves elevation.
export function authorizeAdminElevationForDomainMutation(
  context: AdminElevationContext,
  capability: AdminCapability,
  denialAction: string,
  now = new Date(),
): Promise<ElevationGrant> {
  return evaluateAdminElevation(context, capability, now, { success: false, denialAction });
}
