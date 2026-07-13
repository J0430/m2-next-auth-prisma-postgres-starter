// Wires admin invite services and HTTP handlers to Prisma and shared auth controls.
import { getServerSession } from "next-auth";
import { cookies } from "next/headers";
import { authOptions } from "../options";
import { authorizeAdminElevationForDomainMutation } from "../adminElevation";
import { encryptInviteDeliveryToken } from "../outbox/inviteCrypto";
import { env } from "@/lib/env";
import { prisma } from "@/lib/prisma";
import { getClientIp, rateLimit } from "@/lib/rateLimit";
import { createAdminInviteHttpHandler } from "./adminInviteHttp";
import { createAdminInviteService } from "./adminInviteService";

const CSRF_COOKIE = "admin_csrf";

function deliveryKey(): { keyHex: string; version: number } {
  const rawVersion = env.INVITE_DELIVERY_KEY_VERSION;
  const version = rawVersion ? Number(rawVersion) : Number.NaN;
  const keyHex = rawVersion ? env.INVITE_DELIVERY_ENCRYPTION_KEYS?.[rawVersion] : undefined;
  if (!Number.isInteger(version) || !keyHex) throw new Error("INVITE_DELIVERY_KEY_MISSING");
  return { keyHex, version };
}

export function createDefaultAdminInviteService() {
  return createAdminInviteService({
    transaction: (callback) => prisma.$transaction((tx) => callback(tx), { isolationLevel: "Serializable" }),
    authorize: (context, capability, denialAction, now) =>
      authorizeAdminElevationForDomainMutation(context, capability, denialAction, now),
    encryptToken: encryptInviteDeliveryToken,
    deliveryKey: deliveryKey(),
    now: () => new Date(),
  });
}

export function createDefaultAdminInviteHttpHandler(operation: "issue" | "revoke" | "resend") {
  return createAdminInviteHttpHandler(operation, {
    session: () => getServerSession(authOptions),
    csrfCookie: async () => (await cookies()).get(CSRF_COOKIE)?.value ?? null,
    limit: rateLimit,
    service: createDefaultAdminInviteService(),
    expectedOrigin: new URL(env.AUTH_URL ?? env.NEXTAUTH_URL ?? "http://localhost:3000").origin,
    clientIp: getClientIp,
  });
}
