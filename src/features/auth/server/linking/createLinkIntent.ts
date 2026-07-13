// Creates a hash-only link intent after ACTIVE-session and recent-auth checks.
import { compare } from "bcryptjs";
import { prisma } from "@/lib/prisma";
import { recordLinkDenied } from "./audit";
import { generateLinkNonce, hashLinkNonce } from "./nonce";
import { LINK_INTENT_TTL_MS, LINK_REAUTH_FRESHNESS_MS, type CreateLinkIntentResult, type LinkableProvider } from "./linking.types";

const DUMMY_HASH = "$2a$10$7EqJtq98hPqEX7fNZaFWoOhi.McZTpBdWnB7Rso8yX3i.Yx5x2m6e";
export interface CreateLinkIntentInput {
  userId: string; provider: LinkableProvider; currentPassword: string | null;
  lastAuthAtMs: number | null; currentAuthProvider: string | null; sessionVersion: number;
}

async function recent(input: CreateLinkIntentInput, user: { passwordHash: string | null }): Promise<boolean> {
  if (input.currentAuthProvider === "credentials") {
    return input.currentPassword !== null && user.passwordHash !== null &&
      compare(input.currentPassword, user.passwordHash ?? DUMMY_HASH);
  }
  const social = input.currentAuthProvider === "google" || input.currentAuthProvider === "github";
  const age = input.lastAuthAtMs === null ? Number.POSITIVE_INFINITY : Date.now() - input.lastAuthAtMs;
  return social && age >= 0 && age <= LINK_REAUTH_FRESHNESS_MS;
}

export async function createAccountLinkIntent(input: CreateLinkIntentInput): Promise<CreateLinkIntentResult> {
  const user = await prisma.user.findUnique({ where: { id: input.userId }, select: {
    id: true, status: true, passwordHash: true, sessionVersion: true,
  } });
  if (!user || user.status !== "ACTIVE" || user.sessionVersion !== input.sessionVersion) {
    await recordLinkDenied(input.provider, "user_not_active", user?.id ?? null);
    return { ok: false, reason: "user_not_active" };
  }
  if (!(await recent(input, user))) {
    const reason = input.currentAuthProvider === "credentials" ? "reauth_failed" : "reauth_stale";
    await recordLinkDenied(input.provider, reason, user.id);
    return { ok: false, reason };
  }
  const linked = await prisma.account.findFirst({ where: { userId: user.id, provider: input.provider }, select: { id: true } });
  if (linked) {
    await recordLinkDenied(input.provider, "provider_already_connected", user.id);
    return { ok: false, reason: "provider_already_connected" };
  }
  const rawState = generateLinkNonce();
  const expiresAt = new Date(Date.now() + LINK_INTENT_TTL_MS);
  try {
    await prisma.$transaction(async (tx) => {
      await tx.accountLinkIntent.updateMany({ where: { userId: user.id, provider: input.provider, consumedAt: null }, data: { consumedAt: new Date() } });
      await tx.accountLinkIntent.create({ data: { userId: user.id, provider: input.provider, nonceHash: hashLinkNonce(rawState), expiresAt, sessionVersion: input.sessionVersion } });
      await tx.auditEvent.create({ data: { action: "auth.account_link_started", targetType: "AccountLink", actorUserId: user.id, targetUserId: user.id, metadata: { provider: input.provider } } });
    });
    return { ok: true, rawState, expiresAt };
  } catch {
    await recordLinkDenied(input.provider, "intent_persistence_failed", user.id);
    return { ok: false, reason: "intent_persistence_failed" };
  }
}
