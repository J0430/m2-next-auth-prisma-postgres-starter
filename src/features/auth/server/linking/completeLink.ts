// Completes a dedicated OAuth link after current-session and intent revalidation.
import { prisma } from "@/lib/prisma";
import { recordLinkDenied } from "./audit";
import { constantTimeNonceHashMatches, hashLinkNonce } from "./nonce";
import { deriveLinkVerifier } from "./pkce";
import { fetchProviderSubject } from "./providerOAuth";
import type { LinkDenialReason, LinkableProvider } from "./linking.types";

interface CallbackSession { userId: string; sessionVersion: number }
type Completion = { ok: true } | { ok: false; reason: LinkDenialReason };

export async function completeAccountLink(input: {
  provider: LinkableProvider; state: string; code: string | null; providerError: boolean; session: CallbackSession | null;
}): Promise<Completion> {
  const digest = hashLinkNonce(input.state);
  const intent = await prisma.accountLinkIntent.findUnique({ where: { nonceHash: digest }, include: {
    user: { select: { id: true, status: true, sessionVersion: true } },
  } });
  const actorId = intent?.userId ?? input.session?.userId ?? null;
  const deny = async (reason: LinkDenialReason): Promise<Completion> => {
    await recordLinkDenied(input.provider, reason, actorId);
    return { ok: false, reason };
  };
  if (!intent || !constantTimeNonceHashMatches(digest, intent.nonceHash)) return deny("unknown_intent");
  if (intent.provider !== input.provider) return deny("provider_mismatch");
  if (intent.consumedAt !== null) return deny("replayed_intent");
  if (intent.expiresAt <= new Date()) return deny("expired_intent");
  if (intent.user.status !== "ACTIVE") return deny("intent_user_not_active");
  if (!input.session || input.session.userId !== intent.userId ||
      input.session.sessionVersion !== intent.sessionVersion ||
      intent.user.sessionVersion !== intent.sessionVersion) return deny("session_mismatch");

  const claimed = await prisma.accountLinkIntent.updateMany({ where: {
    id: intent.id, userId: input.session.userId, provider: input.provider,
    sessionVersion: input.session.sessionVersion, consumedAt: null, expiresAt: { gt: new Date() },
  }, data: { consumedAt: new Date() } });
  if (claimed.count !== 1) return deny("replayed_intent");
  if (input.providerError || !input.code) return deny("provider_error");

  let subject: string;
  try { subject = await fetchProviderSubject(input.provider, input.code, deriveLinkVerifier(input.state, input.provider)); }
  catch { return deny("provider_error"); }
  const collision = await prisma.account.findUnique({ where: { provider_providerAccountId: {
    provider: input.provider, providerAccountId: subject,
  } }, select: { userId: true } });
  if (collision) return deny("provider_already_linked");

  try {
    await prisma.$transaction(async (tx) => {
      await tx.account.create({ data: { userId: intent.userId, type: "oauth", provider: input.provider, providerAccountId: subject } });
      const updated = await tx.user.updateMany({ where: { id: intent.userId, status: "ACTIVE", sessionVersion: intent.sessionVersion }, data: { sessionVersion: { increment: 1 } } });
      if (updated.count !== 1) throw new Error("LINK_SESSION_CHANGED");
      await tx.auditEvent.create({ data: { action: "auth.account_link_completed", targetType: "AccountLink", actorUserId: intent.userId, targetUserId: intent.userId, metadata: { provider: input.provider } } });
    });
    return { ok: true };
  } catch {
    return deny("link_transaction_failed");
  }
}
