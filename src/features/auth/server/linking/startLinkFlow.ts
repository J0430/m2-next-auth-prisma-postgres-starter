// Orchestrates intent creation and dedicated provider authorization URL creation.
import { createAccountLinkIntent, type CreateLinkIntentInput } from "./createLinkIntent";
import { prisma } from "@/lib/prisma";
import { recordLinkDenied } from "./audit";
import { hashLinkNonce } from "./nonce";
import { createS256Challenge, deriveLinkVerifier } from "./pkce";
import { assertLinkProviderConfigured, buildAuthorizationUrl } from "./providerOAuth";

async function revokeFailedIntent(input: CreateLinkIntentInput, rawState: string): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await tx.accountLinkIntent.updateMany({
      where: {
        userId: input.userId,
        provider: input.provider,
        nonceHash: hashLinkNonce(rawState),
        consumedAt: null,
      },
      data: { consumedAt: new Date() },
    });
    await tx.auditEvent.create({ data: {
      action: "auth.account_link_denied",
      targetType: "AccountLink",
      targetUserId: input.userId,
      metadata: { provider: input.provider, reason: "authorization_url_failed" },
    } });
  });
}

export async function startAccountLinkFlow(input: CreateLinkIntentInput) {
  try {
    assertLinkProviderConfigured(input.provider);
  } catch {
    await recordLinkDenied(input.provider, "provider_unavailable", input.userId);
    return { ok: false as const, reason: "provider_unavailable" as const };
  }
  let result: Awaited<ReturnType<typeof createAccountLinkIntent>>;
  try {
    result = await createAccountLinkIntent(input);
  } catch {
    await recordLinkDenied(input.provider, "intent_persistence_failed", input.userId);
    return { ok: false as const, reason: "intent_persistence_failed" as const };
  }
  if (!result.ok) return result;
  try {
    const verifier = deriveLinkVerifier(result.rawState, input.provider);
    return { ok: true as const, authorizationUrl: buildAuthorizationUrl(input.provider, result.rawState, createS256Challenge(verifier)) };
  } catch {
    await revokeFailedIntent(input, result.rawState);
    return { ok: false as const, reason: "authorization_url_failed" as const };
  }
}
