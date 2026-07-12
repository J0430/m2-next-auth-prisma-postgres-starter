// Redacted, separately durable audit emission for account-link denials.
// Success/start audits are written inside their transactions; denial audits
// are awaited in a separate write so a rolled-back mutation cannot erase them.
import { prisma } from "@/lib/prisma";
import type { LinkDenialReason, LinkInitiationDenialReason } from "./linking.types";

export async function recordLinkDenied(
  provider: string,
  reason: LinkDenialReason | LinkInitiationDenialReason,
  targetUserId: string | null,
): Promise<void> {
  const baseData = {
    action: "auth.account_link_denied",
    targetType: "AccountLink",
    metadata: { provider, reason },
  };

  if (targetUserId) {
    await prisma.auditEvent.create({ data: { ...baseData, targetUserId } });
    return;
  }
  await prisma.auditEvent.create({ data: baseData });
}
