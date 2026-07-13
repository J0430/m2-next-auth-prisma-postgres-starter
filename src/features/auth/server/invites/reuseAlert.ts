// src/features/auth/server/invites/reuseAlert.ts
// Reuse alert hook for invite replay detection.
import type { InviteReuseAlertHandler } from "./invite.types";

const productionReuseAlertHandler: InviteReuseAlertHandler = (payload) => {
  console.error("security.invite_reuse_detected", payload);
};

let inviteReuseAlertHandler: InviteReuseAlertHandler = productionReuseAlertHandler;

export function setInviteReuseAlertHandler(handler: InviteReuseAlertHandler): () => void {
  const previousHandler = inviteReuseAlertHandler;
  inviteReuseAlertHandler = handler;

  return () => {
    inviteReuseAlertHandler = previousHandler;
  };
}

export async function alertInviteReuse(inviteId: string, auditPersisted: boolean): Promise<void> {
  try {
    await inviteReuseAlertHandler({ inviteId, status: "REDEEMED", auditPersisted });
  } catch {
    console.error("security.invite_reuse_alert_failed", {
      inviteId,
      auditPersisted,
      code: "INVITE_REUSE_ALERT_FAILED",
    });
  }
}
