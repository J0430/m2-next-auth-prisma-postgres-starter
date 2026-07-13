// Persists redacted invite-reuse evidence outside a rolled-back caller transaction.
import { prisma } from "@/lib/prisma";
import { monotonicNow, withinDeadline, type MonotonicClock } from "@/features/auth/server/admission";
import { alertInviteReuse } from "./reuseAlert";

const REUSE_EVIDENCE_BUDGET_MS = 1_000;
const REUSE_AUDIT_MAX_WAIT_MS = 500;
const REUSE_AUDIT_TIMEOUT_MS = 750;

export async function recordInviteReuseEvidence(
  inviteId: string,
  clock: MonotonicClock = monotonicNow,
): Promise<void> {
  const startedAtMs = clock();
  let auditPersisted = false;
  try {
    await prisma.$transaction((tx) => tx.auditEvent.create({
      data: {
        action: "invite.reuse_detected",
        targetType: "Invite",
        targetId: inviteId,
        metadata: { inviteStatus: "REDEEMED" },
      },
    }), { maxWait: REUSE_AUDIT_MAX_WAIT_MS, timeout: REUSE_AUDIT_TIMEOUT_MS });
    auditPersisted = true;
  } catch {
    console.error("security.invite_reuse_audit_failed", {
      inviteId,
      auditPersisted: false,
    });
  }

  try {
    await withinDeadline(
      () => alertInviteReuse(inviteId, auditPersisted),
      startedAtMs + REUSE_EVIDENCE_BUDGET_MS,
      clock,
    );
  } catch {
    console.error("security.invite_reuse_alert_timeout", { inviteId, auditPersisted });
  }
}
