// Implements atomic issue/list/revoke/resend operations with elevation and redacted audit.
import { createHash } from "node:crypto";
import { z } from "zod";
import { createInviteInTx, revokeInviteInTx } from "../invites";
import { normalizeInviteEmail } from "../invites/token";
import type {
  AdminInviteListItem, AdminInviteService, AdminInviteServiceDeps,
  AdminInviteTx, ExistingAdminInviteInput, IssueAdminInviteInput,
} from "./adminInvites.types";

const ReasonSchema = z.string().trim().min(1).max(500);
const IssueInputSchema = z.object({ email: z.string().trim().email().max(320), reason: ReasonSchema });
const ExistingInputSchema = z.object({ inviteId: z.string().trim().min(1).max(128), reason: ReasonSchema });

function requireValidInput(result: { success: boolean }): void {
  if (!result.success) throw new Error("ADMIN_INVITE_INVALID_INPUT");
}

function buildInviteDedupId(inviteId: string, keyVersion: number): string {
  return createHash("sha256")
    .update(["INVITATION_DELIVERY", inviteId, String(keyVersion), "v1"].join("\u001f"), "utf8")
    .digest("hex");
}

function maskEmail(email: string | null): string | null {
  if (!email) return null;
  const separator = email.indexOf("@");
  if (separator < 1) return "***";
  return `${email.slice(0, 1)}***${email.slice(separator)}`;
}

function auditData(actorId: string, action: string, targetId: string, reason: string, requestId: string, outcome: "SUCCESS" | "NO_OP") {
  return {
    actorUserId: actorId, action, targetType: "Invite", targetId, requestId,
    supportId: requestId, metadata: {
      outcome, reasonDigest: createHash("sha256").update(reason.trim(), "utf8").digest("hex"),
    },
  };
}

async function createInviteAndOutbox(
  tx: AdminInviteTx, deps: AdminInviteServiceDeps, actorId: string, normalizedEmail: string,
): Promise<string> {
  const invite = await createInviteInTx(tx, { issuerUserId: actorId, email: normalizedEmail });
  const inviteCiphertext = deps.encryptToken(invite.rawToken, deps.deliveryKey.keyHex);
  await tx.outboxEmail.create({ data: {
    eventType: "INVITATION_DELIVERY", aggregateId: invite.inviteId,
    dedupId: buildInviteDedupId(invite.inviteId, deps.deliveryKey.version),
    inviteCiphertext, keyVersion: deps.deliveryKey.version,
  } });
  return invite.inviteId;
}

async function authorizeMutation(
  deps: AdminInviteServiceDeps, tx: AdminInviteTx, input: IssueAdminInviteInput | ExistingAdminInviteInput,
  capability: "admin:invite:issue" | "admin:invite:revoke", action: string,
) {
  return deps.authorize({ session: input.session, tx }, capability, `${action}.denied`, deps.now());
}

export function createAdminInviteService(deps: AdminInviteServiceDeps): AdminInviteService {
  return {
    issue: async (input) => {
      requireValidInput(IssueInputSchema.safeParse(input));
      return deps.transaction(async (tx) => {
      const grant = await authorizeMutation(deps, tx, input, "admin:invite:issue", "admin.invite.issue");
      const normalizedEmail = normalizeInviteEmail(input.email);
      const existing = await tx.invite.findFirst({ where: { normalizedEmail, status: "ISSUED", expiresAt: { gt: deps.now() } }, select: { id: true } });
      if (existing) {
        await tx.auditEvent.create({ data: auditData(grant.actorId, "admin.invite.issue", existing.id, input.reason, input.requestId, "NO_OP") });
        return { ok: true, inviteId: existing.id };
      }
      const inviteId = await createInviteAndOutbox(tx, deps, grant.actorId, normalizedEmail);
      await tx.auditEvent.create({ data: auditData(grant.actorId, "admin.invite.issue", inviteId, input.reason, input.requestId, "SUCCESS") });
        return { ok: true, inviteId };
      });
    },
    revoke: async (input) => {
      requireValidInput(ExistingInputSchema.safeParse(input));
      return deps.transaction(async (tx) => {
      const grant = await authorizeMutation(deps, tx, input, "admin:invite:revoke", "admin.invite.revoke");
      const revoked = await revokeInviteInTx(tx, { inviteId: input.inviteId }, deps.now());
      await tx.auditEvent.create({ data: auditData(grant.actorId, "admin.invite.revoke", input.inviteId, input.reason, input.requestId, revoked.revoked ? "SUCCESS" : "NO_OP") });
        return { ok: true };
      });
    },
    resend: async (input) => {
      requireValidInput(ExistingInputSchema.safeParse(input));
      return deps.transaction(async (tx) => {
      const grant = await authorizeMutation(deps, tx, input, "admin:invite:issue", "admin.invite.resend");
      const current = await tx.invite.findFirst({ where: { id: input.inviteId }, select: { id: true, status: true, normalizedEmail: true } });
      if (!current?.normalizedEmail) {
        await tx.auditEvent.create({ data: auditData(grant.actorId, "admin.invite.resend", input.inviteId, input.reason, input.requestId, "NO_OP") });
        return { ok: true, inviteId: null };
      }
      const revoked = await revokeInviteInTx(tx, { inviteId: current.id }, deps.now());
      if (!revoked.revoked) {
        await tx.auditEvent.create({ data: auditData(grant.actorId, "admin.invite.resend", input.inviteId, input.reason, input.requestId, "NO_OP") });
        return { ok: true, inviteId: null };
      }
      const inviteId = await createInviteAndOutbox(tx, deps, grant.actorId, current.normalizedEmail);
      await tx.auditEvent.create({ data: auditData(grant.actorId, "admin.invite.resend", inviteId, input.reason, input.requestId, "SUCCESS") });
        return { ok: true, inviteId };
      });
    },
    list: (session) => deps.transaction(async (tx) => {
      await deps.authorize({ session, tx }, "admin:invite:issue", "admin.invite.list.denied", deps.now());
      const now = deps.now();
      const rows = await tx.invite.findMany({ orderBy: { createdAt: "desc" }, take: 100, select: { id: true, normalizedEmail: true, status: true, expiresAt: true, createdAt: true } });
      return rows.map((row): AdminInviteListItem => ({
        id: row.id, maskedEmail: maskEmail(row.normalizedEmail),
        status: row.status === "ISSUED" && row.expiresAt <= now ? "EXPIRED" : row.status,
        expiresAt: row.expiresAt, createdAt: row.createdAt,
      }));
    }),
  };
}
