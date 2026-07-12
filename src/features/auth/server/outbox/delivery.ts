// Delivery handlers for claimed transactional outbox rows.
import type {
  ClaimableOutboxEmailRow,
  OutboxProcessorDeps,
  RecipientUser,
  SendVerificationEmailArgs,
} from "./types";
import type { SendInvitationEmailArgs } from "./invitationEmail";

export const OUTBOX_PROVIDER_TIMEOUT_MS = 10_000;

export async function withProviderTimeout(
  operation: (signal: AbortSignal) => Promise<void>,
  parentSignal?: AbortSignal,
  afterInitialParentCheck?: () => void,
): Promise<void> {
  parentSignal?.throwIfAborted();
  afterInitialParentCheck?.();
  const controller = new AbortController();
  let rejectFromParent: ((reason: unknown) => void) | null = null;
  let parentAbortHandled = false;
  const abortFromParent = () => {
    if (parentAbortHandled) return;
    parentAbortHandled = true;
    const reason = parentSignal?.reason ?? new Error("OUTBOX_DELIVERY_ABORTED");
    controller.abort(reason);
    rejectFromParent?.(reason);
  };
  const parentAbort = new Promise<never>((_resolve, reject) => {
    rejectFromParent = reject;
  });
  parentSignal?.addEventListener("abort", abortFromParent, { once: true });
  if (parentSignal?.aborted) abortFromParent();
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  let cleanedUp = false;
  const cleanup = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    if (timeoutId !== null) clearTimeout(timeoutId);
    parentSignal?.removeEventListener("abort", abortFromParent);
  };
  const timeout = new Promise<never>((_resolve, reject) => {
    timeoutId = setTimeout(() => {
      controller.abort();
      reject(new Error("EMAIL_SEND_TIMEOUT"));
    }, OUTBOX_PROVIDER_TIMEOUT_MS);
  });
  try {
    if (controller.signal.aborted) await parentAbort;
    await Promise.race([operation(controller.signal), timeout, parentAbort]);
  } finally {
    cleanup();
  }
}

function buildVerificationEmailArgs(
  recipient: RecipientUser,
  code: string,
  signal: AbortSignal,
): SendVerificationEmailArgs {
  if (recipient.name) {
    return { to: recipient.email, code, name: recipient.name, signal };
  }
  return { to: recipient.email, code, signal };
}

function buildInvitationEmailArgs(
  recipient: { email: string; name: string | null },
  inviteUrl: string,
  signal: AbortSignal,
): SendInvitationEmailArgs & { signal: AbortSignal } {
  if (recipient.name) {
    return { to: recipient.email, inviteUrl, name: recipient.name, signal };
  }
  return { to: recipient.email, inviteUrl, signal };
}

async function findRecipient(
  row: ClaimableOutboxEmailRow,
  deps: OutboxProcessorDeps
): Promise<RecipientUser> {
  if (!row.recipientUserId) throw new Error("OUTBOX_RECIPIENT_NOT_FOUND");

  const recipient = await deps.db.findRecipientUser(row.recipientUserId);
  if (!recipient) throw new Error("OUTBOX_RECIPIENT_NOT_FOUND");
  return recipient;
}

async function deliverVerificationEmail(
  row: ClaimableOutboxEmailRow,
  deps: OutboxProcessorDeps,
  signal?: AbortSignal,
): Promise<void> {
  signal?.throwIfAborted();
  const recipient = await findRecipient(row, deps);
  signal?.throwIfAborted();
  const token = await deps.createVerificationToken(recipient.email);
  signal?.throwIfAborted();
  await withProviderTimeout((providerSignal) =>
    deps.sendVerificationEmail(buildVerificationEmailArgs(recipient, token.code, providerSignal)), signal);
}

async function deliverInvitationEmail(
  row: ClaimableOutboxEmailRow,
  deps: OutboxProcessorDeps,
  signal?: AbortSignal,
): Promise<void> {
  signal?.throwIfAborted();
  if (!row.inviteCiphertext) throw new Error("INVITE_DELIVERY_DECRYPT_FAILED");

  if (!row.aggregateId || row.recipientUserId) throw new Error("OUTBOX_INVITE_INVALID");
  const invite = await deps.db.findInviteRecipient?.(row.aggregateId);
  signal?.throwIfAborted();
  if (!invite || invite.id !== row.aggregateId || invite.status !== "ISSUED" ||
      invite.expiresAt <= deps.now() || !invite.normalizedEmail) {
    throw new Error("OUTBOX_INVITE_INVALID");
  }
  const recipient = { email: invite.normalizedEmail, name: null };
  const rawToken = deps.decryptInviteToken(row.inviteCiphertext, row.keyVersion);
  const inviteUrl = deps.buildInviteAcceptUrl(rawToken);
  await withProviderTimeout((providerSignal) =>
    deps.sendInvitationEmail(buildInvitationEmailArgs(recipient, inviteUrl, providerSignal)), signal);
}

export async function deliverClaimedOutboxEmail(
  row: ClaimableOutboxEmailRow,
  deps: OutboxProcessorDeps,
  signal?: AbortSignal,
): Promise<void> {
  switch (row.eventType) {
    case "EMAIL_VERIFICATION":
      await deliverVerificationEmail(row, deps, signal);
      return;
    case "INVITATION_DELIVERY":
      await deliverInvitationEmail(row, deps, signal);
      return;
    default:
      throw new Error("OUTBOX_UNSUPPORTED_EVENT_TYPE");
  }
}
