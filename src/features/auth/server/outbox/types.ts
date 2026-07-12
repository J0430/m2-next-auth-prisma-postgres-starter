// Shared types for the transactional email outbox worker.
import type { SendInvitationEmailArgs } from "./invitationEmail";

export type OutboxEmailStatus = "PENDING" | "CLAIMED" | "SENT" | "FAILED" | "CANCELLED";

export type ClaimableOutboxEmailRow = {
  id: string;
  eventType: string;
  aggregateId: string | null;
  recipientUserId: string | null;
  attempts: number;
  inviteCiphertext: Uint8Array | null;
  keyVersion: number | null;
};

export type OutboxStatusFilter = OutboxEmailStatus | { in: OutboxEmailStatus[] };

export type OutboxUpdateWhere = {
  id: string;
  status?: OutboxStatusFilter;
  claimToken?: string | null;
};

export type OutboxUpdateData = {
  status?: OutboxEmailStatus;
  attempts?: number;
  claimedAt?: Date;
  claimToken?: string | null;
  leaseExpiresAt?: Date | null;
  nextAttemptAt?: Date | null;
  sentAt?: Date;
  failedAt?: Date;
  lastErrorCode?: string | null;
  inviteCiphertext?: Uint8Array | null;
  keyVersion?: number | null;
  clearedAt?: Date | null;
};

export type OutboxUpdateManyArgs = {
  where: OutboxUpdateWhere;
  data: OutboxUpdateData;
};

export type OutboxUpdateResult = {
  count: number;
};

export type RecipientUser = {
  id: string;
  email: string;
  name: string | null;
  status: string;
};

export type InviteRecipient = {
  id: string;
  normalizedEmail: string | null;
  status: string;
  expiresAt: Date;
};

export type SendVerificationEmailArgs = {
  to: string;
  code: string;
  name?: string;
  signal?: AbortSignal;
};

export type OutboxStateDeps = {
  db: {
    updateOutboxEmailMany(args: OutboxUpdateManyArgs): Promise<OutboxUpdateResult>;
  };
  now(): Date;
};

export type OutboxTransactionClient = OutboxStateDeps["db"] & {
  queryClaimableOutboxEmails(id: string, now: Date): Promise<ClaimableOutboxEmailRow[]>;
  findRecipientUser(id: string): Promise<RecipientUser | null>;
  findInviteRecipient?(id: string): Promise<InviteRecipient | null>;
};

export type OutboxDb = OutboxTransactionClient & {
  $transaction<T>(callback: (tx: OutboxTransactionClient) => Promise<T>): Promise<T>;
};

export type OutboxProcessorDeps = {
  db: OutboxDb;
  now(): Date;
  generateClaimToken(): string;
  createVerificationToken(email: string): Promise<{ ok: true; code: string }>;
  sendVerificationEmail(args: SendVerificationEmailArgs): Promise<void>;
  decryptInviteToken(ciphertext: Uint8Array, keyVersion: number | null): string;
  buildInviteAcceptUrl(rawToken: string): string;
  sendInvitationEmail(args: SendInvitationEmailArgs & { signal?: AbortSignal }): Promise<void>;
};

export type OutboxProcessResult = {
  ok: true;
  outcome: "sent" | "skipped" | "stale" | "retry" | "failed";
};

export type OutboxClaim = {
  row: ClaimableOutboxEmailRow;
  claimToken: string;
};
