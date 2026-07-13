// Exercises TASK-016 database invariants against an already-migrated disposable PostgreSQL database.
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import {
  AccountStatus,
  AdminMfaKind,
  AdminMfaStatus,
  InviteStatus,
  OutboxEmailStatus,
  Prisma,
  PrismaClient,
  RegistrationSessionStatus,
  Role,
} from '@prisma/client';
import { z } from 'zod';
import { validateStoredAdminMfaKeyVersions } from '../src/features/auth/server/adminMfa/secretCrypto';
import {
  createInviteRedemptionContext,
  lookupInviteByToken,
  recordInviteReuseEvidence,
  redeemInviteInTx,
  setInviteReuseAlertHandler,
} from '../src/features/auth/server/invites/index';
import type {
  InviteTransactionClient,
  RedeemedInviteRecord,
} from '../src/features/auth/server/invites/invite.types';
import { CLAIM_DUE_OUTBOX_EMAIL_SQL } from '../src/features/auth/server/outbox/db';
import { createPrismaOutboxDb } from '../src/features/auth/server/outbox/db';
import { processOutboxEmailMessage } from '../src/features/auth/server/outbox/processor';
import {
  finalizeOutboxEmailSent,
  recordOutboxEmailFailure,
} from '../src/features/auth/server/outbox/state';
import type { ClaimableOutboxEmailRow } from '../src/features/auth/server/outbox/types';
import { createVerificationToken, hashOtpCode } from '../src/features/auth/server/verify/createToken';
import { consumeVerificationToken } from '../src/features/auth/server/verify/consumeToken';

const EnvironmentSchema = z.object({ DATABASE_URL: z.string().url() });

function disposableDatabaseUrl(): string {
  const { DATABASE_URL } = EnvironmentSchema.parse(process.env);
  const url = new URL(DATABASE_URL);
  if (
    url.protocol !== 'postgresql:'
    || url.hostname !== 'localhost'
    || url.pathname !== '/auth_ci'
    || url.search !== ''
    || url.hash !== ''
  ) {
    throw new Error('TASK-016 integration requires canonical disposable localhost/auth_ci PostgreSQL');
  }
  return url.toString();
}

const prisma = new PrismaClient({ datasourceUrl: disposableDatabaseUrl() });
const runId = `task016-${randomUUID()}`;
const now = new Date();
const expiredAt = new Date(now.getTime() - 60_000);
const futureAt = new Date(now.getTime() + 600_000);
const consumedGraceCutoff = new Date(now.getTime() - 30_000);

function invariant(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function isPrismaError(error: unknown, code: string): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === code;
}

function isNamedConstraintError(error: unknown, constraint: string): boolean {
  return error instanceof Error
    && (error.message.includes(constraint)
      || (error instanceof Prisma.PrismaClientKnownRequestError
        && JSON.stringify(error.meta).includes(constraint)));
}

async function expectNamedConstraintViolation(
  operation: () => Promise<unknown>,
  constraint: string,
  fallbackMessage?: RegExp,
): Promise<void> {
  try {
    await operation();
  } catch (error: unknown) {
    const matchesFallback = error instanceof Error && fallbackMessage?.test(error.message) === true;
    invariant(isNamedConstraintError(error, constraint) || matchesFallback, `expected exact ${constraint} violation`);
    return;
  }
  throw new Error(`expected exact ${constraint} violation`);
}

async function verifyCaseInsensitiveEmailUniqueness(): Promise<void> {
  const email = `${runId}@example.com`;
  await prisma.user.create({ data: { email: email.toUpperCase() } });
  let uniqueFailures = 0;
  try {
    await prisma.user.create({ data: { email: email.toLowerCase() } });
  } catch (error: unknown) {
    invariant(isPrismaError(error, 'P2002'), 'case-variant email must raise Prisma P2002');
    uniqueFailures += 1;
  }
  const count = await prisma.user.count({ where: { email } });
  invariant(count === 1, `case-variant email must leave one user, found ${count}`);
  invariant(uniqueFailures === 1, `case-variant email must raise one P2002, found ${uniqueFailures}`);
}

async function verifyCredentialCheck(): Promise<void> {
  let rejectedUnsafeState = false;
  try {
    await prisma.user.create({
      data: {
        email: `${runId}-forbidden@example.com`,
        status: AccountStatus.ACTIVE,
        hasPasswordCredential: true,
        passwordHash: null,
      },
    });
  } catch {
    rejectedUnsafeState = true;
  }
  invariant(rejectedUnsafeState, 'ACTIVE credential user without a password hash must be rejected');

  await prisma.user.createMany({ data: [
    {
      email: `${runId}-provider@example.com`, status: AccountStatus.ACTIVE,
      hasPasswordCredential: false, passwordHash: null,
    },
    {
      email: `${runId}-suspended@example.com`, status: AccountStatus.SUSPENDED,
      hasPasswordCredential: true, passwordHash: 'retained-hash',
    },
    {
      email: `${runId}-inactive@example.com`, status: AccountStatus.INACTIVE,
      hasPasswordCredential: true, passwordHash: null,
    },
  ] });
}

async function verifyInviteIntegrity(): Promise<void> {
  const issuer = await prisma.user.create({ data: { email: `${runId}-issuer@example.com` } });
  const redeemer = await prisma.user.create({ data: { email: `${runId}-redeemer@example.com` } });
  await expectNamedConstraintViolation(
    () => prisma.$executeRaw`INSERT INTO "public"."invites" (
      "id", "tokenHash", "expiresAt", "issuerUserId", "updatedAt"
    ) VALUES (${`${runId}-short-hash`}, ${randomBytes(31)}, ${futureAt}, ${issuer.id}, CURRENT_TIMESTAMP)`,
    'chk_invites_token_hash_length',
  );

  const invite = await prisma.invite.create({
    data: {
      id: `${runId}-invite`, tokenHash: randomBytes(32), expiresAt: futureAt,
      issuerUserId: issuer.id,
    },
  });
  await expectNamedConstraintViolation(
    () => prisma.$executeRaw`UPDATE "public"."invites" SET "status" = 'REDEEMED' WHERE "id" = ${invite.id}`,
    'chk_invite_redeemed_binding',
  );
  await expectNamedConstraintViolation(
    () => prisma.$executeRaw`UPDATE "public"."invites" SET "redeemedAt" = ${now} WHERE "id" = ${invite.id}`,
    'chk_invite_redeemed_binding',
  );
  await expectNamedConstraintViolation(
    () => prisma.$executeRaw`UPDATE "public"."invites" SET "status" = 'REVOKED' WHERE "id" = ${invite.id}`,
    'chk_invite_revoked_binding',
  );
  await expectNamedConstraintViolation(
    () => prisma.$executeRaw`UPDATE "public"."invites" SET "revokedAt" = ${now} WHERE "id" = ${invite.id}`,
    'chk_invite_revoked_binding',
  );
  await expectNamedConstraintViolation(
    () => prisma.$executeRaw`UPDATE "public"."invites" SET
      "status" = 'REDEEMED', "redeemedAt" = ${now}, "redeemedByUserId" = ${`${runId}-absent-user`}
      WHERE "id" = ${invite.id}`,
    'invites_redeemedByUserId_fkey',
  );
  await prisma.invite.update({
    where: { id: invite.id },
    data: { status: InviteStatus.REDEEMED, redeemedAt: now, redeemedByUserId: redeemer.id },
  });
}

function redeemedInviteRecord(invite: {
  id: string;
  tokenHash: Uint8Array;
  normalizedEmail: string | null;
  status: string;
  expiresAt: Date;
  redeemedByUserId: string | null;
  redeemedAt: Date | null;
  revokedAt: Date | null;
} | null): RedeemedInviteRecord | null {
  if (!invite || invite.status !== 'REDEEMED' || !invite.redeemedByUserId || !invite.redeemedAt) return null;
  return { ...invite, status: 'REDEEMED', redeemedByUserId: invite.redeemedByUserId, redeemedAt: invite.redeemedAt };
}

class InviteReuseSignal extends Error {
  constructor(readonly inviteId: string) {
    super('REGISTRATION_ADMISSION_DENIED');
  }
}

function inviteTx(
  tx: Prisma.TransactionClient,
  redeemerUserId: string,
  signalReuseDetected: (inviteId: string) => void,
) {
  const client: InviteTransactionClient = {
    redeemerUserId,
    invite: {
      updateMany: (args) => tx.invite.updateMany(args),
      findFirst: async (args) => redeemedInviteRecord(await tx.invite.findFirst(args)),
    },
  };
  return createInviteRedemptionContext(client, signalReuseDetected);
}

async function redeemThroughProductionRollbackBoundary(
  resolvedInvite: { inviteId: string } | { tokenHash: Buffer },
  expectedNormalizedEmail: string | null,
  redeemerUserId: string,
): Promise<{ ok: boolean }> {
  try {
    return await prisma.$transaction(async (tx) => {
      const result = await redeemInviteInTx(
        inviteTx(tx, redeemerUserId, (inviteId) => {
          throw new InviteReuseSignal(inviteId);
        }),
        resolvedInvite,
        expectedNormalizedEmail,
      );
      if (!result.ok) {
        throw new Error('REGISTRATION_ADMISSION_DENIED');
      }
      return { ok: true };
    }, { maxWait: 50, timeout: 150 });
  } catch (error) {
    if (error instanceof InviteReuseSignal) await recordInviteReuseEvidence(error.inviteId);
    return { ok: false };
  }
}

async function verifyInviteLifecycleBehavior(): Promise<void> {
  const issuer = await prisma.user.create({ data: { email: `${runId}-lifecycle-issuer@example.com` } });
  const email = `${runId}-winner@example.com`;
  const redeemer = await prisma.user.create({ data: { email } });
  const tokenHash = randomBytes(32);
  const invite = await prisma.invite.create({ data: {
    id: `${runId}-lifecycle-invite`, tokenHash, normalizedEmail: email,
    expiresAt: futureAt, issuerUserId: issuer.id,
  } });
  let alerts = 0;
  const resetAlert = setInviteReuseAlertHandler(() => { alerts += 1; });
  try {
    const attempts = await Promise.all(Array.from({ length: 8 }, () =>
      redeemThroughProductionRollbackBoundary({ inviteId: invite.id }, email, redeemer.id),
    ));
    invariant(attempts.filter(({ ok }) => ok).length === 1, 'invite CAS must have exactly one MVCC winner');
    invariant(attempts.filter(({ ok }) => !ok).length === 7, 'all concurrent invite CAS losers must get generic failure');
    const second = await redeemThroughProductionRollbackBoundary(
      { tokenHash }, email, redeemer.id,
    );
    invariant(JSON.stringify(second) === JSON.stringify({ ok: false }), 'second redemption must return generic failure');
    const persisted = await prisma.invite.findUnique({ where: { id: invite.id } });
    invariant(persisted?.status === InviteStatus.REDEEMED, 'winning redemption must persist REDEEMED');
    invariant(persisted.redeemedByUserId === redeemer.id, 'winning redemption must bind the server-resolved user');
    const audits = await prisma.auditEvent.findMany({
      where: { action: 'invite.reuse_detected', targetId: invite.id },
      select: { targetId: true, metadata: true },
    });
    invariant(audits.length === 8, 'each replay loser must append one reuse audit event');
    invariant(alerts === 8, 'each replay loser must fire the reuse alert');
    const auditText = JSON.stringify(audits);
    invariant(!auditText.includes(email), 'reuse audit metadata must exclude plaintext email');
    invariant(!auditText.includes(tokenHash.toString('hex')), 'reuse audit metadata must exclude token digest');
  } finally {
    resetAlert();
  }

  const mismatchHash = randomBytes(32);
  const mismatch = await prisma.invite.create({ data: {
    id: `${runId}-mismatch-invite`, tokenHash: mismatchHash, normalizedEmail: email,
    expiresAt: futureAt, issuerUserId: issuer.id,
  } });
  const mismatchResult = await redeemThroughProductionRollbackBoundary(
    { inviteId: mismatch.id }, `${runId}-other@example.com`, redeemer.id,
  );
  invariant(JSON.stringify(mismatchResult) === JSON.stringify({ ok: false }), 'email mismatch must be generic failure');
  const mismatchPersisted = await prisma.invite.findUnique({ where: { id: mismatch.id } });
  invariant(mismatchPersisted?.status === InviteStatus.ISSUED, 'email mismatch must leave invite ISSUED');

  const digest = (token: string) => createHash('sha256').update(token).digest();
  const lookupTokens = {
    expired: `${runId}-expired`,
    revoked: `${runId}-revoked`,
    redeemed: `${runId}-redeemed`,
    mismatch: `${runId}-email-mismatch`,
    absent: `${runId}-absent`,
  };
  await prisma.invite.createMany({ data: [
    {
      id: `${runId}-lookup-expired`, tokenHash: digest(lookupTokens.expired), normalizedEmail: email,
      expiresAt: expiredAt, issuerUserId: issuer.id,
    },
    {
      id: `${runId}-lookup-revoked`, tokenHash: digest(lookupTokens.revoked), normalizedEmail: email,
      status: InviteStatus.REVOKED, revokedAt: now, expiresAt: futureAt, issuerUserId: issuer.id,
    },
    {
      id: `${runId}-lookup-redeemed`, tokenHash: digest(lookupTokens.redeemed), normalizedEmail: email,
      status: InviteStatus.REDEEMED, redeemedAt: now, redeemedByUserId: redeemer.id,
      expiresAt: futureAt, issuerUserId: issuer.id,
    },
    {
      id: `${runId}-lookup-mismatch`, tokenHash: digest(lookupTokens.mismatch), normalizedEmail: email,
      expiresAt: futureAt, issuerUserId: issuer.id,
    },
  ] });
  const lookupCases = [
    lookupInviteByToken(lookupTokens.absent, email),
    lookupInviteByToken('', email),
    lookupInviteByToken(lookupTokens.expired, email),
    lookupInviteByToken(lookupTokens.revoked, email),
    lookupInviteByToken(lookupTokens.redeemed, email),
    lookupInviteByToken(lookupTokens.mismatch, `${runId}-other@example.com`),
  ];
  const lookupResults = await Promise.all(lookupCases);
  const firstResult = JSON.stringify(lookupResults[0]);
  invariant(lookupResults.every((result) => JSON.stringify(result) === firstResult), 'six lookup failures must share body/status');
}

async function verifyOutboxDeduplication(): Promise<void> {
  const dedupId = `${runId}-dedup`;
  await prisma.outboxEmail.create({ data: { id: `${runId}-outbox`, eventType: 'TASK016', dedupId } });
  try {
    await prisma.outboxEmail.create({ data: { id: `${runId}-outbox-collision`, eventType: 'TASK016', dedupId } });
  } catch (error: unknown) {
    invariant(isPrismaError(error, 'P2002'), 'duplicate OutboxEmail.dedupId must raise P2002');
    return;
  }
  throw new Error('duplicate OutboxEmail.dedupId must be rejected');
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function verifyOutboxRuntimeBehavior(): Promise<void> {
  const id = `${runId}-outbox-runtime`;
  await prisma.outboxEmail.create({ data: {
    id, eventType: 'INVITATION_DELIVERY', dedupId: `${runId}-runtime-dedup`,
    availableAt: now, inviteCiphertext: Buffer.from('authenticated-ciphertext'), keyVersion: 1,
  } });

  const firstWorker = prisma.$transaction(async (tx) => {
    const rows = await tx.$queryRawUnsafe<Array<{ id: string }>>(
      CLAIM_DUE_OUTBOX_EMAIL_SQL, id, now, now,
    );
    invariant(rows.length === 1, 'first worker must lock the due outbox row');
    await tx.$executeRaw`SELECT pg_sleep(0.15)`;
    await tx.outboxEmail.update({ where: { id }, data: {
      status: OutboxEmailStatus.CLAIMED, claimToken: `${runId}-claim-one`, leaseExpiresAt: futureAt,
    } });
  });
  await wait(25);
  const secondRows = await prisma.$transaction((tx) => tx.$queryRawUnsafe<Array<{ id: string }>>(
    CLAIM_DUE_OUTBOX_EMAIL_SQL, id, now, now,
  ));
  invariant(secondRows.length === 0, 'second worker must SKIP LOCKED while the first owns the row');
  await firstWorker;

  await prisma.outboxEmail.update({ where: { id }, data: {
    claimToken: `${runId}-claim-two`, leaseExpiresAt: futureAt,
  } });
  const staleFinalized = await finalizeOutboxEmailSent(id, `${runId}-claim-one`, {
    db: { updateOutboxEmailMany: (args) => prisma.outboxEmail.updateMany(args) }, now: () => now,
  });
  invariant(!staleFinalized, 'stale claim token must not finalize a re-claimed row');
  const finalized = await finalizeOutboxEmailSent(id, `${runId}-claim-two`, {
    db: { updateOutboxEmailMany: (args) => prisma.outboxEmail.updateMany(args) }, now: () => now,
  });
  invariant(finalized, 'current fenced claim must finalize');
  const sent = await prisma.outboxEmail.findUnique({ where: { id } });
  invariant(sent?.status === OutboxEmailStatus.SENT, 'successful row must be SENT');
  invariant(sent.inviteCiphertext === null && sent.keyVersion === null && sent.clearedAt !== null,
    'successful invitation must erase ciphertext/key and persist clearedAt');
  const terminalRows = await prisma.$queryRawUnsafe<Array<{ id: string }>>(
    CLAIM_DUE_OUTBOX_EMAIL_SQL, id, now, now,
  );
  invariant(terminalRows.length === 0, 'terminal row status must make duplicate delivery a no-op');

  const failureId = `${runId}-outbox-terminal`;
  await prisma.outboxEmail.create({ data: {
    id: failureId, eventType: 'INVITATION_DELIVERY', dedupId: `${runId}-terminal-dedup`,
    status: OutboxEmailStatus.CLAIMED, attempts: 4, availableAt: now, claimToken: `${runId}-terminal-claim`,
    inviteCiphertext: Buffer.from('authenticated-ciphertext'), keyVersion: 1,
  } });
  const failureRow: ClaimableOutboxEmailRow = {
    id: failureId, eventType: 'INVITATION_DELIVERY', aggregateId: null,
    recipientUserId: null, attempts: 4, inviteCiphertext: Buffer.from('authenticated-ciphertext'),
    keyVersion: 1,
  };
  const terminal = await recordOutboxEmailFailure(
    failureRow, `${runId}-terminal-claim`, new Error('EMAIL_SEND_FAILED'),
    { db: { updateOutboxEmailMany: (args) => prisma.outboxEmail.updateMany(args) }, now: () => now },
  );
  invariant(terminal === 'terminal', 'fifth failure must enter terminal state');
  const failed = await prisma.outboxEmail.findUnique({ where: { id: failureId } });
  invariant(failed?.status === OutboxEmailStatus.FAILED, 'terminal delivery must persist FAILED');
  invariant(failed.inviteCiphertext === null && failed.keyVersion === null && failed.clearedAt !== null,
    'terminal invitation must erase ciphertext/key and persist clearedAt');

  const retryId = `${runId}-outbox-retry`;
  await prisma.outboxEmail.create({ data: {
    id: retryId, eventType: 'EMAIL_VERIFICATION', dedupId: `${runId}-retry-dedup`,
    status: OutboxEmailStatus.CLAIMED, availableAt: now, claimToken: `${runId}-retry-claim`,
  } });
  const retry = await recordOutboxEmailFailure(
    {
      id: retryId, eventType: 'EMAIL_VERIFICATION', aggregateId: null,
      recipientUserId: null, attempts: 0, inviteCiphertext: null, keyVersion: null,
    },
    `${runId}-retry-claim`, new Error('EMAIL_SEND_FAILED'),
    { db: { updateOutboxEmailMany: (args) => prisma.outboxEmail.updateMany(args) }, now: () => now },
  );
  invariant(retry === 'retry', 'first failure must remain retryable');
  const retryRow = await prisma.outboxEmail.findUnique({ where: { id: retryId } });
  const retryDelay = (retryRow?.nextAttemptAt?.getTime() ?? 0) - now.getTime();
  invariant(retryRow?.status === OutboxEmailStatus.PENDING && retryRow.attempts === 1,
    'retry must return to PENDING and increment attempts');
  invariant(retryDelay >= 60_000 && retryDelay <= 75_000,
    'retry must use bounded exponential backoff with bounded jitter');
}

async function verifyAdminMfaCapability(): Promise<void> {
  const user = await prisma.user.create({ data: { email: `${runId}-admin@example.com` } });
  await expectNamedConstraintViolation(
    () => prisma.$transaction(async (tx) => {
      await tx.user.update({ where: { id: user.id }, data: { role: Role.ADMIN } });
    }),
    'chk_admin_mfa_capability',
    /ADMIN requires mfaEnrolledAt and at least one ACTIVE AdminMfaFactor/u,
  );
  await expectNamedConstraintViolation(
    () => prisma.$transaction(async (tx) => {
      await tx.user.update({ where: { id: user.id }, data: { role: Role.ADMIN, mfaEnrolledAt: now } });
    }),
    'chk_admin_mfa_capability',
    /ADMIN requires mfaEnrolledAt and at least one ACTIVE AdminMfaFactor/u,
  );
  const factorId = `${runId}-factor`;
  await prisma.$transaction(async (tx) => {
    await tx.user.update({ where: { id: user.id }, data: { role: Role.ADMIN, mfaEnrolledAt: now } });
    await tx.adminMfaFactor.create({ data: {
      id: factorId, userId: user.id, kind: AdminMfaKind.TOTP, status: AdminMfaStatus.ACTIVE,
      secretCipher: randomBytes(32), keyVersion: 1, activatedAt: now,
    } });
  });
  await expectNamedConstraintViolation(
    () => prisma.$transaction(async (tx) => {
      await tx.adminMfaFactor.update({ where: { id: factorId }, data: { status: AdminMfaStatus.REVOKED } });
    }),
    'chk_admin_mfa_capability',
    /ADMIN requires mfaEnrolledAt and at least one ACTIVE AdminMfaFactor/u,
  );
  const replacementId = `${runId}-replacement-factor`;
  await prisma.$transaction(async (tx) => {
    await tx.adminMfaFactor.create({ data: {
      id: replacementId, userId: user.id, kind: AdminMfaKind.TOTP, status: AdminMfaStatus.PENDING,
      secretCipher: randomBytes(32), keyVersion: 1,
    } });
    await tx.user.update({ where: { id: user.id }, data: { lastStrongAuthAt: null, sessionVersion: { increment: 1 } } });
  });
  await prisma.$transaction(async (tx) => {
    await tx.adminMfaFactor.update({ where: { id: replacementId }, data: { status: AdminMfaStatus.ACTIVE, activatedAt: now } });
    await tx.adminMfaFactor.update({ where: { id: factorId }, data: { status: AdminMfaStatus.REVOKED, revokedAt: now } });
    await tx.user.update({ where: { id: user.id }, data: { mfaEnrolledAt: now, lastStrongAuthAt: now } });
  });
  await prisma.$transaction(async (tx) => {
    await tx.adminMfaFactor.update({ where: { id: replacementId }, data: { status: AdminMfaStatus.REVOKED } });
    await tx.user.update({ where: { id: user.id }, data: { role: Role.USER } });
  });
}

async function verifyLegacyExemptionSnapshotImmutability(): Promise<void> {
  const user = await prisma.user.create({ data: { email: `${runId}-exemption@example.com` } });
  for (const statement of [
    () => prisma.$executeRaw`INSERT INTO "public"."admin_mfa_legacy_exemptions" ("userId") VALUES (${user.id})`,
    () => prisma.$executeRaw`UPDATE "public"."admin_mfa_legacy_exemptions" SET "userId" = ${user.id} WHERE FALSE`,
  ]) {
    let rejected = false;
    try { await statement(); } catch { rejected = true; }
    invariant(rejected, 'legacy exemption snapshot must reject INSERT and UPDATE');
  }
  await prisma.$executeRaw`DELETE FROM "public"."admin_mfa_legacy_exemptions" WHERE "userId" = ${user.id}`;
}

async function expectAuditMutationRejected(operation: 'UPDATE' | 'DELETE', id: string): Promise<void> {
  let rejected = false;
  try {
    if (operation === 'UPDATE') {
      await prisma.$executeRaw`UPDATE "public"."audit_events" SET "action" = 'mutated' WHERE "id" = ${id}`;
    } else {
      await prisma.$executeRaw`DELETE FROM "public"."audit_events" WHERE "id" = ${id}`;
    }
  } catch {
    rejected = true;
  }
  invariant(rejected, `AuditEvent ${operation} must be rejected by the database trigger`);
}

async function verifyAuditImmutability(): Promise<void> {
  const event = await prisma.auditEvent.create({
    data: { id: `${runId}-audit`, action: `${runId}:created`, targetType: 'TASK-016' },
  });
  await expectAuditMutationRejected('UPDATE', event.id);
  await expectAuditMutationRejected('DELETE', event.id);
  const persisted = await prisma.auditEvent.findUnique({ where: { id: event.id } });
  invariant(persisted?.action === `${runId}:created`, 'immutable AuditEvent must remain unchanged');
}

function sessionData(
  suffix: string,
  status: RegistrationSessionStatus,
  expiresAt: Date,
  consumedAt: Date | null = null,
) {
  return {
    id: `${runId}-${suffix}`,
    handleHash: randomBytes(32),
    nonce: randomBytes(16),
    status,
    expiresAt,
    consumedAt,
  };
}

async function consume(handleHash: Uint8Array): Promise<number> {
  const result = await prisma.registrationSession.updateMany({
    where: {
      handleHash,
      status: RegistrationSessionStatus.PENDING,
      expiresAt: { gt: now },
      consumedAt: null,
    },
    data: { status: RegistrationSessionStatus.CONSUMED, consumedAt: now },
  });
  return result.count;
}

async function verifyRegistrationSessionCas(): Promise<void> {
  const pending = sessionData('pending', RegistrationSessionStatus.PENDING, futureAt);
  const decoy = sessionData('decoy', RegistrationSessionStatus.DECOY, futureAt);
  const expired = sessionData('expired', RegistrationSessionStatus.PENDING, expiredAt);
  const consumed = sessionData('consumed', RegistrationSessionStatus.CONSUMED, futureAt, now);
  await prisma.registrationSession.createMany({ data: [pending, decoy, expired, consumed] });

  const contenders = await Promise.all([consume(pending.handleHash), consume(pending.handleHash)]);
  invariant(contenders.reduce((sum, count) => sum + count, 0) === 1, 'CAS must have exactly one winner');
  const losingCounts = await Promise.all([
    consume(decoy.handleHash), consume(expired.handleHash), consume(consumed.handleHash), consume(randomBytes(32)),
  ]);
  invariant(losingCounts.every((count) => count === 0), 'decoy, expired, consumed, and unknown refs must lose CAS');
}

async function verifyCleanupPredicate(): Promise<void> {
  const expiredDecoy = sessionData('cleanup-expired-decoy', RegistrationSessionStatus.DECOY, expiredAt);
  const oldConsumed = sessionData(
    'cleanup-old-consumed', RegistrationSessionStatus.CONSUMED, futureAt,
    new Date(consumedGraceCutoff.getTime() - 1_000),
  );
  const freshConsumed = sessionData('cleanup-fresh-consumed', RegistrationSessionStatus.CONSUMED, futureAt, now);
  const livePending = sessionData('cleanup-live-pending', RegistrationSessionStatus.PENDING, futureAt);
  await prisma.registrationSession.createMany({ data: [expiredDecoy, oldConsumed, freshConsumed, livePending] });

  const ownedIds = [expiredDecoy.id, oldConsumed.id, freshConsumed.id, livePending.id];
  const liveBeforeCleanup = await prisma.registrationSession.findUnique({
    where: { id: livePending.id },
    select: { expiresAt: true, status: true, consumedAt: true },
  });
  invariant(
    liveBeforeCleanup?.status === RegistrationSessionStatus.PENDING
      && liveBeforeCleanup.consumedAt === null
      && liveBeforeCleanup.expiresAt.getTime() > now.getTime(),
    `live pending row must be ineligible before cleanup; stored ${JSON.stringify(liveBeforeCleanup)}`,
  );
  const cleanupBatch = () => prisma.$queryRaw<Array<{ id: string }>>`
    DELETE FROM "public"."registration_sessions"
    WHERE "id" IN (
      SELECT "id" FROM "public"."registration_sessions"
      WHERE "id" IN (${Prisma.join(ownedIds)})
        AND ("expiresAt" < (${now} AT TIME ZONE 'UTC')
          OR ("status" = 'CONSUMED' AND "consumedAt" < (${consumedGraceCutoff} AT TIME ZONE 'UTC')))
      ORDER BY "expiresAt" ASC, "id" ASC
      FOR UPDATE SKIP LOCKED
      LIMIT 1
    )
    RETURNING "id"
  `;
  const concurrentBatches = await Promise.all([cleanupBatch(), cleanupBatch()]);
  invariant(concurrentBatches.flat().length === 2,
    'two concurrent cleanup batches must reap exactly the two eligible owned rows');
  const idempotentBatch = await cleanupBatch();
  invariant(
    idempotentBatch.length === 0,
    `re-running cleanup must be idempotent; deleted ${idempotentBatch.map(({ id }) => id).join(', ')}`,
  );
  const survivors = await prisma.registrationSession.findMany({
    where: { id: { in: [expiredDecoy.id, oldConsumed.id, freshConsumed.id, livePending.id] } },
    select: { id: true },
  });
  const survivorIds = new Set(survivors.map(({ id }) => id));
  invariant(!survivorIds.has(expiredDecoy.id), 'expired decoy must be reaped by expiresAt');
  invariant(!survivorIds.has(oldConsumed.id), 'consumed row beyond grace must be reaped');
  invariant(survivorIds.has(freshConsumed.id), 'fresh consumed row must remain during grace');
  invariant(survivorIds.has(livePending.id), 'unexpired pending row must remain');
}

async function verifyConcurrentOtpSupersession(): Promise<void> {
  const identifier = `${runId}-otp@example.com`;
  await prisma.user.create({ data: {
    email: identifier, status: AccountStatus.INACTIVE,
    hasPasswordCredential: false, passwordHash: null,
  } });
  const completionOrder: Array<Awaited<ReturnType<typeof createVerificationToken>>> = [];
  const issue = async () => {
    const result = await createVerificationToken(identifier);
    completionOrder.push(result);
    return result;
  };
  await Promise.all([issue(), issue()]);
  const rows = await prisma.verificationToken.findMany({ where: { identifier } });
  invariant(rows.length === 1, 'concurrent OTP replacement must leave exactly one live token');
  const newestDigest = rows[0]?.token;
  const lastCompleted = completionOrder.at(-1);
  invariant(lastCompleted !== undefined && hashOtpCode(lastCompleted.code) === newestDigest,
    'the persisted OTP must be the last completed replacement');
  const superseded = completionOrder.at(-2);
  invariant(superseded !== undefined && hashOtpCode(superseded.code) !== newestDigest,
    'the earlier completed OTP must be superseded');
  const oldResult = await consumeVerificationToken(identifier, superseded.code, 'ReplacementP@ssword123');
  invariant(!oldResult.ok && oldResult.reason === 'invalid-code',
    'the superseded OTP must be rejected by production consumption');
  const newestResult = await consumeVerificationToken(identifier, lastCompleted.code, 'ReplacementP@ssword123');
  invariant(newestResult.ok, 'the newest OTP must activate exactly once');
  const replayResult = await consumeVerificationToken(identifier, lastCompleted.code, 'ReplacementP@ssword123');
  invariant(!replayResult.ok, 'the newest OTP must fail after its single successful consumption');
}

async function verifyProviderFailureKeepsAccountInactive(): Promise<void> {
  const email = `${runId}-provider-failure@example.com`;
  const user = await prisma.user.create({ data: {
    email, status: AccountStatus.INACTIVE, emailVerified: null,
    hasPasswordCredential: false, password: null, passwordHash: null,
  } });
  const outbox = await prisma.outboxEmail.create({ data: {
    id: `${runId}-provider-failure-outbox`, eventType: 'EMAIL_VERIFICATION',
    aggregateId: user.id, recipientUserId: user.id,
    availableAt: now, dedupId: `${runId}-provider-failure-dedup`,
  } });

  const result = await processOutboxEmailMessage({ id: outbox.id }, {
    db: createPrismaOutboxDb(), now: () => now, generateClaimToken: randomUUID,
    createVerificationToken,
    sendVerificationEmail: async () => { throw new Error('EMAIL_SEND_FAILED'); },
    decryptInviteToken: () => { throw new Error('UNEXPECTED_INVITE_DECRYPT'); },
    buildInviteAcceptUrl: () => { throw new Error('UNEXPECTED_INVITE_URL'); },
    sendInvitationEmail: async () => { throw new Error('UNEXPECTED_INVITE_SEND'); },
  });
  invariant(result.outcome === 'retry', 'provider failure must schedule an outbox retry');

  const persisted = await prisma.user.findUnique({
    where: { id: user.id },
    select: {
      status: true, emailVerified: true, password: true, passwordHash: true,
      hasPasswordCredential: true, sessionVersion: true,
    },
  });
  invariant(persisted?.status === AccountStatus.INACTIVE, 'provider failure must leave user INACTIVE');
  invariant(persisted.emailVerified === null, 'provider failure must not verify the email');
  invariant(persisted.password === null && persisted.passwordHash === null,
    'provider failure must not create or change password material');
  invariant(!persisted.hasPasswordCredential && persisted.sessionVersion === 0,
    'provider failure must not enable credentials or advance session version');
  invariant(await prisma.session.count({ where: { userId: user.id } }) === 0,
    'provider failure must not create a session');
}

async function cleanup(): Promise<void> {
  await prisma.registrationSession.deleteMany({ where: { id: { startsWith: runId } } });
  await prisma.outboxEmail.deleteMany({ where: { id: { startsWith: runId } } });
  await prisma.invite.deleteMany({ where: { id: { startsWith: runId } } });
  await prisma.adminMfaFactor.deleteMany({ where: { id: { startsWith: runId } } });
  await prisma.user.deleteMany({ where: { email: { startsWith: runId } } });
  await prisma.verificationToken.deleteMany({ where: { identifier: { startsWith: runId } } });
}

async function main(): Promise<void> {
  try {
    await verifyCaseInsensitiveEmailUniqueness();
    await verifyCredentialCheck();
    await verifyInviteIntegrity();
    await verifyInviteLifecycleBehavior();
    await verifyOutboxDeduplication();
    await verifyOutboxRuntimeBehavior();
    await verifyAdminMfaCapability();
    await verifyLegacyExemptionSnapshotImmutability();
    await verifyAuditImmutability();
    await verifyRegistrationSessionCas();
    await verifyCleanupPredicate();
    await verifyConcurrentOtpSupersession();
    await verifyProviderFailureKeepsAccountInactive();
    await validateStoredAdminMfaKeyVersions(prisma);
    console.log(JSON.stringify({
      ok: true,
      suite: 'TASK-016/TASK-017/TASK-018 real PostgreSQL behavioral integration',
      auditRetention: 'test-owned immutable row retained only until disposable database teardown',
    }));
  } finally {
    await cleanup();
    await prisma.$disconnect();
  }
}

await main();
