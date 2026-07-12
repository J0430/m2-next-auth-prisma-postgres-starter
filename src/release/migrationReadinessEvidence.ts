// Validates signed CI evidence that the application rollback phase completed.
import { createHmac, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';

import { MigrationReadinessError } from './migrationReadinessError';

export const ReleaseIdentifierSchema = z.string().regex(/^[a-f0-9]{40}$/);
export const AppRollbackEvidenceSchema = z.strictObject({
  phase: z.literal('app-rollback-complete'),
  runId: z.string().min(1),
  targetDatabase: z.string().min(1),
  fromRelease: ReleaseIdentifierSchema,
  toRelease: ReleaseIdentifierSchema,
  repositorySha: ReleaseIdentifierSchema,
  completedAt: z.iso.datetime(),
  signature: z.string().regex(/^[a-fA-F0-9]{64}$/),
});

type AppRollbackEvidence = z.infer<typeof AppRollbackEvidenceSchema>;
type EvidenceInput = Readonly<{
  appRollbackEvidence?: AppRollbackEvidence;
  appRollbackEvidenceSecret?: string;
}>;

const EVIDENCE_MAX_AGE_MS = 15 * 60 * 1_000;

function rollbackEvidencePayload(evidence: AppRollbackEvidence): string {
  return JSON.stringify({
    phase: evidence.phase,
    runId: evidence.runId,
    targetDatabase: evidence.targetDatabase,
    fromRelease: evidence.fromRelease.toLowerCase(),
    toRelease: evidence.toRelease.toLowerCase(),
    repositorySha: evidence.repositorySha.toLowerCase(),
    completedAt: evidence.completedAt,
  });
}

export function verifyRollbackEvidence(input: EvidenceInput, repositorySha: string): void {
  const evidence = input.appRollbackEvidence;
  const secret = input.appRollbackEvidenceSecret;
  if (evidence === undefined || secret === undefined) {
    throw new MigrationReadinessError('CI mode requires signed app rollback evidence');
  }
  if (evidence.repositorySha.toLowerCase() !== repositorySha.toLowerCase()) {
    throw new MigrationReadinessError('App rollback evidence does not match the current repository SHA');
  }
  const completedAt = Date.parse(evidence.completedAt);
  const now = Date.now();
  if (completedAt > now || now - completedAt > EVIDENCE_MAX_AGE_MS) {
    throw new MigrationReadinessError('App rollback evidence must be recent and not from the future');
  }
  const expected = createHmac('sha256', secret).update(rollbackEvidencePayload(evidence)).digest();
  const actual = Buffer.from(evidence.signature, 'hex');
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new MigrationReadinessError('App rollback evidence signature is invalid');
  }
}
