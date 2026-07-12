// gated-registration-schema.test.ts - Packet 02 schema and migration invariants.
import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'fs';
import { join, resolve } from 'path';

const ROOT = resolve(import.meta.dirname, '..');
const MIGRATION_SUFFIX = '_gated_registration_foundation';
const CORRECTION_MIGRATION = '20260712180000_gated_registration_invariant_correction';

type PrismaBlockType = 'enum' | 'model';

function readProjectFile(pathParts: string[]): string {
  return readFileSync(join(ROOT, ...pathParts), 'utf8');
}

function readSchema(): string {
  return readProjectFile(['prisma', 'schema.prisma']);
}

function readPrismaBlock(blockType: PrismaBlockType, blockName: string): string {
  const pattern = new RegExp(`${blockType}\\s+${blockName}\\s*\\{[\\s\\S]*?\\n\\}`);
  const match = pattern.exec(readSchema());
  expect(match, `Expected ${blockType} ${blockName} in schema.prisma`).not.toBeNull();
  return match?.[0] ?? '';
}

function findGatedMigrationDir(): string | null {
  const migrationsRoot = join(ROOT, 'prisma', 'migrations');
  const matches = readdirSync(migrationsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((name) => name.endsWith(MIGRATION_SUFFIX))
    .sort();

  return matches.at(-1) ?? null;
}

function readMigrationFile(filename: 'migration.sql' | 'down.sql'): string {
  const migrationDir = findGatedMigrationDir();
  expect(
    migrationDir,
    `Expected a prisma/migrations/*${MIGRATION_SUFFIX} directory`,
  ).not.toBeNull();

  if (migrationDir === null) {
    return '';
  }

  const filePath = join(ROOT, 'prisma', 'migrations', migrationDir, filename);
  expect(existsSync(filePath), `Expected ${filename} in ${migrationDir}`).toBe(true);
  return readFileSync(filePath, 'utf8');
}

function readCorrectionMigration(filename: 'migration.sql' | 'down.sql'): string {
  return readProjectFile(['prisma', 'migrations', CORRECTION_MIGRATION, filename]);
}

function expectBlockMatches(blockType: PrismaBlockType, blockName: string, pattern: RegExp, message: string): void {
  const block = readPrismaBlock(blockType, blockName);
  expect(block, message).toMatch(pattern);
}

function expectMigrationContains(expected: string): void {
  const migrationSql = readMigrationFile('migration.sql');
  expect(migrationSql).toContain(expected);
}

describe('Packet 02 gated registration schema foundation', () => {
  it('enforces one verification token per identifier', () => {
    expect(readPrismaBlock('model', 'VerificationToken')).toMatch(/identifier\s+String\s+@unique/);
    expect(readCorrectionMigration('migration.sql')).toContain(
      'CREATE UNIQUE INDEX "verification_tokens_identifier_key"',
    );
  });
  it('D1-01 models case-insensitive unique user email', () => {
    expectBlockMatches(
      'model',
      'User',
      /email\s+String\s+(?=.*@unique)(?=.*@db\.Citext)/,
      'User.email must stay unique and use citext for case-insensitive matching',
    );
    expectMigrationContains('CREATE EXTENSION IF NOT EXISTS "citext";');
    expectMigrationContains('ALTER COLUMN "email" TYPE CITEXT');
  });

  it('D1-02 models invite status and database integrity constraints', () => {
    expectBlockMatches('enum', 'InviteStatus', /ISSUED[\s\S]*REDEEMED[\s\S]*REVOKED/, 'InviteStatus must model issued, redeemed, and revoked only');
    expect(readPrismaBlock('enum', 'InviteStatus')).not.toContain('EXPIRED');
    expectBlockMatches(
      'model',
      'Invite',
      /tokenHash\s+Bytes[\s\S]*expiresAt\s+DateTime[\s\S]*redeemedByUserId\s+String\?/, 
      'Invite must store token hash, expiry, and redemption identity',
    );
    expectMigrationContains('chk_invite_redeemed_binding');
    expectMigrationContains('chk_invite_revoked_binding');
    expect(readCorrectionMigration('migration.sql')).toContain(
      'CONSTRAINT "chk_invites_token_hash_length"',
    );
    expect(readCorrectionMigration('migration.sql')).toContain(
      'CHECK (octet_length("tokenHash") = 32)',
    );
  });

  it('D1-04 models deduplicated outbox email with ciphertext clearing guard', () => {
    expectBlockMatches(
      'model',
      'OutboxEmail',
      /dedupId\s+String\s+@unique[\s\S]*inviteCiphertext\s+Bytes\?[\s\S]*clearedAt\s+DateTime\?/,
      'OutboxEmail must deduplicate and track invite payload clearing',
    );
    expect(readSchema()).not.toContain('dedupKey');
    expect(readSchema()).not.toContain('ciphertext      Bytes?');
    expectBlockMatches(
      'model',
      'OutboxEmail',
      /claimToken\s+String\?[\s\S]*leaseExpiresAt\s+DateTime\?[\s\S]*nextAttemptAt\s+DateTime\?[\s\S]*failedAt\s+DateTime\?/,
      'OutboxEmail must expose TASK-018 lease, fencing, retry, and terminal failure fields',
    );
    expectMigrationContains('chk_outbox_email_ciphertext_clear');
    expectMigrationContains('outbox_emails_status_availableAt_idx');
    expectMigrationContains('outbox_emails_status_nextAttemptAt_idx');
    expectMigrationContains('outbox_emails_leaseExpiresAt_idx');
    expectMigrationContains('"claimToken" TEXT');
    expectMigrationContains('"leaseExpiresAt" TIMESTAMP(3)');
    expectMigrationContains('"nextAttemptAt" TIMESTAMP(3)');
    expectMigrationContains('"failedAt" TIMESTAMP(3)');
    expectMigrationContains('"inviteCiphertext" BYTEA');
    expectMigrationContains('outbox_emails_dedupId_key');
  });

  it('D1-06 keeps audit events insert-only at the database layer', () => {
    expectBlockMatches(
      'model',
      'AuditEvent',
      /action\s+String[\s\S]*metadata\s+Json\?/, 
      'AuditEvent must capture immutable audit metadata',
    );
    expectMigrationContains('audit_events_immutable');
    expectMigrationContains('BEFORE UPDATE OR DELETE ON "public"."audit_events"');
    expectMigrationContains('RAISE EXCEPTION');
  });

  it('D1-07 models registration sessions with one-use consumption shape', () => {
    expectBlockMatches(
      'enum',
      'RegistrationSessionStatus',
      /PENDING[\s\S]*CONSUMED[\s\S]*DECOY/,
      'RegistrationSessionStatus must include pending, consumed, and decoy',
    );
    expectBlockMatches(
      'model',
      'RegistrationSession',
      /handleHash\s+Bytes\s+@unique[\s\S]*inviteTokenHash\s+Bytes\?[\s\S]*nonce\s+Bytes[\s\S]*consumedAt\s+DateTime\?/, 
      'RegistrationSession must support decoy refs with nullable inviteTokenHash and a nonce',
    );
    expectBlockMatches(
      'model',
      'RegistrationSession',
      /@@index\(\[expiresAt\]\)[\s\S]*@@index\(\[inviteTokenHash\]\)/,
      'RegistrationSession must expose cleanup and token-resolution indexes',
    );
    expectMigrationContains('chk_registration_sessions_consumption');
    expectMigrationContains('"inviteTokenHash" BYTEA,');
    expectMigrationContains('"nonce" BYTEA NOT NULL');
    expectMigrationContains('registration_sessions_expiresAt_idx');
    expectMigrationContains('registration_sessions_inviteTokenHash_idx');
    expect(readMigrationFile('migration.sql')).not.toContain('registration_sessions_pending_expiry_idx');
    expect(readMigrationFile('migration.sql')).not.toContain('registration_sessions_nonceHash_key');
  });

  it('D1-08 scopes activation to credential-backed accounts only', () => {
    expectBlockMatches('enum', 'AccountStatus', /INACTIVE[\s\S]*ACTIVE[\s\S]*SUSPENDED[\s\S]*DELETED/, 'AccountStatus must include inactive, active, suspended, and deleted');
    expectBlockMatches('model', 'User', /status\s+AccountStatus\s+@default\(INACTIVE\)/, 'New users must default to INACTIVE');
    expectBlockMatches('model', 'User', /passwordHash\s+String\?/, 'User.passwordHash must be nullable during rollout');
    expectBlockMatches('model', 'User', /hasPasswordCredential\s+Boolean\s+@default\(false\)/, 'Credential state must be explicit');
    expectMigrationContains('chk_user_active_credential_binding');
    expectMigrationContains('UPDATE "public"."users"');
  });

  it('D2-01 models admin MFA factors and excludes step-up challenge state', () => {
    expectBlockMatches('enum', 'AdminMfaKind', /TOTP[\s\S]*WEBAUTHN/, 'Admin MFA must support TOTP and WebAuthn factors');
    expectBlockMatches('enum', 'AdminMfaStatus', /PENDING[\s\S]*ACTIVE[\s\S]*REVOKED/, 'Admin MFA factors must have lifecycle status');
    const adminMfaFactor = readPrismaBlock('model', 'AdminMfaFactor');
    expect(adminMfaFactor).toMatch(/secretCipher\s+Bytes[\s\S]*keyVersion\s+Int/);
    expect(adminMfaFactor).toContain('ADMIN_MFA_SECRET_ENCRYPTION_KEYS');
    expect(adminMfaFactor).toContain('ADMIN_MFA_SECRET_KEY_VERSION');
    expect(adminMfaFactor).not.toContain('secretCiphertext');
    expect(adminMfaFactor).not.toContain('lastStrongAuthAt');
    expectMigrationContains('"secretCipher" BYTEA NOT NULL');
    expectBlockMatches('model', 'User', /mfaEnrolledAt\s+DateTime\?/, 'User must expose admin MFA posture marker');
    expectBlockMatches('model', 'User', /lastStrongAuthAt\s+DateTime\?/, 'User must expose freshness marker');
    expectBlockMatches('model', 'User', /sessionVersion\s+Int\s+@default\(0\)/, 'User must support session invalidation versioning');
    expect(readSchema()).not.toContain('AdminStepUpChallenge');
    const correction = readCorrectionMigration('migration.sql');
    expect(correction).toContain('CREATE CONSTRAINT TRIGGER "users_admin_mfa_capability"');
    expect(correction).toContain('CREATE CONSTRAINT TRIGGER "admin_mfa_factors_admin_capability"');
    expect(correction).toContain('DEFERRABLE INITIALLY DEFERRED');
    expect(correction).toContain("candidate.\"role\" = 'ADMIN'");
    expect(correction).toContain('candidate."mfaEnrolledAt" IS NULL');
    expect(correction).toContain("factor.\"status\" = 'ACTIVE'");
    expect(correction).toContain("CONSTRAINT = 'chk_admin_mfa_capability'");
    expect(readPrismaBlock('model', 'AdminCapabilityGrant')).toMatch(/userId\s+String[\s\S]*capability\s+String[\s\S]*revokedAt\s+DateTime\?/);
    expect(correction).toContain('admin_capability_grants_active_unique');
    expect(correction).toContain('admin_mfa_factors_one_pending_totp_per_user');
    expect(correction).toContain('"lastUsedStep" BIGINT');
    expect(correction).toContain('CREATE TRIGGER "admin_mfa_legacy_exemptions_immutable"');
    expect(correction).toContain('BEFORE INSERT OR UPDATE ON "public"."admin_mfa_legacy_exemptions"');
    expect(correction).toContain('REVOKE INSERT, UPDATE, TRUNCATE');
  });

  it('provides an explicit reversible down migration', () => {
    const downSql = readMigrationFile('down.sql');
    expect(downSql).toContain('DROP TRIGGER IF EXISTS "audit_events_immutable"');
    expect(downSql).toContain('DROP TABLE IF EXISTS "public"."admin_mfa_factors"');
    expect(downSql).toContain('DROP TABLE IF EXISTS "public"."registration_sessions"');
    expect(downSql).toContain('DROP TYPE IF EXISTS "public"."AccountStatus"');
    const correctionDown = readCorrectionMigration('down.sql');
    expect(correctionDown).toContain('DROP TRIGGER IF EXISTS "admin_mfa_factors_admin_capability"');
    expect(correctionDown).toContain('DROP TRIGGER IF EXISTS "users_admin_mfa_capability"');
    expect(correctionDown).toContain('DROP CONSTRAINT IF EXISTS "chk_invites_token_hash_length"');
    expect(correctionDown).toContain('DROP TABLE IF EXISTS "public"."admin_capability_grants"');
    expect(correctionDown).toContain('DROP TRIGGER IF EXISTS "admin_mfa_legacy_exemptions_immutable"');
    expect(correctionDown).toContain('DROP FUNCTION IF EXISTS "public"."reject_admin_mfa_legacy_exemption_mutation"');
    expect(correctionDown).toContain('DROP COLUMN IF EXISTS "lastUsedStep"');
  });
});
