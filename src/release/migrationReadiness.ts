// Runs fail-closed, explicitly targeted Prisma migration readiness checks.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { z } from 'zod';

import {
  AppRollbackEvidenceSchema,
  ReleaseIdentifierSchema,
  verifyRollbackEvidence,
} from './migrationReadinessEvidence';
import {
  ADMIN_MFA_RELEASE_READINESS_SQL,
  EMPTY_DATABASE_SQL,
  MIGRATION_CHECKSUM_SQL,
  PRESERVATION_FIXTURE_SQL,
  PRESERVATION_SQL,
  TASK_016_CORRECTION_DIRECTORY,
  TASK_016_FOUNDATION_DIRECTORY,
  TASK_023_LINK_BINDING_DIRECTORY,
} from './migrationReadinessSql';
import { MigrationReadinessError } from './migrationReadinessError';

export { MigrationReadinessError } from './migrationReadinessError';
const RawInputSchema = z.strictObject({
  mode: z.enum(['ci', 'schema-rollback', 'live']),
  databaseUrl: z.string().min(1, 'An explicit database target is required'),
  confirmDatabase: z.string().min(1),
  shadowDatabaseUrl: z.string().min(1).optional(),
  runId: z.string().min(1).optional(),
  appRollbackEvidenceSecret: z.string().min(32).optional(),
  appRollbackEvidence: AppRollbackEvidenceSchema.optional(),
});

const DISPOSABLE_DATABASE = /(?:^|_)(?:ci|test|disposable)$/u;
const DISPOSABLE_SHADOW_DATABASE = /(?:^|_)(?:shadow|ci|test|disposable)$/u;

export const ROLLBACK_ORDER = ['app', 'schema'] as const;

export type MigrationReadinessInput = z.infer<typeof RawInputSchema>;
export type CommandResult = Readonly<{ exitCode: number; stdout: string; stderr: string }>;
export type CommandEnvironment = Readonly<Record<string, string>>;
export type CommandRunner = (
  command: string,
  args: readonly string[],
  environment?: CommandEnvironment,
) => Promise<CommandResult>;

function databaseName(databaseUrl: string): string {
  let url: URL;
  try {
    url = new URL(databaseUrl);
  } catch {
    throw new MigrationReadinessError('Database target must be a valid PostgreSQL URL');
  }
  if (url.protocol !== 'postgresql:' && url.protocol !== 'postgres:') {
    throw new MigrationReadinessError('Database target must use PostgreSQL');
  }
  const name = decodeURIComponent(url.pathname.replace(/^\//u, ''));
  if (name.length === 0) throw new MigrationReadinessError('Database target must name a database');
  return name;
}

function isLoopbackDisposable(databaseUrl: string, pattern = DISPOSABLE_DATABASE): boolean {
  const url = new URL(databaseUrl);
  const name = databaseName(databaseUrl);
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  return loopback && pattern.test(name);
}

function requireCanonicalDisposableUrl(databaseUrl: string): void {
  const url = new URL(databaseUrl);
  if (url.search.length > 0 || url.hash.length > 0) {
    throw new MigrationReadinessError(
      'CI mode database URLs must not contain query parameters or fragments',
    );
  }
}

export function parseMigrationReadinessInput(input: unknown): MigrationReadinessInput {
  const parsed = RawInputSchema.safeParse(input);
  if (!parsed.success) {
    const missingTarget = parsed.error.issues.some((issue) => issue.path[0] === 'databaseUrl');
    throw new MigrationReadinessError(
      missingTarget ? 'An explicit database target is required' : parsed.error.issues[0]?.message ?? 'Invalid input',
    );
  }
  const targetName = databaseName(parsed.data.databaseUrl);
  if (targetName !== parsed.data.confirmDatabase) {
    throw new MigrationReadinessError('Database confirmation does not match the explicit target');
  }
  if (parsed.data.mode !== 'live') {
    requireCanonicalDisposableUrl(parsed.data.databaseUrl);
    if (!isLoopbackDisposable(parsed.data.databaseUrl)) {
      throw new MigrationReadinessError('CI mode requires a loopback disposable database target');
    }
    if (parsed.data.shadowDatabaseUrl === undefined) {
      throw new MigrationReadinessError('CI mode requires an explicit shadow database target');
    }
    requireCanonicalDisposableUrl(parsed.data.shadowDatabaseUrl);
    if (
      !isLoopbackDisposable(parsed.data.shadowDatabaseUrl, DISPOSABLE_SHADOW_DATABASE)
      || databaseName(parsed.data.shadowDatabaseUrl) === targetName
    ) {
      throw new MigrationReadinessError('CI mode requires a distinct loopback disposable shadow database');
    }
    if (parsed.data.mode === 'schema-rollback') {
      const evidence = parsed.data.appRollbackEvidence;
      if (parsed.data.runId === undefined || evidence === undefined || evidence.runId !== parsed.data.runId) {
        throw new MigrationReadinessError('Schema rollback mode requires app rollback evidence for the current run');
      }
      if (parsed.data.appRollbackEvidenceSecret === undefined) {
        throw new MigrationReadinessError('Schema rollback mode requires an explicit app rollback evidence secret');
      }
      if (evidence.targetDatabase !== targetName) {
        throw new MigrationReadinessError('App rollback evidence does not match the explicit target');
      }
      if (evidence.fromRelease.toLowerCase() === evidence.toRelease.toLowerCase()) {
        throw new MigrationReadinessError('App rollback evidence must identify distinct releases');
      }
    }
  }
  return parsed.data;
}

async function requireSuccess(
  run: CommandRunner,
  command: string,
  args: readonly string[],
  message: string,
  environment?: CommandEnvironment,
): Promise<CommandResult> {
  const result = await run(command, args, environment);
  if (result.exitCode !== 0) throw new MigrationReadinessError(message);
  return result;
}

function prismaEnvironment(databaseUrl: string): CommandEnvironment {
  return { DATABASE_URL: databaseUrl };
}

async function psql(
  run: CommandRunner,
  databaseUrl: string,
  args: readonly string[],
  message: string,
): Promise<CommandResult> {
  return requireSuccess(
    run,
    'psql',
    ['--no-psqlrc', '--set', 'ON_ERROR_STOP=1', '--dbname', databaseUrl, ...args],
    message,
  );
}

async function verifyAdminMfaReleaseReadiness(run: CommandRunner, databaseUrl: string): Promise<void> {
  const result = await psql(run, databaseUrl, [
    '--tuples-only', '--no-align', '--command', ADMIN_MFA_RELEASE_READINESS_SQL,
  ], 'Unable to validate admin MFA release readiness');
  const fields = result.stdout.trim().split('\t');
  if (fields.length !== 2 || fields[0] !== '0' || fields[1] !== '0') {
    throw new MigrationReadinessError('Release requires zero invalid admins and zero legacy MFA exemptions');
  }
}

async function verifyAdminMfaKeyReadiness(run: CommandRunner, databaseUrl: string): Promise<void> {
  await requireSuccess(
    run,
    'pnpm',
    ['exec', 'tsx', 'scripts/admin-mfa-key-readiness.ts'],
    'Stored admin MFA key-version readiness failed',
    prismaEnvironment(databaseUrl),
  );
}

async function verifySchemaParity(
  run: CommandRunner,
  input: MigrationReadinessInput & Readonly<{ shadowDatabaseUrl: string }>,
): Promise<void> {
  await requireSuccess(run, 'pnpm', [
    'exec', 'prisma', 'migrate', 'diff', '--exit-code',
    '--from-migrations', 'prisma/migrations',
    '--to-schema-datamodel', 'prisma/schema.prisma',
    '--shadow-database-url', input.shadowDatabaseUrl,
  ], 'Committed migration history does not match the current Prisma schema', prismaEnvironment(input.databaseUrl));
  await requireSuccess(run, 'pnpm', [
    'exec', 'prisma', 'migrate', 'diff', '--exit-code',
    '--from-url', input.databaseUrl,
    '--to-schema-datamodel', 'prisma/schema.prisma',
  ], 'Current database does not match the expected Prisma schema', prismaEnvironment(input.databaseUrl));
}

async function runCiReadiness(
  run: CommandRunner,
  input: MigrationReadinessInput & Readonly<{ shadowDatabaseUrl: string }>,
): Promise<void> {
  const empty = await psql(
    run,
    input.databaseUrl,
    ['--tuples-only', '--command', EMPTY_DATABASE_SQL],
    'Unable to verify that the disposable database is empty',
  );
  const objectCount = empty.stdout.trim();
  if (!/^\d+$/u.test(objectCount)) {
    throw new MigrationReadinessError('Unable to prove that the disposable database schema is empty');
  }
  if (objectCount !== '0') {
    throw new MigrationReadinessError('Disposable database must be empty before migration apply');
  }
  await requireSuccess(
    run,
    'pnpm',
    ['exec', 'prisma', 'migrate', 'deploy'],
    'Clean migration apply failed',
    prismaEnvironment(input.databaseUrl),
  );
  await requireSuccess(
    run,
    'pnpm',
    ['exec', 'prisma', 'migrate', 'status'],
    'Prisma migration status is pending, failed, or otherwise not clean',
    prismaEnvironment(input.databaseUrl),
  );
  await verifySchemaParity(run, input);
  await verifyMigrationChecksums(run, input.databaseUrl);
  await verifyAdminMfaReleaseReadiness(run, input.databaseUrl);
  await verifyAdminMfaKeyReadiness(run, input.databaseUrl);
  await psql(
    run,
    input.databaseUrl,
    ['--command', PRESERVATION_FIXTURE_SQL],
    'Unable to create disposable rollback preservation fixtures',
  );
  const before = await psql(run, input.databaseUrl, ['--tuples-only', '--command', PRESERVATION_SQL], 'Unable to capture rollback preservation state');
  await psql(run, input.databaseUrl, ['--file', `${TASK_023_LINK_BINDING_DIRECTORY}/down.sql`], 'TASK-023 link binding down migration failed');
  await psql(run, input.databaseUrl, ['--file', `${TASK_016_CORRECTION_DIRECTORY}/down.sql`], 'TASK-016 correction down migration failed');
  await psql(run, input.databaseUrl, ['--file', `${TASK_016_FOUNDATION_DIRECTORY}/down.sql`], 'TASK-016 foundation down migration failed');
  await psql(run, input.databaseUrl, ['--file', `${TASK_016_FOUNDATION_DIRECTORY}/migration.sql`], 'TASK-016 foundation re-apply failed');
  await psql(run, input.databaseUrl, ['--file', `${TASK_016_CORRECTION_DIRECTORY}/migration.sql`], 'TASK-016 correction re-apply failed');
  await psql(run, input.databaseUrl, ['--file', `${TASK_023_LINK_BINDING_DIRECTORY}/migration.sql`], 'TASK-023 link binding re-apply failed');
  const after = await psql(run, input.databaseUrl, ['--tuples-only', '--command', PRESERVATION_SQL], 'Unable to verify rollback preservation state');
  if (before.stdout.trim() !== after.stdout.trim()) {
    throw new MigrationReadinessError('TASK-016 up/down/up did not preserve core identity state');
  }
  await verifySchemaParity(run, input);
  await requireSuccess(
    run,
    'pnpm',
    ['exec', 'prisma', 'migrate', 'status'],
    'Prisma migration history is not clean after TASK-016 up/down/up',
    prismaEnvironment(input.databaseUrl),
  );
}

async function committedMigrationChecksums(run: CommandRunner): Promise<Map<string, string>> {
  const tracked = await requireSuccess(
    run,
    'git',
    ['ls-files', '--', 'prisma/migrations/*/migration.sql'],
    'Unable to enumerate committed migration files',
  );
  const checksums = new Map<string, string>();
  for (const path of tracked.stdout.split('\n').map((line) => line.trim()).filter(Boolean)) {
    const segments = path.split('/');
    const migrationName = segments.at(-2);
    if (migrationName === undefined || checksums.has(migrationName)) {
      throw new MigrationReadinessError('Committed migration file layout is invalid');
    }
    const contents = await readFile(path);
    checksums.set(migrationName, createHash('sha256').update(contents).digest('hex'));
  }
  return checksums;
}

async function verifyMigrationChecksums(run: CommandRunner, databaseUrl: string): Promise<void> {
  const expected = await committedMigrationChecksums(run);
  const result = await psql(
    run,
    databaseUrl,
    ['--tuples-only', '--no-align', '--command', MIGRATION_CHECKSUM_SQL],
    'Unable to inspect applied migration checksums',
  );
  const actual = new Map<string, string>();
  for (const row of result.stdout.split('\n').map((line) => line.trim()).filter(Boolean)) {
    const fields = row.split('\t');
    const name = fields[0];
    const checksum = fields[1];
    if (fields.length !== 2 || name === undefined || checksum === undefined || actual.has(name)) {
      throw new MigrationReadinessError('Applied migration checksum metadata is malformed');
    }
    actual.set(name, checksum);
  }
  const matches = expected.size === actual.size && [...expected].every(
    ([name, checksum]) => actual.get(name) === checksum,
  );
  if (!matches) {
    throw new MigrationReadinessError('Applied migration checksums do not match committed migration files');
  }
}

export async function runMigrationReadiness(
  rawInput: unknown,
  run: CommandRunner,
): Promise<
  | Readonly<{ mode: 'schema-rollback' | 'live'; rollbackOrder: typeof ROLLBACK_ORDER }>
  | Readonly<{
    mode: 'ci';
    schemaExercise: 'committed-down-up';
    productionRollbackEvidence: false;
  }>
> {
  const input = parseMigrationReadinessInput(rawInput);
  const git = await requireSuccess(
    run,
    'git',
    ['status', '--porcelain', '--untracked-files=all', '--', 'prisma/schema.prisma', 'prisma/migrations'],
    'Unable to inspect migration repository state',
  );
  if (git.stdout.trim().length > 0) {
    throw new MigrationReadinessError('Migration files must be committed and unchanged');
  }
  const repository = await requireSuccess(
    run,
    'git',
    ['rev-parse', 'HEAD'],
    'Unable to identify the current repository SHA',
  );
  const repositorySha = repository.stdout.trim();
  if (!ReleaseIdentifierSchema.safeParse(repositorySha).success) {
    throw new MigrationReadinessError('Current repository SHA is not a full Git SHA');
  }
  if (input.mode === 'schema-rollback') verifyRollbackEvidence(input, repositorySha);
  await requireSuccess(
    run,
    'pnpm',
    ['exec', 'prisma', 'validate'],
    'Prisma schema validation failed',
    prismaEnvironment(input.databaseUrl),
  );
  if (input.mode !== 'live') {
    if (input.shadowDatabaseUrl === undefined) throw new MigrationReadinessError('CI shadow target is required');
    await runCiReadiness(run, { ...input, shadowDatabaseUrl: input.shadowDatabaseUrl });
  } else {
    await requireSuccess(
      run,
      'pnpm',
      ['exec', 'prisma', 'migrate', 'status'],
      'Prisma migration status is pending, failed, or otherwise not clean',
      prismaEnvironment(input.databaseUrl),
    );
    await verifyAdminMfaReleaseReadiness(run, input.databaseUrl);
    await verifyAdminMfaKeyReadiness(run, input.databaseUrl);
  }
  if (input.mode === 'ci') {
    return {
      mode: input.mode,
      schemaExercise: 'committed-down-up',
      productionRollbackEvidence: false,
    };
  }
  return { mode: input.mode, rollbackOrder: ROLLBACK_ORDER };
}
