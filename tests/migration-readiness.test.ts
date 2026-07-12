// Verifies fail-closed Prisma migration readiness without contacting a database.
import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  MigrationReadinessError,
  parseMigrationReadinessInput,
  runMigrationReadiness,
} from '@/release/migrationReadiness';
import { runMigrationReadinessCli } from '../scripts/migration-readiness';

type CommandResult = Readonly<{ exitCode: number; stdout: string; stderr: string }>;
type CommandCall = Readonly<{
  command: string;
  args: readonly string[];
  environment?: Readonly<Record<string, string>>;
}>;

function successfulResult(stdout = ''): CommandResult {
  return { exitCode: 0, stdout, stderr: '' };
}

function createRunner(results: readonly CommandResult[] = []) {
  const calls: CommandCall[] = [];
  let configuredResultIndex = 0;
  return {
    calls,
    run: async (
      command: string,
      args: readonly string[],
      environment?: Readonly<Record<string, string>>,
    ): Promise<CommandResult> => {
      calls.push({ command, args, ...(environment === undefined ? {} : { environment }) });
      if (command === 'git' && args[0] === 'rev-parse') {
        return successfulResult(`${CURRENT_REPOSITORY_SHA}\n`);
      }
      const configured = results[configuredResultIndex];
      configuredResultIndex += 1;
      if (configured !== undefined) return configured;
      if (command === 'psql' && args.some((arg) => arg.includes('pg_class'))) {
        return successfulResult('0');
      }
      if (command === 'psql' && args.some((arg) => arg.includes('admin_mfa_legacy_exemptions'))) {
        return successfulResult('0\t0');
      }
      return successfulResult();
    },
  };
}

const CURRENT_REPOSITORY_SHA = '3333333333333333333333333333333333333333';
const EVIDENCE_SECRET = 'task032-ci-only-evidence-secret-32-characters';
const completedAt = new Date().toISOString();
const unsignedEvidence = {
  phase: 'app-rollback-complete',
  runId: 'task032-run-001',
  targetDatabase: 'auth_ci',
  fromRelease: '1111111111111111111111111111111111111111',
  toRelease: '2222222222222222222222222222222222222222',
  repositorySha: CURRENT_REPOSITORY_SHA,
  completedAt,
} as const;
function signEvidence(evidence: typeof unsignedEvidence): string {
  return createHmac('sha256', EVIDENCE_SECRET).update(JSON.stringify(evidence)).digest('hex');
}
const signature = signEvidence(unsignedEvidence);
const SCHEMA_ROLLBACK_INPUT = {
  mode: 'schema-rollback',
  databaseUrl: 'postgresql://postgres:postgres@localhost:5432/auth_ci',
  confirmDatabase: 'auth_ci',
  shadowDatabaseUrl: 'postgresql://postgres:postgres@localhost:5432/auth_shadow',
  runId: 'task032-run-001',
  appRollbackEvidenceSecret: EVIDENCE_SECRET,
  appRollbackEvidence: { ...unsignedEvidence, signature },
} as const;
const CI_INPUT = {
  mode: 'ci',
  databaseUrl: SCHEMA_ROLLBACK_INPUT.databaseUrl,
  confirmDatabase: SCHEMA_ROLLBACK_INPUT.confirmDatabase,
  shadowDatabaseUrl: SCHEMA_ROLLBACK_INPUT.shadowDatabaseUrl,
} as const;

describe('migration readiness target protection', () => {
  it('requires an explicit database URL instead of inferring DATABASE_URL', () => {
    expect(() => parseMigrationReadinessInput({ mode: 'live', confirmDatabase: 'app' }))
      .toThrow('An explicit database target is required');
  });

  it('rejects a mismatched database confirmation', () => {
    expect(() => parseMigrationReadinessInput({
      mode: 'live',
      databaseUrl: 'postgresql://localhost/app',
      confirmDatabase: 'production',
    })).toThrow('Database confirmation does not match the explicit target');
  });

  it('restricts CI mode to a loopback disposable database', () => {
    expect(() => parseMigrationReadinessInput({
      ...SCHEMA_ROLLBACK_INPUT,
      databaseUrl: 'postgresql://db.example.com/production',
      confirmDatabase: 'production',
    })).toThrow('CI mode requires a loopback disposable database target');
  });

  it('rejects a shared or non-disposable shadow database', () => {
    expect(() => parseMigrationReadinessInput({
      ...SCHEMA_ROLLBACK_INPUT,
      shadowDatabaseUrl: 'postgresql://db.example.com/production',
    })).toThrow('CI mode requires a distinct loopback disposable shadow database');
  });

  it.each(['host', 'hostaddr', 'service', 'options'])(
    'rejects destructive CI URLs containing the %s routing parameter',
    (parameter) => {
      expect(() => parseMigrationReadinessInput({
        ...SCHEMA_ROLLBACK_INPUT,
        databaseUrl: `postgresql://postgres:postgres@localhost:5432/auth_ci?${parameter}=remote.example`,
      })).toThrow('CI mode database URLs must not contain query parameters or fragments');
    },
  );

  it('rejects fragments but accepts canonical disposable PostgreSQL URLs', () => {
    expect(() => parseMigrationReadinessInput({
      ...SCHEMA_ROLLBACK_INPUT,
      databaseUrl: `${SCHEMA_ROLLBACK_INPUT.databaseUrl}#unsafe-routing-data`,
    })).toThrow('CI mode database URLs must not contain query parameters or fragments');

    expect(parseMigrationReadinessInput(CI_INPUT).databaseUrl).toBe(CI_INPUT.databaseUrl);
  });

  it('rejects missing or mismatched app rollback evidence before commands run', async () => {
    const runner = createRunner();
    const { appRollbackEvidence: _omitted, ...withoutEvidence } = SCHEMA_ROLLBACK_INPUT;
    await expect(runMigrationReadiness(withoutEvidence, runner.run)).rejects.toThrow(
      'Schema rollback mode requires app rollback evidence for the current run',
    );
    await expect(runMigrationReadiness({
      ...SCHEMA_ROLLBACK_INPUT,
      appRollbackEvidence: { ...SCHEMA_ROLLBACK_INPUT.appRollbackEvidence, targetDatabase: 'other_ci' },
    }, runner.run)).rejects.toThrow('App rollback evidence does not match the explicit target');
    expect(runner.calls).toHaveLength(0);
  });

  it.each([
    ['invalid signature', { signature: '0'.repeat(64) }],
    ['wrong repository', { repositorySha: '4444444444444444444444444444444444444444' }],
  ])('rejects signed evidence with %s before any down migration', async (_case, override) => {
    const runner = createRunner();
    await expect(runMigrationReadiness({
      ...SCHEMA_ROLLBACK_INPUT,
      appRollbackEvidence: { ...SCHEMA_ROLLBACK_INPUT.appRollbackEvidence, ...override },
    }, runner.run)).rejects.toBeInstanceOf(MigrationReadinessError);
    expect(runner.calls.some((call) => call.args.some((arg) => arg.includes('/down.sql')))).toBe(false);
  });

  it.each([
    ['stale', new Date(Date.now() - 16 * 60 * 1_000).toISOString()],
    ['future', new Date(Date.now() + 60_000).toISOString()],
  ])('rejects %s rollback evidence even when correctly signed', async (_case, timestamp) => {
    const evidence = { ...unsignedEvidence, completedAt: timestamp };
    const runner = createRunner();
    await expect(runMigrationReadiness({
      ...SCHEMA_ROLLBACK_INPUT,
      appRollbackEvidence: { ...evidence, signature: signEvidence(evidence) },
    }, runner.run)).rejects.toThrow('App rollback evidence must be recent and not from the future');
    expect(runner.calls.some((call) => call.args.some((arg) => arg.includes('/down.sql')))).toBe(false);
  });

  it.each(['fromRelease', 'toRelease', 'repositorySha'] as const)(
    'rejects uppercase %s values to keep the signed payload canonical',
    (field) => {
      expect(() => parseMigrationReadinessInput({
        ...SCHEMA_ROLLBACK_INPUT,
        appRollbackEvidence: {
          ...SCHEMA_ROLLBACK_INPUT.appRollbackEvidence,
          [field]: 'A'.repeat(40),
        },
      })).toThrow();
    },
  );
});

describe('migration readiness repository gate', () => {
  it.each([
    ['modified', ' M prisma/migrations/20260620173500_gated_registration_foundation/migration.sql'],
    ['untracked', '?? prisma/migrations/new/migration.sql'],
  ])('rejects %s migration state', async (_state, gitStatus) => {
    const runner = createRunner([successfulResult(gitStatus)]);

    await expect(runMigrationReadiness(SCHEMA_ROLLBACK_INPUT, runner.run)).rejects.toThrow(
      'Migration files must be committed and unchanged',
    );
    expect(runner.calls).toHaveLength(1);
  });

  it.each(['pending', 'failed'])('rejects %s Prisma migration status', async (state) => {
    const runner = createRunner([
      successfulResult(),
      successfulResult(),
      { exitCode: 1, stdout: `Migration status is ${state}: 20260620173500`, stderr: '' },
    ]);

    await expect(runMigrationReadiness({
      mode: 'live',
      databaseUrl: 'postgresql://db.example.com/app',
      confirmDatabase: 'app',
    }, runner.run)).rejects.toBeInstanceOf(MigrationReadinessError);
    expect(runner.calls.some((call) => call.args.includes('deploy'))).toBe(false);
  });
});

describe('migration readiness execution modes', () => {
  it('runs disposable down/up rehearsal without accepting or claiming app rollback evidence', async () => {
    const runner = createRunner();

    const result = await runMigrationReadiness(CI_INPUT, runner.run);

    expect(result).toEqual({
      mode: 'ci',
      schemaExercise: 'committed-down-up',
      productionRollbackEvidence: false,
    });
    expect(runner.calls.some((call) => call.args.some((arg) => arg.includes('/down.sql')))).toBe(true);
  });

  it('keeps live mode read-only', async () => {
    const runner = createRunner();

    const result = await runMigrationReadiness({
      mode: 'live',
      databaseUrl: 'postgresql://db.example.com/app',
      confirmDatabase: 'app',
    }, runner.run);

    expect(result).toEqual({ mode: 'live', rollbackOrder: ['app', 'schema'] });
    expect(runner.calls.map((call) => [call.command, ...call.args].join(' '))).toEqual([
      'git status --porcelain --untracked-files=all -- prisma/schema.prisma prisma/migrations',
      'git rev-parse HEAD',
      'pnpm exec prisma validate',
      'pnpm exec prisma migrate status',
      expect.stringContaining('admin_mfa_legacy_exemptions'),
      'pnpm exec tsx scripts/admin-mfa-key-readiness.ts',
    ]);
  });

  it('blocks release readiness while invalid admins or legacy exemptions remain', async () => {
    const runner = createRunner();
    const baseRun = runner.run;
    const run = async (command: string, args: readonly string[], environment?: Readonly<Record<string, string>>) => {
      if (command === 'psql' && args.some((arg) => arg.includes('admin_mfa_legacy_exemptions'))) {
        return successfulResult('1\t1');
      }
      return baseRun(command, args, environment);
    };
    await expect(runMigrationReadiness({
      mode: 'live', databaseUrl: 'postgresql://db.example.com/app', confirmDatabase: 'app',
    }, run)).rejects.toThrow('zero invalid admins and zero legacy MFA exemptions');
  });

  it('runs clean apply and the authoritative TASK-016 up/down/up cycle in schema rollback mode', async () => {
    const runner = createRunner();

    await runMigrationReadiness(SCHEMA_ROLLBACK_INPUT, runner.run);

    const commands = runner.calls.map((call) => [call.command, ...call.args].join(' '));
    expect(commands).toEqual(expect.arrayContaining([
      expect.stringContaining("--command SELECT ("),
      'pnpm exec prisma migrate deploy',
      'pnpm exec prisma migrate status',
      expect.stringContaining('prisma migrate diff --exit-code'),
      expect.stringContaining('--from-url postgresql://postgres:postgres@localhost:5432/auth_ci'),
      expect.stringContaining("INSERT INTO public.users"),
      expect.stringContaining("INSERT INTO public.oauth_authorization_codes"),
      expect.stringContaining("'oauth_clients'"),
      expect.stringContaining('"clientSecretHash"'),
      expect.stringContaining('--file prisma/migrations/20260620173500_gated_registration_foundation/down.sql'),
      expect.stringContaining('--file prisma/migrations/20260620173500_gated_registration_foundation/migration.sql'),
      expect.stringContaining('--file prisma/migrations/20260712180000_gated_registration_invariant_correction/down.sql'),
      expect.stringContaining('--file prisma/migrations/20260712180000_gated_registration_invariant_correction/migration.sql'),
      expect.stringContaining('--file prisma/migrations/20260712210000_account_link_session_binding/down.sql'),
      expect.stringContaining('--file prisma/migrations/20260712210000_account_link_session_binding/migration.sql'),
      'pnpm exec prisma migrate status',
    ]));
    expect(commands.indexOf('pnpm exec prisma migrate deploy')).toBeLessThan(
      commands.findIndex((command) => command.includes('/down.sql')),
    );
    expect(commands.findIndex((command) => command.includes('invariant_correction/down.sql'))).toBeLessThan(
      commands.findIndex((command) => command.includes('foundation/down.sql')),
    );
    expect(commands.findIndex((command) => command.includes('account_link_session_binding/down.sql'))).toBeLessThan(
      commands.findIndex((command) => command.includes('invariant_correction/down.sql')),
    );
    expect(commands.findIndex((command) => command.includes('foundation/migration.sql'))).toBeLessThan(
      commands.findIndex((command) => command.includes('invariant_correction/migration.sql')),
    );
    const lastParityIndex = commands.reduce(
      (latest, command, index) => command.includes('migrate diff --exit-code') ? index : latest,
      -1,
    );
    expect(lastParityIndex).toBeGreaterThan(
      commands.findIndex((command) => command.includes('/migration.sql')),
    );
    expect(commands.at(-1)).toBe('pnpm exec prisma migrate status');
    const prismaCalls = runner.calls.filter((call) => call.command === 'pnpm');
    expect(prismaCalls.every(
      (call) => call.environment?.DATABASE_URL === SCHEMA_ROLLBACK_INPUT.databaseUrl,
    )).toBe(true);
    const psqlCalls = runner.calls.filter((call) => call.command === 'psql');
    expect(psqlCalls.every((call) => {
      const databaseFlag = call.args.indexOf('--dbname');
      return call.args[databaseFlag + 1] === SCHEMA_ROLLBACK_INPUT.databaseUrl;
    })).toBe(true);
  });

  it('rejects a CI target that is not empty before applying migrations', async () => {
    const runner = createRunner([
      successfulResult(),
      successfulResult(),
      successfulResult('1'),
    ]);

    await expect(runMigrationReadiness(SCHEMA_ROLLBACK_INPUT, runner.run)).rejects.toThrow(
      'Disposable database must be empty before migration apply',
    );
    expect(runner.calls.some((call) => call.args.includes('deploy'))).toBe(false);
  });

  it('counts all relation classes and additional user-created public objects before apply', async () => {
    const runner = createRunner();
    await runMigrationReadiness(SCHEMA_ROLLBACK_INPUT, runner.run);
    const emptySchemaCall = runner.calls.find(
      (call) => call.command === 'psql' && call.args.some((arg) => arg.includes('pg_class')),
    );
    const sql = emptySchemaCall?.args.find((arg) => arg.includes('pg_class')) ?? '';
    expect(sql).toContain("c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f', 'i', 'I', 'c')");
    expect(sql).toContain('FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace');
    expect(sql).not.toContain("t.typtype IN ('e', 'd')");
    expect(sql).toContain('pg_collation');
    expect(sql).toContain('pg_conversion');
    expect(sql).toContain('pg_operator');
    expect(sql).toContain('pg_ts_config');
  });

  it.each(['', 'not-a-count', '0\t0\t0'])('rejects inconclusive empty-schema output %j', async (stdout) => {
    const runner = createRunner([
      successfulResult(),
      successfulResult(),
      successfulResult(stdout),
    ]);
    await expect(runMigrationReadiness(SCHEMA_ROLLBACK_INPUT, runner.run)).rejects.toThrow(
      'Unable to prove that the disposable database schema is empty',
    );
  });

  it.each([
    ['missing', ''],
    ['extra', '20251003141621_\twrong-checksum\nextra_migration\textra-checksum'],
    ['mismatched', '20251003141621_\twrong-checksum'],
  ])('never runs down.sql when applied migration checksums are %s', async (_state, databaseRows) => {
    const runner = createRunner([
      successfulResult(), successfulResult(), successfulResult('0'),
      successfulResult(), successfulResult(), successfulResult(), successfulResult(),
      successfulResult('prisma/migrations/20251003141621_/migration.sql'),
      successfulResult(databaseRows),
    ]);
    await expect(runMigrationReadiness(SCHEMA_ROLLBACK_INPUT, runner.run)).rejects.toThrow(
      'Applied migration checksums do not match committed migration files',
    );
    expect(runner.calls.some((call) => call.args.some((arg) => arg.includes('/down.sql')))).toBe(false);
  });
});

describe('migration readiness CLI', () => {
  it('maps explicit flags and emits no database URL', async () => {
    const runner = createRunner();
    const output: string[] = [];

    const exitCode = await runMigrationReadinessCli([
      '--mode', 'live',
      '--database-url', 'postgresql://user:password@db.example.com/app',
      '--confirm-database', 'app',
    ], runner.run, (line) => output.push(line));

    expect(exitCode).toBe(0);
    expect(output.join('\n')).toContain('"mode":"live"');
    expect(output.join('\n')).not.toContain('password');
    expect(output.join('\n')).toContain('"rollbackOrder":["app","schema"]');
  });

  it('accepts the schema rollback evidence secret outside argv and never emits evidence material', async () => {
    const runner = createRunner();
    const output: string[] = [];
    const exitCode = await runMigrationReadinessCli([
      '--mode', 'schema-rollback',
      '--database-url', SCHEMA_ROLLBACK_INPUT.databaseUrl,
      '--confirm-database', SCHEMA_ROLLBACK_INPUT.confirmDatabase,
      '--shadow-database-url', SCHEMA_ROLLBACK_INPUT.shadowDatabaseUrl,
      '--run-id', SCHEMA_ROLLBACK_INPUT.runId,
      '--app-rollback-evidence-json', JSON.stringify(SCHEMA_ROLLBACK_INPUT.appRollbackEvidence),
    ], runner.run, (line) => output.push(line), EVIDENCE_SECRET);

    expect(exitCode).toBe(0);
    expect(output.join('\n')).not.toContain(EVIDENCE_SECRET);
    expect(output.join('\n')).not.toContain(SCHEMA_ROLLBACK_INPUT.appRollbackEvidence.signature);
  });
});
