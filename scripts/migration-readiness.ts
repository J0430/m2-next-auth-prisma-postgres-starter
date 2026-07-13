// Adapts explicit CLI flags and child processes for migration-readiness checks.
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

import { z } from 'zod';

import {
  MigrationReadinessError,
  type CommandEnvironment,
  type CommandResult,
  type CommandRunner,
  runMigrationReadiness,
} from '../src/release/migrationReadiness';

const ArgvSchema = z.array(z.string());
const FlagSchema = z.enum([
  '--mode', '--database-url', '--confirm-database', '--shadow-database-url',
  '--run-id', '--app-rollback-evidence-json',
]);

function parseEvidence(value: string | undefined): unknown {
  if (value === undefined) return undefined;
  try {
    return JSON.parse(value);
  } catch {
    throw new MigrationReadinessError('App rollback evidence must be valid JSON');
  }
}

function parseFlags(rawArgv: unknown, appRollbackEvidenceSecret: string | undefined): unknown {
  const argv = ArgvSchema.parse(rawArgv);
  const values: Record<string, string> = {};
  for (let index = 0; index < argv.length; index += 2) {
    const rawFlag = argv[index];
    const value = argv[index + 1];
    const flag = FlagSchema.safeParse(rawFlag);
    if (!flag.success || value === undefined || values[flag.data] !== undefined) {
      throw new MigrationReadinessError('Use each supported migration-readiness flag exactly once with a value');
    }
    values[flag.data] = value;
  }
  return {
    mode: values['--mode'],
    databaseUrl: values['--database-url'],
    confirmDatabase: values['--confirm-database'],
    shadowDatabaseUrl: values['--shadow-database-url'],
    runId: values['--run-id'],
    appRollbackEvidenceSecret,
    appRollbackEvidence: parseEvidence(values['--app-rollback-evidence-json']),
  };
}

export const runCommand: CommandRunner = async (
  command: string,
  args: readonly string[],
  environment?: CommandEnvironment,
): Promise<CommandResult> => new Promise((resolve, reject) => {
  const child = spawn(command, args, {
    env: { ...process.env, ...environment },
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
  child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
  child.on('error', reject);
  child.on('close', (exitCode) => resolve({ exitCode: exitCode ?? 1, stdout, stderr }));
});

export async function runMigrationReadinessCli(
  argv: unknown,
  runner: CommandRunner = runCommand,
  write: (line: string) => void = console.log,
  appRollbackEvidenceSecret: string | undefined = process.env.APP_ROLLBACK_EVIDENCE_SECRET,
): Promise<number> {
  try {
    const result = await runMigrationReadiness(parseFlags(argv, appRollbackEvidenceSecret), runner);
    write(JSON.stringify({ ok: true, ...result }));
    return 0;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Migration readiness failed';
    write(JSON.stringify({ ok: false, error: message }));
    return 1;
  }
}

const entryPath = process.argv[1];
if (entryPath !== undefined && import.meta.url === pathToFileURL(entryPath).href) {
  process.exitCode = await runMigrationReadinessCli(process.argv.slice(2));
}
