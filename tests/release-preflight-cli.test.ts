// Verifies CLI input, JSON channel, and classified exit behavior without side effects.
import { describe, expect, it, vi } from 'vitest';
import { ReleasePreflightError } from '@/release/releasePreflight';
import { runReleasePreflightCli } from '../scripts/release-preflight';

const ENVIRONMENT = {
  VERCEL_TOKEN: 'non-secret-authorization-sentinel',
  VERCEL_PROJECT_ID: 'prj_test',
  RELEASE_TARGET: 'preview',
  RELEASE_DEPLOYMENT_ID: 'dpl_test',
  RELEASE_GIT_PROVIDER: 'github',
  RELEASE_GIT_REPOSITORY: 'manumustudio/auth',
  RELEASE_GIT_BRANCH: 'main',
  RELEASE_GIT_SHA: 'abcdef1234567890abcdef1234567890abcdef12',
} as const;

function dependencies(execute: (input: unknown) => Promise<never>) {
  return { execute, writeStdout: vi.fn(), writeStderr: vi.fn() };
}

describe('release preflight CLI', () => {
  it('writes one success JSON line to stdout and exits zero', async () => {
    const result = {
      status: 'passed', target: 'preview', projectId: 'prj_test',
      projectName: 'manumu-auth', checkedKeys: [], missingKeys: [], extraKeys: [],
      deploymentId: 'dpl_test',
    } as const;
    const deps = {
      execute: vi.fn(async () => result),
      writeStdout: vi.fn(),
      writeStderr: vi.fn(),
    };

    expect(await runReleasePreflightCli(ENVIRONMENT, deps)).toBe(0);
    expect(deps.writeStdout).toHaveBeenCalledTimes(1);
    expect(JSON.parse(deps.writeStdout.mock.calls[0]?.[0] ?? '')).toEqual(result);
    expect(deps.writeStderr).not.toHaveBeenCalled();
  });

  it('requires RELEASE_TARGET and emits one input-failure JSON line', async () => {
    const { RELEASE_TARGET: _omitted, ...environment } = ENVIRONMENT;
    const deps = dependencies(vi.fn());
    expect(await runReleasePreflightCli(environment, deps)).toBe(4);
    expect(deps.writeStdout).not.toHaveBeenCalled();
    expect(deps.writeStderr).toHaveBeenCalledTimes(1);
    expect(JSON.parse(deps.writeStderr.mock.calls[0]?.[0] ?? '')).toMatchObject({
      status: 'failed', classification: 'input', exitCode: 4,
    });
  });

  it.each([
    ['drift', 2],
    ['auth-network', 3],
  ] as const)('returns the %s exit code through stderr only', async (classification, exitCode) => {
    const deps = dependencies(vi.fn(async () => {
      throw new ReleasePreflightError('redacted failure', classification, exitCode);
    }));
    expect(await runReleasePreflightCli(ENVIRONMENT, deps)).toBe(exitCode);
    expect(deps.writeStdout).not.toHaveBeenCalled();
    expect(deps.writeStderr).toHaveBeenCalledTimes(1);
  });
});
