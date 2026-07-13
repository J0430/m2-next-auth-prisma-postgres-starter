// Verifies fail-closed, redacted Vercel release preflight behavior.
import { describe, expect, it, vi } from 'vitest';
import {
  REQUIRED_RELEASE_ENV_KEYS,
  ReleasePreflightError,
  formatPreflightFailure,
  runReleasePreflight,
} from '@/release/releasePreflight';

const NON_SECRET_AUTHORIZATION_SENTINEL = 'non-secret-authorization-sentinel';
const SUBJECT = {
  id: 'dpl_test', provider: 'github', repository: 'manumustudio/auth',
  branch: 'main', sha: 'abcdef1234567890abcdef1234567890abcdef12',
} as const;
const PROJECT = {
  id: 'prj_test', name: 'manumu-auth', framework: 'nextjs',
  installCommand: 'corepack enable && pnpm install --frozen-lockfile',
  buildCommand: 'pnpm build',
};
const DEPLOYMENT = {
  id: 'dpl_test', projectId: 'prj_test',
  gitSource: {
    type: 'github', org: 'manumustudio', repo: 'auth', ref: 'main',
    sha: 'abcdef1234567890abcdef1234567890abcdef12',
  },
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function createFetcher(overrides: {
  project?: unknown; envs?: unknown; deployment?: unknown;
} = {}): typeof fetch {
  return vi.fn(async (input: string | URL | Request) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url.includes('/env')) {
      return jsonResponse(overrides.envs ?? REQUIRED_RELEASE_ENV_KEYS.map((key) => ({
        key, target: ['preview', 'production'], value: 'ignored-by-schema',
      })));
    }
    if (url.includes('/deployments/')) return jsonResponse(overrides.deployment ?? DEPLOYMENT);
    return jsonResponse(overrides.project ?? PROJECT);
  });
}

function options(fetcher: typeof fetch, target: 'preview' | 'production' = 'preview') {
  return {
    token: NON_SECRET_AUTHORIZATION_SENTINEL,
    expectedProjectId: 'prj_test',
    target,
    deployment: SUBJECT,
    fetcher,
  };
}

async function expectDrift(input: unknown, message: string): Promise<void> {
  try {
    await runReleasePreflight(input);
    throw new Error('Expected release preflight to fail');
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(ReleasePreflightError);
    expect(error).toMatchObject({ classification: 'drift', exitCode: 2 });
    expect(error).toHaveProperty('message', message);
  }
}

describe('release preflight', () => {
  it('returns redacted structured evidence and reports extra names', async () => {
    const envs = [
      ...REQUIRED_RELEASE_ENV_KEYS.map((key) => ({ key, target: ['preview', 'production'] })),
      { key: 'OPTIONAL_NAME', target: 'preview' },
    ];
    const result = await runReleasePreflight(options(createFetcher({ envs })));

    expect(result).toEqual({
      status: 'passed', target: 'preview', projectId: 'prj_test', projectName: 'manumu-auth',
      checkedKeys: REQUIRED_RELEASE_ENV_KEYS, missingKeys: [], extraKeys: ['OPTIONAL_NAME'],
      deploymentId: 'dpl_test',
    });
    expect(JSON.stringify(result)).not.toContain(NON_SECRET_AUTHORIZATION_SENTINEL);
  });

  it('requests the v10 direct-list environment endpoint with team scope', async () => {
    const fetcher = createFetcher();
    await runReleasePreflight({ ...options(fetcher), teamId: 'team_test' });
    const urls = vi.mocked(fetcher).mock.calls.map(([input]) => new URL(
      input instanceof Request ? input.url : input.toString(),
    ));
    const envUrl = urls.find((url) => url.pathname.endsWith('/env'));
    expect(envUrl?.pathname).toBe('/v10/projects/prj_test/env');
    expect(envUrl?.searchParams.toString()).toBe('teamId=team_test');
  });

  it.each([
    [{ envs: [] }],
    [[{ target: 'preview' }]],
  ])('fails auth-network for a malformed environment list', async (envs) => {
    await expect(runReleasePreflight(options(createFetcher({ envs })))).rejects.toMatchObject({
      classification: 'auth-network', exitCode: 3,
      message: 'Vercel API returned malformed environment metadata',
    });
  });

  it.each([
    [{ ...PROJECT, id: 'wrong' }, 'Vercel project ID does not match the explicit release target'],
    [{ ...PROJECT, name: 'wrong' }, 'Vercel project name does not match the release contract'],
    [{ ...PROJECT, framework: 'vite' }, 'Vercel framework does not match the release contract'],
    [{ ...PROJECT, installCommand: 'npm install' }, 'Vercel install command does not match the release contract'],
    [{ ...PROJECT, buildCommand: 'next build' }, 'Vercel build command does not match the release contract'],
  ])('rejects project contract drift', async (project, message) => {
    await expectDrift(options(createFetcher({ project })), message);
  });

  it('reports missing keys without values and rejects a scope mix-up', async () => {
    const envs = REQUIRED_RELEASE_ENV_KEYS.map((key) => ({
      key, target: key === 'TURNSTILE_SECRET_KEY' ? 'production' : 'preview',
    }));
    const pageEnvs = [...envs, { key: 'OPTIONAL_NAME', target: 'preview' }];
    const failure = runReleasePreflight(options(createFetcher({ envs: pageEnvs })));
    await expect(failure).rejects.toMatchObject({
      classification: 'drift', exitCode: 2,
      evidence: { missingKeys: ['TURNSTILE_SECRET_KEY'], extraKeys: ['OPTIONAL_NAME'] },
    });
  });

  it.each([
    [null, 'Deployment Git provenance is absent or local'],
    [undefined, 'Deployment Git provenance is absent or local'],
    [{ type: 'local' }, 'Deployment Git provenance is absent or local'],
    [{ ...DEPLOYMENT.gitSource, type: 'gitlab' }, 'Deployment Git provider does not match'],
    [{ ...DEPLOYMENT.gitSource, repo: 'other' }, 'Deployment Git repository does not match'],
    [{ ...DEPLOYMENT.gitSource, ref: 'feature' }, 'Deployment Git branch does not match'],
    [{ ...DEPLOYMENT.gitSource, sha: '0000000000000000000000000000000000000000' }, 'Deployment Git SHA does not match'],
  ])('rejects unverifiable deployment provenance', async (gitSource, message) => {
    await expectDrift(
      options(createFetcher({ deployment: { ...DEPLOYMENT, gitSource } })),
      message,
    );
  });

  it('rejects a deployment from another Vercel project', async () => {
    await expectDrift(
      options(createFetcher({ deployment: { ...DEPLOYMENT, projectId: 'prj_other' } })),
      'Deployment belongs to a different Vercel project',
    );
  });

  it('rejects a returned deployment whose ID differs from the requested deployment', async () => {
    await expectDrift(
      options(createFetcher({ deployment: { ...DEPLOYMENT, id: 'dpl_other' } })),
      'Returned deployment ID does not match the requested deployment',
    );
  });

  it('compares hexadecimal Git SHAs case-insensitively', async () => {
    const result = await runReleasePreflight(options(createFetcher({ deployment: {
      ...DEPLOYMENT,
      gitSource: { ...DEPLOYMENT.gitSource, sha: DEPLOYMENT.gitSource.sha.toUpperCase() },
    } })));
    expect(result.status).toBe('passed');
  });

  it('requires a requested deployment subject before fetching', async () => {
    const fetcher = createFetcher();
    await expectDrift({ ...options(fetcher), deployment: undefined }, 'Deployment subject is required');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([401, 403])('classifies HTTP %s as auth-network without response content', async (status) => {
    const fetcher = vi.fn(async () => jsonResponse({ secret: 'must-not-escape' }, status));
    await expect(runReleasePreflight(options(fetcher))).rejects.toMatchObject({
      classification: 'auth-network', exitCode: 3,
      message: `Vercel API authorization failed with HTTP ${status}`,
    });
  });

  it('classifies network failures and redacts structured failure output', async () => {
    const fetcher = vi.fn(async () => { throw new Error(NON_SECRET_AUTHORIZATION_SENTINEL); });
    let caught: unknown;
    try { await runReleasePreflight(options(fetcher)); } catch (error: unknown) { caught = error; }

    expect(formatPreflightFailure(caught)).toEqual({
      status: 'failed', classification: 'auth-network', exitCode: 3,
      message: 'Vercel API network request failed',
    });
    expect(JSON.stringify(formatPreflightFailure(caught))).not.toContain(NON_SECRET_AUTHORIZATION_SENTINEL);
  });

  it.each([
    ['invalid JSON', vi.fn(async () => new Response('{', { status: 200 }))],
    ['malformed metadata', createFetcher({ project: { id: 'only-id' } })],
    ['malformed provenance', createFetcher({ deployment: {
      ...DEPLOYMENT, gitSource: { type: 'github', org: 'manumustudio' },
    } })],
  ])('classifies %s remote responses as auth-network', async (_label, fetcher) => {
    await expect(runReleasePreflight(options(fetcher))).rejects.toMatchObject({
      classification: 'auth-network', exitCode: 3,
    });
  });

  it('constructs the authorization header only inside the request boundary', async () => {
    const fetcher = createFetcher();
    await runReleasePreflight(options(fetcher));
    expect(fetcher).toHaveBeenCalledWith(expect.any(URL), {
      headers: { Authorization: `Bearer ${NON_SECRET_AUTHORIZATION_SENTINEL}` },
    });
  });
});
