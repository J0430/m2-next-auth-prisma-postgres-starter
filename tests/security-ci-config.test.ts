// Parses repository manifests and verifies blocking CI/release contracts structurally.
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

const ROOT = resolve(import.meta.dirname, '..');
const StepSchema = z.object({
  name: z.string().optional(),
  run: z.string().optional(),
  uses: z.string().optional(),
  with: z.record(z.string(), z.unknown()).optional(),
  env: z.record(z.string(), z.unknown()).optional(),
  'continue-on-error': z.boolean().optional(),
});
const JobSchema = z.object({
  needs: z.union([z.string(), z.array(z.string())]).optional(),
  'timeout-minutes': z.number().int().positive().optional(),
  services: z.record(z.string(), z.unknown()).optional(),
  steps: z.array(StepSchema),
  'continue-on-error': z.boolean().optional(),
});
const WorkflowSchema = z.object({
  on: z.object({
    push: z.unknown().optional(),
    pull_request: z.unknown().optional(),
    workflow_dispatch: z.object({
      inputs: z.record(z.string(), z.object({ required: z.boolean() })),
    }).optional(),
  }),
  concurrency: z.object({ group: z.string(), 'cancel-in-progress': z.boolean() }),
  jobs: z.record(z.string(), JobSchema),
});
const PackageSchema = z.object({
  packageManager: z.string(),
  scripts: z.record(z.string(), z.string()),
  dependencies: z.record(z.string(), z.string()).optional(),
  devDependencies: z.record(z.string(), z.string()),
});

function loadWorkflow(path: string): z.infer<typeof WorkflowSchema> {
  return WorkflowSchema.parse(parse(readFileSync(resolve(ROOT, path), 'utf8')));
}

function requiredJob(workflow: z.infer<typeof WorkflowSchema>, name: string): z.infer<typeof JobSchema> {
  const job = workflow.jobs[name];
  expect(job, `missing required job: ${name}`).toBeDefined();
  return JobSchema.parse(job);
}

function commands(job: z.infer<typeof JobSchema>): string[] {
  return job.steps.flatMap((step) => step.run === undefined ? [] : [step.run]);
}

function uses(job: z.infer<typeof JobSchema>): string[] {
  return job.steps.flatMap((step) => step.uses === undefined ? [] : [step.uses]);
}

const pkg = PackageSchema.parse(JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf8')));
const ci = loadWorkflow('.github/workflows/ci.yml');
const release = loadWorkflow('.github/workflows/release-readiness.yml');
const builtAuthGoldenPath = readFileSync(
  resolve(ROOT, 'scripts/built-auth-golden-path.ts'),
  'utf8',
);
const gatedRegistrationDatabaseTest = readFileSync(
  resolve(ROOT, 'scripts/gated-registration-db-integration.ts'),
  'utf8',
);

describe('package and lockfile contracts', () => {
  it('uses the frozen pnpm toolchain and non-mutating lint verification', () => {
    expect(pkg.packageManager).toBe('pnpm@9.12.3');
    expect(pkg.scripts.lint).not.toContain('--fix');
    expect(pkg.scripts['lint:fix']).toContain('--fix');
    expect(pkg.scripts.build).toContain('next build');
    expect(pkg.scripts['migration:readiness:ci']).toContain('--mode ci');
    expect(pkg.scripts['test:db:gated-registration']).toContain(
      'scripts/gated-registration-db-integration.ts',
    );
    expect(pkg.scripts['migration:readiness:ci']).not.toContain('APP_ROLLBACK');
    expect(pkg.scripts['migration:rollback:schema']).toContain('--mode schema-rollback');
    expect(Object.keys(pkg.scripts).filter((name) => name.startsWith('migration:')).sort()).toEqual([
      'migration:readiness',
      'migration:readiness:ci',
      'migration:rollback:schema',
      'migration:status:live',
    ]);
  });

  it('keeps one lockfile and aligned Vitest tooling', () => {
    expect(existsSync(resolve(ROOT, 'pnpm-lock.yaml'))).toBe(true);
    expect(existsSync(resolve(ROOT, 'package-lock.json'))).toBe(false);
    expect(existsSync(resolve(ROOT, 'yarn.lock'))).toBe(false);
    const majors = ['vitest', '@vitest/ui', '@vitest/coverage-v8'].map((name) =>
      Number.parseInt((pkg.devDependencies[name] ?? '0').replace(/^[^0-9]*/, '').split('.')[0] ?? '0', 10));
    expect(new Set(majors).size).toBe(1);
  });
});

describe('parallel CI contract', () => {
  it('covers documented branches and cancels superseded refs', () => {
    expect(ci.on).toHaveProperty('push');
    expect(ci.on).toHaveProperty('pull_request');
    expect(JSON.stringify(ci.on)).toContain('feat/**');
    expect(JSON.stringify(ci.on)).toContain('feature/**');
    expect(JSON.stringify(ci.on)).toContain('fix/**');
    expect(ci.concurrency.group).toContain('github.ref');
    expect(ci.concurrency['cancel-in-progress']).toBe(true);
  });

  it('keeps core and audit gates independent while E2E consumes the build artifact', () => {
    for (const name of ['lint-typecheck', 'test-coverage', 'build-bundle', 'migration-readiness', 'security-audit']) {
      expect(requiredJob(ci, name).needs).toBeUndefined();
    }
    const e2e = requiredJob(ci, 'e2e');
    expect(e2e.needs).toBe('build-bundle');
    expect(uses(e2e)).toContain('actions/download-artifact@v4');
    expect(e2e.services).toHaveProperty('postgres');
    expect(Object.values(ci.jobs).every((job) => job['timeout-minutes'] !== undefined)).toBe(true);
  });

  it('fails closed when the hidden Next build artifact is absent or incomplete', () => {
    const build = requiredJob(ci, 'build-bundle');
    const upload = build.steps.find((step) => step.uses === 'actions/upload-artifact@v4');
    expect(upload?.with).toMatchObject({
      path: '.next',
      'include-hidden-files': true,
      'if-no-files-found': 'error',
    });
    const e2eCommands = commands(requiredJob(ci, 'e2e')).join('\n');
    expect(e2eCommands).toContain('test -f .next/BUILD_ID');
    expect(e2eCommands).toContain('test -f .next/routes-manifest.json');
    expect(e2eCommands).toContain('test -d .next/server');
  });

  it('uses frozen pnpm installs, canonical build, coverage, bundle and smoke gates', () => {
    const allCommands = Object.values(ci.jobs).flatMap(commands);
    expect(allCommands.filter((command) => command.includes('pnpm install --frozen-lockfile')).length)
      .toBe(Object.keys(ci.jobs).length);
    expect(commands(requiredJob(ci, 'build-bundle'))).toContain('pnpm build');
    expect(commands(requiredJob(ci, 'test-coverage'))).toContain('pnpm test:coverage');
    expect(allCommands.join('\n')).toContain('BUNDLE_BUDGET_KB');
    const e2eCommands = commands(requiredJob(ci, 'e2e')).join('\n');
    expect(e2eCommands).toContain('/api/healthz');
    expect(e2eCommands).toContain('pnpm e2e:built-auth');
    expect(builtAuthGoldenPath).toContain('prisma.user.create');
    expect(builtAuthGoldenPath).toContain('/api/auth/csrf');
    expect(builtAuthGoldenPath).toContain('/api/auth/callback/credentials');
    expect(builtAuthGoldenPath).toContain('/api/auth/session');
    expect(builtAuthGoldenPath).toContain('hasPasswordCredential: true');
    expect(builtAuthGoldenPath).toContain('emailVerified: new Date()');
    expect(builtAuthGoldenPath).toMatch(/hash\([^,]+,\s*10\)/);
    expect(builtAuthGoldenPath).not.toContain('/api/auth/providers');
    expect(builtAuthGoldenPath).not.toContain('prisma.user.findUnique');
    expect(builtAuthGoldenPath).not.toContain('/api/healthz');
    expect(allCommands.join('\n')).not.toContain('next build --no-lint');
    expect(allCommands.join('\n')).not.toMatch(/(^|\s)npm install/);
  });

  it('generates, masks, and validates OAuth keys inside every app runtime job', () => {
    for (const jobName of ['build-bundle', 'e2e']) {
      const job = requiredJob(ci, jobName);
      const keyStep = job.steps.find((step) => step.name === 'Generate ephemeral OAuth RSA keypair');
      expect(keyStep?.run, `${jobName} must generate its own keys`).toContain('openssl genpkey');
      expect(keyStep?.run).toContain('openssl rsa -pubout');
      expect(keyStep?.run).toContain('::add-mask::');
      expect(keyStep?.run).toContain('test -n "$PRIVATE_KEY"');
      expect(keyStep?.run).toContain('test -n "$PUBLIC_KEY"');
      expect(keyStep?.run).toContain('GITHUB_ENV');
    }

    const e2e = requiredJob(ci, 'e2e');
    const start = e2e.steps.find((step) => step.name === 'Start downloaded built application');
    expect(start?.env).toMatchObject({
      OAUTH_JWT_PRIVATE_KEY: '${{ env.OAUTH_JWT_PRIVATE_KEY }}',
      OAUTH_JWT_PUBLIC_KEY: '${{ env.OAUTH_JWT_PUBLIC_KEY }}',
    });
  });

  it('runs an explicitly disposable TASK-032 rehearsal without fabricating app rollback evidence', () => {
    const migration = requiredJob(ci, 'migration-readiness');
    const migrationCommands = commands(migration).join('\n');
    expect(migration.services).toHaveProperty('postgres');
    expect(migrationCommands).toContain('CREATE DATABASE auth_shadow');
    expect(migrationCommands).toContain('pnpm migration:readiness:ci');
    expect(migrationCommands).toContain('pnpm test:db:gated-registration');
    expect(migrationCommands).not.toContain('APP_ROLLBACK_EVIDENCE_SECRET');
    expect(migrationCommands).not.toContain('APP_ROLLBACK_EVIDENCE_JSON');
    expect(migrationCommands).not.toContain('app-rollback-complete');
    expect(migrationCommands).not.toContain('pnpm prisma:deploy');
    expect(gatedRegistrationDatabaseTest).toContain("hostname !== 'localhost'");
    expect(gatedRegistrationDatabaseTest).toContain("pathname !== '/auth_ci'");
    expect(gatedRegistrationDatabaseTest).toContain('search !==');
    expect(gatedRegistrationDatabaseTest).toContain('hash !==');
  });

  it('keeps both dependency audits and secret scanning blocking', () => {
    const audit = requiredJob(ci, 'security-audit');
    expect(commands(audit)).toContain('pnpm audit --audit-level=high');
    expect(commands(audit)).toContain('pnpm audit --prod --audit-level=high');
    expect(uses(audit)).toContain('gitleaks/gitleaks-action@v2');
    expect(audit.steps.find((step) => step.uses === 'actions/checkout@v4')?.with?.['fetch-depth']).toBe(0);
  });

  it('does not weaken any required job or step', () => {
    for (const job of Object.values(ci.jobs)) {
      expect(job['continue-on-error']).not.toBe(true);
      expect(job.steps.some((step) => step['continue-on-error'] === true)).toBe(false);
    }
  });
});

describe('release readiness provenance contract', () => {
  it('uses an explicit deployment ID and trusted GitHub branch/SHA identity', () => {
    expect(release.on).toHaveProperty('workflow_dispatch');
    const inputs = release.on.workflow_dispatch?.inputs;
    for (const name of ['target', 'deployment_id']) {
      expect(inputs?.[name]?.required, `workflow input must be mandatory: ${name}`).toBe(true);
    }
    expect(inputs).not.toHaveProperty('git_branch');
    expect(inputs).not.toHaveProperty('git_sha');
    const command = requiredJob(release, 'vercel-preflight').steps
      .find((step) => step.run === 'pnpm release:preflight');
    expect(command?.env).toMatchObject({
      RELEASE_TARGET: '${{ inputs.target }}',
      RELEASE_DEPLOYMENT_ID: '${{ inputs.deployment_id }}',
      RELEASE_GIT_PROVIDER: 'github',
      RELEASE_GIT_REPOSITORY: '${{ github.repository }}',
      RELEASE_GIT_BRANCH: '${{ github.ref_name }}',
      RELEASE_GIT_SHA: '${{ github.sha }}',
    });
    expect(requiredJob(release, 'vercel-preflight')['timeout-minutes']).toBeDefined();
  });

  it('has no continue-on-error escape hatch', () => {
    const job = requiredJob(release, 'vercel-preflight');
    expect(job['continue-on-error']).toBeUndefined();
    expect(job.steps.every((step) => step['continue-on-error'] === undefined)).toBe(true);
  });
});
