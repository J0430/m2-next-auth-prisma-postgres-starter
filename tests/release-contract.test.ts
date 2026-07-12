// Verifies the typed, non-secret release contract and repository drift guards.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  RELEASE_CONTRACT,
  validateReleaseContract,
} from '@/release/releaseContract';

const ROOT = resolve(import.meta.dirname, '..');
const VercelContractSchema = z.object({
  installCommand: z.string().min(1),
  buildCommand: z.string().min(1),
});

function sorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

function extractExampleKeys(source: string): string[] {
  return sorted(
    Array.from(
      source.matchAll(/^([A-Z][A-Z0-9_]*)=/gm),
      (match) => match[1] ?? '',
    ),
  ).filter((key) => key.length > 0);
}

function extractProductionRuntimeKeys(source: string): string[] {
  const productionBlock = source.split('const EnvSchemaProd =')[1]
    ?.split('const shouldSkipValidation =')[0];
  if (!productionBlock) throw new Error('Production environment contract was not found');

  const directChecks = Array.from(
    productionBlock.matchAll(/data\.([A-Z][A-Z0-9_]+)/g),
    (match) => match[1] ?? '',
  );
  const helperChecks = Array.from(
    productionBlock.matchAll(/requireProductionValue\(ctx, "([A-Z][A-Z0-9_]+)"/g),
    (match) => match[1] ?? '',
  );

  return sorted([
    'DATABASE_URL',
    'NEXTAUTH_SECRET',
    ...directChecks,
    ...helperChecks,
  ]).filter((key) => key.length > 0 && key !== 'NEXTAUTH_URL');
}

describe('release contract', () => {
  it('defines explicit project, framework, command, and scope contracts', () => {
    expect(RELEASE_CONTRACT.project).toEqual({
      expectedName: 'manumu-auth',
      idInput: 'VERCEL_PROJECT_ID',
      idPolicy: 'required-explicit',
    });
    expect(RELEASE_CONTRACT.framework).toBe('nextjs');
    expect(RELEASE_CONTRACT.commands).toEqual({
      install: 'corepack enable && pnpm install --frozen-lockfile',
      build: 'pnpm build',
    });
    expect(RELEASE_CONTRACT.urlPolicy).toEqual({
      canonicalReleaseKey: 'AUTH_URL',
      runtimeAlias: 'NEXTAUTH_URL',
      requirement: 'canonical-release-key-required',
    });
    expect(RELEASE_CONTRACT.environments.preview.scope).toBe('preview');
    expect(RELEASE_CONTRACT.environments.production.scope).toBe('production');
    expect(RELEASE_CONTRACT.environments.preview).not.toBe(
      RELEASE_CONTRACT.environments.production,
    );
  });

  it.each(['preview', 'production'] as const)(
    'rejects duplicate environment key names in the %s scope',
    (scope) => {
    expect(() => validateReleaseContract({
      ...RELEASE_CONTRACT,
      environments: {
        ...RELEASE_CONTRACT.environments,
        [scope]: {
          scope,
          requiredKeys: ['DATABASE_URL', 'DATABASE_URL'],
        },
      },
    })).toThrow('Duplicate release environment key: DATABASE_URL');
    },
  );

  it('matches the canonical commands checked into vercel.json', () => {
    const vercelContract = VercelContractSchema.parse(JSON.parse(
      readFileSync(resolve(ROOT, 'vercel.json'), 'utf8'),
    ));

    expect(RELEASE_CONTRACT.commands).toEqual({
      install: vercelContract.installCommand,
      build: vercelContract.buildCommand,
    });
  });

  it('matches production-required runtime keys and documents them in .env.example', () => {
    const runtimeSource = readFileSync(resolve(ROOT, 'src/lib/env.ts'), 'utf8');
    const exampleSource = readFileSync(resolve(ROOT, '.env.example'), 'utf8');
    const productionKeys = RELEASE_CONTRACT.environments.production.requiredKeys;

    expect(sorted(productionKeys)).toEqual(extractProductionRuntimeKeys(runtimeSource));
    expect(extractExampleKeys(exampleSource)).toEqual(
      expect.arrayContaining([...productionKeys]),
    );
  });

  it('keeps Preview and Production explicit and complete', () => {
    expect(sorted(RELEASE_CONTRACT.environments.preview.requiredKeys)).toEqual(
      sorted(RELEASE_CONTRACT.environments.production.requiredKeys),
    );
  });

  it('exposes deeply frozen contract data', () => {
    expect(Object.isFrozen(RELEASE_CONTRACT)).toBe(true);
    expect(Object.isFrozen(RELEASE_CONTRACT.project)).toBe(true);
    expect(Object.isFrozen(RELEASE_CONTRACT.commands)).toBe(true);
    expect(Object.isFrozen(RELEASE_CONTRACT.environments)).toBe(true);
    expect(Object.isFrozen(RELEASE_CONTRACT.environments.preview)).toBe(true);
    expect(Object.isFrozen(RELEASE_CONTRACT.environments.preview.requiredKeys)).toBe(true);
    expect(Object.isFrozen(RELEASE_CONTRACT.environments.production)).toBe(true);
    expect(Object.isFrozen(RELEASE_CONTRACT.environments.production.requiredKeys)).toBe(true);
  });
});
