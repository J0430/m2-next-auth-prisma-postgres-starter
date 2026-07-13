// Adapts environment input and JSON output for the release preflight CLI.
import { pathToFileURL } from 'node:url';
import { z } from 'zod';
import {
  formatPreflightFailure,
  runReleasePreflight,
} from '../src/release/releasePreflight';

const CliEnvironmentSchema = z.object({
  VERCEL_TOKEN: z.string().min(1),
  VERCEL_PROJECT_ID: z.string().min(1),
  VERCEL_TEAM_ID: z.string().min(1).optional(),
  RELEASE_TARGET: z.enum(['preview', 'production']),
  RELEASE_DEPLOYMENT_ID: z.string().min(1),
  RELEASE_GIT_PROVIDER: z.literal('github'),
  RELEASE_GIT_REPOSITORY: z.string().regex(/^[^/]+\/[^/]+$/),
  RELEASE_GIT_BRANCH: z.string().min(1),
  RELEASE_GIT_SHA: z.string().regex(/^[a-fA-F0-9]{40}$/),
});

export interface ReleasePreflightCliDependencies {
  execute: typeof runReleasePreflight;
  writeStdout: (line: string) => void;
  writeStderr: (line: string) => void;
}

const DEFAULT_DEPENDENCIES: ReleasePreflightCliDependencies = {
  execute: runReleasePreflight,
  writeStdout: console.log,
  writeStderr: console.error,
};

export async function runReleasePreflightCli(
  environment: unknown,
  dependencies: ReleasePreflightCliDependencies = DEFAULT_DEPENDENCIES,
): Promise<number> {
  try {
    const env = CliEnvironmentSchema.parse(environment);
    const result = await dependencies.execute({
      token: env.VERCEL_TOKEN,
      expectedProjectId: env.VERCEL_PROJECT_ID,
      target: env.RELEASE_TARGET,
      ...(env.VERCEL_TEAM_ID ? { teamId: env.VERCEL_TEAM_ID } : {}),
      deployment: {
        id: env.RELEASE_DEPLOYMENT_ID,
        provider: env.RELEASE_GIT_PROVIDER,
        repository: env.RELEASE_GIT_REPOSITORY,
        branch: env.RELEASE_GIT_BRANCH,
        sha: env.RELEASE_GIT_SHA,
      },
    });
    dependencies.writeStdout(JSON.stringify(result));
    return 0;
  } catch (error: unknown) {
    const failure = formatPreflightFailure(error);
    dependencies.writeStderr(JSON.stringify(failure));
    return failure.exitCode;
  }
}

const entryPath = process.argv[1];
if (entryPath && import.meta.url === pathToFileURL(entryPath).href) {
  process.exitCode = await runReleasePreflightCli(process.env);
}
