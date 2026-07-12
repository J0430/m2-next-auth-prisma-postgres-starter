// Runs a redacted, fail-closed Vercel release preflight.
import { z } from 'zod';
import { RELEASE_CONTRACT } from './releaseContract';

export const RELEASE_PROJECT_NAME = RELEASE_CONTRACT.project.expectedName;
export const REQUIRED_RELEASE_ENV_KEYS = RELEASE_CONTRACT.environments.production.requiredKeys;

type FailureClassification = 'drift' | 'auth-network' | 'input';
type FailureExitCode = 2 | 3 | 4;

export class ReleasePreflightError extends Error {
  constructor(
    message: string,
    readonly classification: FailureClassification,
    readonly exitCode: FailureExitCode,
    readonly evidence?: { readonly missingKeys: readonly string[]; readonly extraKeys: readonly string[] },
  ) {
    super(message);
    this.name = 'ReleasePreflightError';
  }
}

const ReleaseTargetSchema = z.enum(['preview', 'production']);
const FetcherSchema = z.custom<typeof fetch>((value) => typeof value === 'function');
const DeploymentSubjectSchema = z.strictObject({
  id: z.string().trim().min(1),
  provider: z.literal('github'),
  repository: z.string().trim().regex(/^[^/]+\/[^/]+$/),
  branch: z.string().trim().min(1),
  sha: z.string().trim().regex(/^[a-fA-F0-9]{40}$/),
});
const ReleasePreflightInputSchema = z.strictObject({
  token: z.string().trim().min(1),
  expectedProjectId: z.string().trim().min(1),
  target: ReleaseTargetSchema,
  teamId: z.string().trim().min(1).optional(),
  deployment: DeploymentSubjectSchema.optional(),
  fetcher: FetcherSchema.optional(),
});

export type ReleaseTarget = z.infer<typeof ReleaseTargetSchema>;
const ProjectSchema = z.object({
  id: z.string().min(1), name: z.string().min(1),
  framework: z.string().nullable().optional(),
  installCommand: z.string().nullable().optional(),
  buildCommand: z.string().nullable().optional(),
});
const EnvironmentVariableSchema = z.object({
  key: z.string().min(1),
  target: z.union([z.string(), z.array(z.string())]).optional(),
});
const EnvironmentResponseSchema = z.array(EnvironmentVariableSchema);
const DeploymentSchema = z.object({
  id: z.string().min(1), projectId: z.string().min(1), gitSource: z.unknown().optional(),
});
const GitSourceSchema = z.object({
  type: z.literal('github'), org: z.string().min(1), repo: z.string().min(1),
  ref: z.string().min(1), sha: z.string().regex(/^[a-fA-F0-9]{40}$/),
});

export interface ReleasePreflightResult {
  status: 'passed';
  target: ReleaseTarget;
  projectId: string;
  projectName: string;
  checkedKeys: readonly string[];
  missingKeys: readonly string[];
  extraKeys: readonly string[];
  deploymentId: string;
}

export interface PreflightFailureOutput {
  status: 'failed';
  classification: FailureClassification;
  exitCode: FailureExitCode;
  message: string;
  evidence?: { readonly missingKeys: readonly string[]; readonly extraKeys: readonly string[] };
}

function drift(message: string): ReleasePreflightError {
  return new ReleasePreflightError(message, 'drift', 2);
}

function parseInput(input: unknown) {
  const parsed = ReleasePreflightInputSchema.safeParse(input);
  if (!parsed.success) throw new ReleasePreflightError('Invalid preflight input', 'input', 4);
  const deployment = parsed.data.deployment;
  if (!deployment) throw drift('Deployment subject is required');
  return { ...parsed.data, deployment };
}

function buildUrl(path: string, teamId: string | undefined): URL {
  const url = new URL(path, 'https://api.vercel.com');
  if (teamId) url.searchParams.set('teamId', teamId);
  return url;
}

async function fetchJson(fetcher: typeof fetch, url: URL, token: string): Promise<unknown> {
  let response: Response;
  try {
    response = await fetcher(url, { headers: { Authorization: `Bearer ${token}` } });
  } catch {
    throw new ReleasePreflightError('Vercel API network request failed', 'auth-network', 3);
  }
  if (response.status === 401 || response.status === 403) {
    throw new ReleasePreflightError(
      `Vercel API authorization failed with HTTP ${response.status}`,
      'auth-network',
      3,
    );
  }
  if (!response.ok) {
    throw new ReleasePreflightError(
      `Vercel API request failed with HTTP ${response.status}`,
      'auth-network',
      3,
    );
  }
  try {
    return await response.json();
  } catch {
    throw new ReleasePreflightError('Vercel API returned invalid JSON', 'auth-network', 3);
  }
}

function parseRemote<T>(schema: z.ZodType<T>, input: unknown, label: string): T {
  const parsed = schema.safeParse(input);
  if (!parsed.success) {
    throw new ReleasePreflightError(`Vercel API returned malformed ${label} metadata`, 'auth-network', 3);
  }
  return parsed.data;
}

function assertProject(project: z.infer<typeof ProjectSchema>, expectedId: string): void {
  if (project.id !== expectedId) throw drift('Vercel project ID does not match the explicit release target');
  if (project.name !== RELEASE_PROJECT_NAME) throw drift('Vercel project name does not match the release contract');
  if (project.framework !== RELEASE_CONTRACT.framework) throw drift('Vercel framework does not match the release contract');
  if (project.installCommand !== RELEASE_CONTRACT.commands.install) throw drift('Vercel install command does not match the release contract');
  if (project.buildCommand !== RELEASE_CONTRACT.commands.build) throw drift('Vercel build command does not match the release contract');
}

function assertProvenance(
  sourceInput: unknown,
  subject: z.infer<typeof DeploymentSubjectSchema>,
): void {
  if (!sourceInput || typeof sourceInput !== 'object') {
    throw drift('Deployment Git provenance is absent or local');
  }
  const provider = z.object({ type: z.string().optional() }).safeParse(sourceInput);
  if (!provider.success || !provider.data.type || provider.data.type === 'local') {
    throw drift('Deployment Git provenance is absent or local');
  }
  if (provider.data.type !== subject.provider) throw drift('Deployment Git provider does not match');
  const source = parseRemote(GitSourceSchema, sourceInput, 'deployment provenance');
  if (`${source.org}/${source.repo}` !== subject.repository) throw drift('Deployment Git repository does not match');
  if (source.ref !== subject.branch) throw drift('Deployment Git branch does not match');
  if (source.sha.toLowerCase() !== subject.sha.toLowerCase()) {
    throw drift('Deployment Git SHA does not match');
  }
}

function namesForTarget(
  envs: z.infer<typeof EnvironmentVariableSchema>[],
  target: ReleaseTarget,
): Set<string> {
  return new Set(envs.filter((variable) => Array.isArray(variable.target)
    ? variable.target.includes(target)
    : variable.target === target).map((variable) => variable.key));
}

export function formatPreflightFailure(error: unknown): PreflightFailureOutput {
  if (error instanceof ReleasePreflightError) {
    return {
      status: 'failed', classification: error.classification,
      exitCode: error.exitCode, message: error.message,
      ...(error.evidence ? { evidence: error.evidence } : {}),
    };
  }
  return { status: 'failed', classification: 'input', exitCode: 4, message: 'Preflight failed' };
}

export async function runReleasePreflight(input: unknown): Promise<ReleasePreflightResult> {
  const options = parseInput(input);
  const fetcher = options.fetcher ?? fetch;
  const projectUrl = buildUrl(`/v9/projects/${RELEASE_PROJECT_NAME}`, options.teamId);
  const project = parseRemote(ProjectSchema, await fetchJson(fetcher, projectUrl, options.token), 'project');
  assertProject(project, options.expectedProjectId);

  const envUrl = buildUrl(`/v10/projects/${project.id}/env`, options.teamId);
  const environmentVariables = parseRemote(
    EnvironmentResponseSchema,
    await fetchJson(fetcher, envUrl, options.token),
    'environment',
  );
  const available = namesForTarget(environmentVariables, options.target);
  const required = RELEASE_CONTRACT.environments[options.target].requiredKeys;
  const missingKeys = required.filter((key) => !available.has(key));
  const extraKeys = [...available].filter((key) => !required.includes(key)).sort();
  if (missingKeys.length > 0) {
    throw new ReleasePreflightError(
      `Missing ${options.target} environment names: ${missingKeys.join(', ')}`,
      'drift', 2, { missingKeys, extraKeys },
    );
  }

  const deploymentUrl = buildUrl(`/v13/deployments/${options.deployment.id}`, options.teamId);
  const deployment = parseRemote(DeploymentSchema, await fetchJson(fetcher, deploymentUrl, options.token), 'deployment');
  if (deployment.id !== options.deployment.id) {
    throw drift('Returned deployment ID does not match the requested deployment');
  }
  if (deployment.projectId !== project.id) throw drift('Deployment belongs to a different Vercel project');
  assertProvenance(deployment.gitSource, options.deployment);

  return {
    status: 'passed', target: options.target, projectId: project.id,
    projectName: project.name, checkedKeys: required, missingKeys, extraKeys,
    deploymentId: deployment.id,
  };
}
