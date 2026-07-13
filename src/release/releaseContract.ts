// Defines and validates the immutable, non-secret release contract.
import { z } from 'zod';

const REQUIRED_ENVIRONMENT_KEYS = [
  'DATABASE_URL', 'NEXTAUTH_SECRET', 'AUTH_URL',
  'UPSTASH_REDIS_REST_URL', 'UPSTASH_REDIS_REST_TOKEN',
  'OTP_HMAC_SECRET', 'ACCOUNT_LINK_PKCE_SECRET', 'SELF_SERVICE_REGISTRATION_ENABLED',
  'GITHUB_LINK_CLIENT_ID', 'GITHUB_LINK_CLIENT_SECRET',
  'OAUTH_JWT_PRIVATE_KEY', 'OAUTH_JWT_PUBLIC_KEY',
  'TURNSTILE_SECRET_KEY', 'TURNSTILE_EXPECTED_HOSTNAME',
  'TURNSTILE_EXPECTED_ACTION', 'INTERNAL_WORKER_AUTH_SECRET',
  'QSTASH_URL', 'QSTASH_TOKEN',
  'RESEND_API_KEY',
  'INVITE_DELIVERY_ENCRYPTION_KEYS', 'INVITE_DELIVERY_KEY_VERSION',
  'ADMIN_MFA_SECRET_ENCRYPTION_KEYS', 'ADMIN_MFA_SECRET_KEY_VERSION',
] as const;

const UniqueKeyNamesSchema = z.array(z.string().min(1)).superRefine((keys, context) => {
  const duplicates = keys.filter((key, index) => keys.indexOf(key) !== index);
  for (const duplicate of new Set(duplicates)) {
    context.addIssue({
      code: 'custom',
      message: `Duplicate release environment key: ${duplicate}`,
    });
  }
}).readonly();

export const ReleaseContractSchema = z.strictObject({
  project: z.strictObject({
    expectedName: z.string().min(1),
    idInput: z.literal('VERCEL_PROJECT_ID'),
    idPolicy: z.literal('required-explicit'),
  }).readonly(),
  framework: z.literal('nextjs'),
  commands: z.strictObject({
    install: z.string().min(1),
    build: z.string().min(1),
  }).readonly(),
  urlPolicy: z.strictObject({
    canonicalReleaseKey: z.literal('AUTH_URL'),
    runtimeAlias: z.literal('NEXTAUTH_URL'),
    requirement: z.literal('canonical-release-key-required'),
  }).readonly(),
  environments: z.strictObject({
    preview: z.strictObject({
      scope: z.literal('preview'),
      requiredKeys: UniqueKeyNamesSchema,
    }).readonly(),
    production: z.strictObject({
      scope: z.literal('production'),
      requiredKeys: UniqueKeyNamesSchema,
    }).readonly(),
  }).readonly(),
}).readonly();

export type ReleaseContract = z.infer<typeof ReleaseContractSchema>;

export function validateReleaseContract(input: unknown): ReleaseContract {
  return ReleaseContractSchema.parse(input);
}

export const RELEASE_CONTRACT = validateReleaseContract({
  project: {
    expectedName: 'manumu-auth',
    idInput: 'VERCEL_PROJECT_ID',
    idPolicy: 'required-explicit',
  },
  framework: 'nextjs',
  commands: {
    install: 'corepack enable && pnpm install --frozen-lockfile',
    build: 'pnpm build',
  },
  urlPolicy: {
    canonicalReleaseKey: 'AUTH_URL',
    runtimeAlias: 'NEXTAUTH_URL',
    requirement: 'canonical-release-key-required',
  },
  environments: {
    preview: { scope: 'preview', requiredKeys: [...REQUIRED_ENVIRONMENT_KEYS] },
    production: { scope: 'production', requiredKeys: [...REQUIRED_ENVIRONMENT_KEYS] },
  },
});
