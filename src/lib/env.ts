// src/lib/env.ts
import { z } from 'zod';

const HexEncoded32ByteKeySchema = z
  .string()
  .regex(/^[a-f0-9]{64}$/i, "Must be a 32-byte hex-encoded key");

const AdminMfaSecretKeyringSchema = z
  .record(z.string().min(1), HexEncoded32ByteKeySchema)
  .refine((keyring) => Object.keys(keyring).length > 0, {
    message: "ADMIN_MFA_SECRET_ENCRYPTION_KEYS must contain at least one key version",
  });

const AdminMfaSecretKeyringEnvSchema = z
  .string()
  .transform((value, ctx): unknown => {
    try {
      const parsedJson: unknown = JSON.parse(value);
      return parsedJson;
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "ADMIN_MFA_SECRET_ENCRYPTION_KEYS must be valid JSON",
      });
      return z.NEVER;
    }
  })
  .pipe(AdminMfaSecretKeyringSchema);

const InviteDeliveryKeyringSchema = z
  .record(z.string().regex(/^\d+$/), HexEncoded32ByteKeySchema)
  .refine((keyring) => Object.keys(keyring).length > 0, {
    message: "INVITE_DELIVERY_ENCRYPTION_KEYS must contain at least one key version",
  });

const InviteDeliveryKeyringEnvSchema = z.string().transform((value, ctx): unknown => {
  try { return JSON.parse(value) as unknown; }
  catch {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "INVITE_DELIVERY_ENCRYPTION_KEYS must be valid JSON" });
    return z.NEVER;
  }
}).pipe(InviteDeliveryKeyringSchema);

const AdminElevationMaxAgeSchema = z.coerce
  .number()
  .int()
  .refine((value) => value === 300, {
    message: "ADMIN_ELEVATION_MAX_AGE_SECONDS must be 300",
  })
  .default(300);

const EnvSchema = z.object({
  DATABASE_URL: z.string().url(),
  NEXTAUTH_SECRET: z
    .string()
    .min(32, "NEXTAUTH_SECRET must be at least 32 characters for production security"),
  OAUTH_JWT_PRIVATE_KEY: z.string().min(1).optional(),
  OAUTH_JWT_PUBLIC_KEY: z.string().min(1).optional(),
  OAUTH_JWT_KID: z.string().optional(),
  NEXTAUTH_URL: z.string().url().optional(), // Vercel will set AUTH_URL/NEXTAUTH_URL
  AUTH_URL: z.string().url().optional(),
  APP_URL: z.string().url().optional(),
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
  GITHUB_LINK_CLIENT_ID: z.string().optional(),
  GITHUB_LINK_CLIENT_SECRET: z.string().optional(),
  ACCOUNT_LINK_PKCE_SECRET: z.string().min(32).optional(),
  RESEND_API_KEY: z.string().optional(),
  RESEND_FROM: z.string().optional(),
  VERIFY_TOKEN_TTL_MINUTES: z.coerce.number().int().positive().default(10),
  VERIFY_RESEND_COOLDOWN_MINUTES: z.coerce.number().int().positive().default(2),
  RESET_TOKEN_TTL_MINUTES: z.coerce.number().int().positive().default(30),
  RESET_RESEND_COOLDOWN_MINUTES: z.coerce.number().int().positive().default(2),
  UPSTASH_REDIS_REST_URL: z.string().url().optional(),
  UPSTASH_REDIS_REST_TOKEN: z.string().optional(),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(3),
  RATE_LIMIT_WINDOW_MINUTES: z.coerce.number().int().positive().default(60),
  // Security hardening
  ACCOUNT_LOCKOUT_THRESHOLD: z.coerce.number().int().positive().default(5),
  ACCOUNT_LOCKOUT_MINUTES: z.coerce.number().int().positive().default(30),
  SESSION_IDLE_TIMEOUT_MINUTES: z.coerce.number().int().positive().default(30),
  MFA_ISSUER: z.string().default("ManuMu Studio"),
  HIBP_ENABLED: z.enum(["true", "false"]).default("false").transform(v => v === "true"),
  VERCEL: z.enum(["1"]).optional(),
  // OTP HMAC key — required in production, optional in dev (falls back to NEXTAUTH_SECRET)
  OTP_HMAC_SECRET: z.string().min(32).optional(),
  // Self-service registration kill switch
  SELF_SERVICE_REGISTRATION_ENABLED: z.enum(["true", "false"]).default("true"),
  // Packet 02 gated-registration controls
  TURNSTILE_SECRET_KEY: z.string().min(1).optional(),
  TURNSTILE_EXPECTED_HOSTNAME: z.string().min(1).optional(),
  TURNSTILE_EXPECTED_ACTION: z.string().min(1).optional(),
  INTERNAL_WORKER_AUTH_SECRET: z.string().min(32).optional(),
  QSTASH_URL: z.string().url().optional(),
  QSTASH_TOKEN: z.string().min(1).optional(),
  INVITE_DELIVERY_ENCRYPTION_KEYS: InviteDeliveryKeyringEnvSchema.optional(),
  INVITE_DELIVERY_KEY_VERSION: z.string().min(1).optional(),
  ADMIN_MFA_SECRET_ENCRYPTION_KEYS: AdminMfaSecretKeyringEnvSchema.optional(),
  ADMIN_MFA_SECRET_KEY_VERSION: z.string().min(1).optional(),
  ADMIN_ELEVATION_MAX_AGE_SECONDS: AdminElevationMaxAgeSchema,
  // Seed-only optional fields (never set in production)
  SEED_ADMIN_PASSWORD: z.string().optional(),
  SEED_USER_PASSWORD: z.string().optional(),
  SEED_OAUTH_CLIENT_SECRET: z.string().optional(),
  SEED_CONFIRMATION: z.string().optional(),
  ALLOW_USER_BOOTSTRAP: z.enum(["true", "false"]).default("false").transform(value => value === "true"),
});

const requireProductionValue = (ctx: z.RefinementCtx, path: string, value: unknown) => {
  if (value === undefined || value === null || value === "") {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: [path],
      message: `${path} is required in production`,
    });
  }
};

// Production requires Upstash: the in-memory rate-limit fallback is a no-op on
// serverless (each cold start gets a fresh process), so missing Upstash creds
// silently disable rate limiting. Fail boot instead of degrading insecurely.
// Applied only on the full-validation path; the SKIP_ENV_VALIDATION path uses
// EnvSchema.partial() (a ZodObject method unavailable on the ZodEffects below).
const EnvSchemaProd = EnvSchema.superRefine((data, ctx) => {
  if (process.env.NODE_ENV === "production") {
    if (!data.UPSTASH_REDIS_REST_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["UPSTASH_REDIS_REST_URL"],
        message: "UPSTASH_REDIS_REST_URL is required in production",
      });
    }
    if (!data.UPSTASH_REDIS_REST_TOKEN) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["UPSTASH_REDIS_REST_TOKEN"],
        message: "UPSTASH_REDIS_REST_TOKEN is required in production",
      });
    }
    if (!data.OAUTH_JWT_PRIVATE_KEY) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["OAUTH_JWT_PRIVATE_KEY"],
        message: "OAUTH_JWT_PRIVATE_KEY is required in production",
      });
    }
    if (!data.OAUTH_JWT_PUBLIC_KEY) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["OAUTH_JWT_PUBLIC_KEY"],
        message: "OAUTH_JWT_PUBLIC_KEY is required in production",
      });
    }
    if (!data.AUTH_URL && !data.NEXTAUTH_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["AUTH_URL"],
        message: "AUTH_URL or NEXTAUTH_URL is required in production",
      });
    }
    if (!data.OTP_HMAC_SECRET) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["OTP_HMAC_SECRET"],
        message: "OTP_HMAC_SECRET is required in production (min 32 chars)",
      });
    }
    requireProductionValue(ctx, "ACCOUNT_LINK_PKCE_SECRET", data.ACCOUNT_LINK_PKCE_SECRET);
    requireProductionValue(ctx, "GITHUB_LINK_CLIENT_ID", data.GITHUB_LINK_CLIENT_ID);
    requireProductionValue(ctx, "GITHUB_LINK_CLIENT_SECRET", data.GITHUB_LINK_CLIENT_SECRET);
    if (data.SELF_SERVICE_REGISTRATION_ENABLED !== "false") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["SELF_SERVICE_REGISTRATION_ENABLED"],
        message: 'SELF_SERVICE_REGISTRATION_ENABLED must be "false" in production until invite gating ships',
      });
    }
    requireProductionValue(ctx, "TURNSTILE_SECRET_KEY", data.TURNSTILE_SECRET_KEY);
    requireProductionValue(ctx, "TURNSTILE_EXPECTED_HOSTNAME", data.TURNSTILE_EXPECTED_HOSTNAME);
    requireProductionValue(ctx, "TURNSTILE_EXPECTED_ACTION", data.TURNSTILE_EXPECTED_ACTION);
    requireProductionValue(ctx, "INTERNAL_WORKER_AUTH_SECRET", data.INTERNAL_WORKER_AUTH_SECRET);
    requireProductionValue(ctx, "QSTASH_URL", data.QSTASH_URL);
    requireProductionValue(ctx, "QSTASH_TOKEN", data.QSTASH_TOKEN);
    requireProductionValue(ctx, "RESEND_API_KEY", data.RESEND_API_KEY);
    requireProductionValue(ctx, "INVITE_DELIVERY_ENCRYPTION_KEYS", data.INVITE_DELIVERY_ENCRYPTION_KEYS);
    requireProductionValue(ctx, "INVITE_DELIVERY_KEY_VERSION", data.INVITE_DELIVERY_KEY_VERSION);
    if (data.INVITE_DELIVERY_ENCRYPTION_KEYS && data.INVITE_DELIVERY_KEY_VERSION &&
      !Object.prototype.hasOwnProperty.call(data.INVITE_DELIVERY_ENCRYPTION_KEYS, data.INVITE_DELIVERY_KEY_VERSION)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["INVITE_DELIVERY_KEY_VERSION"], message: "INVITE_DELIVERY_KEY_VERSION must exist in INVITE_DELIVERY_ENCRYPTION_KEYS" });
    }
    requireProductionValue(ctx, "ADMIN_MFA_SECRET_ENCRYPTION_KEYS", data.ADMIN_MFA_SECRET_ENCRYPTION_KEYS);
    requireProductionValue(ctx, "ADMIN_MFA_SECRET_KEY_VERSION", data.ADMIN_MFA_SECRET_KEY_VERSION);
    if (
      data.ADMIN_MFA_SECRET_ENCRYPTION_KEYS &&
      data.ADMIN_MFA_SECRET_KEY_VERSION &&
      !Object.prototype.hasOwnProperty.call(
        data.ADMIN_MFA_SECRET_ENCRYPTION_KEYS,
        data.ADMIN_MFA_SECRET_KEY_VERSION
      )
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["ADMIN_MFA_SECRET_KEY_VERSION"],
        message: "ADMIN_MFA_SECRET_KEY_VERSION must exist in ADMIN_MFA_SECRET_ENCRYPTION_KEYS",
      });
    }
  }
});

const shouldSkipValidation = process.env.SKIP_ENV_VALIDATION === "true";

const normalizeEnvValue = (value: string | undefined) => {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

const rawEnv = {
  DATABASE_URL: normalizeEnvValue(process.env.DATABASE_URL),
  NEXTAUTH_SECRET: normalizeEnvValue(process.env.NEXTAUTH_SECRET),
  OAUTH_JWT_PRIVATE_KEY: normalizeEnvValue(process.env.OAUTH_JWT_PRIVATE_KEY),
  OAUTH_JWT_PUBLIC_KEY: normalizeEnvValue(process.env.OAUTH_JWT_PUBLIC_KEY),
  OAUTH_JWT_KID: normalizeEnvValue(process.env.OAUTH_JWT_KID),
  NEXTAUTH_URL: normalizeEnvValue(process.env.NEXTAUTH_URL),
  AUTH_URL: normalizeEnvValue(process.env.AUTH_URL),
  APP_URL: normalizeEnvValue(process.env.APP_URL),
  GOOGLE_CLIENT_ID: normalizeEnvValue(process.env.GOOGLE_CLIENT_ID),
  GOOGLE_CLIENT_SECRET: normalizeEnvValue(process.env.GOOGLE_CLIENT_SECRET),
  GITHUB_CLIENT_ID: normalizeEnvValue(process.env.GITHUB_CLIENT_ID),
  GITHUB_CLIENT_SECRET: normalizeEnvValue(process.env.GITHUB_CLIENT_SECRET),
  GITHUB_LINK_CLIENT_ID: normalizeEnvValue(process.env.GITHUB_LINK_CLIENT_ID),
  GITHUB_LINK_CLIENT_SECRET: normalizeEnvValue(process.env.GITHUB_LINK_CLIENT_SECRET),
  ACCOUNT_LINK_PKCE_SECRET: normalizeEnvValue(process.env.ACCOUNT_LINK_PKCE_SECRET),
  RESEND_API_KEY: normalizeEnvValue(process.env.RESEND_API_KEY),
  RESEND_FROM: normalizeEnvValue(process.env.RESEND_FROM),
  VERIFY_TOKEN_TTL_MINUTES: normalizeEnvValue(process.env.VERIFY_TOKEN_TTL_MINUTES),
  VERIFY_RESEND_COOLDOWN_MINUTES: normalizeEnvValue(process.env.VERIFY_RESEND_COOLDOWN_MINUTES),
  RESET_TOKEN_TTL_MINUTES: normalizeEnvValue(process.env.RESET_TOKEN_TTL_MINUTES),
  RESET_RESEND_COOLDOWN_MINUTES: normalizeEnvValue(process.env.RESET_RESEND_COOLDOWN_MINUTES),
  UPSTASH_REDIS_REST_URL: normalizeEnvValue(process.env.UPSTASH_REDIS_REST_URL),
  UPSTASH_REDIS_REST_TOKEN: normalizeEnvValue(process.env.UPSTASH_REDIS_REST_TOKEN),
  RATE_LIMIT_MAX: normalizeEnvValue(process.env.RATE_LIMIT_MAX),
  RATE_LIMIT_WINDOW_MINUTES: normalizeEnvValue(process.env.RATE_LIMIT_WINDOW_MINUTES),
  // Security hardening
  ACCOUNT_LOCKOUT_THRESHOLD: normalizeEnvValue(process.env.ACCOUNT_LOCKOUT_THRESHOLD),
  ACCOUNT_LOCKOUT_MINUTES: normalizeEnvValue(process.env.ACCOUNT_LOCKOUT_MINUTES),
  SESSION_IDLE_TIMEOUT_MINUTES: normalizeEnvValue(process.env.SESSION_IDLE_TIMEOUT_MINUTES),
  MFA_ISSUER: normalizeEnvValue(process.env.MFA_ISSUER),
  HIBP_ENABLED: normalizeEnvValue(process.env.HIBP_ENABLED),
  VERCEL: normalizeEnvValue(process.env.VERCEL),
  OTP_HMAC_SECRET: normalizeEnvValue(process.env.OTP_HMAC_SECRET),
  SELF_SERVICE_REGISTRATION_ENABLED: normalizeEnvValue(process.env.SELF_SERVICE_REGISTRATION_ENABLED),
  TURNSTILE_SECRET_KEY: normalizeEnvValue(process.env.TURNSTILE_SECRET_KEY),
  TURNSTILE_EXPECTED_HOSTNAME: normalizeEnvValue(process.env.TURNSTILE_EXPECTED_HOSTNAME),
  TURNSTILE_EXPECTED_ACTION: normalizeEnvValue(process.env.TURNSTILE_EXPECTED_ACTION),
  INTERNAL_WORKER_AUTH_SECRET: normalizeEnvValue(process.env.INTERNAL_WORKER_AUTH_SECRET),
  QSTASH_URL: normalizeEnvValue(process.env.QSTASH_URL),
  QSTASH_TOKEN: normalizeEnvValue(process.env.QSTASH_TOKEN),
  INVITE_DELIVERY_ENCRYPTION_KEYS: normalizeEnvValue(process.env.INVITE_DELIVERY_ENCRYPTION_KEYS),
  INVITE_DELIVERY_KEY_VERSION: normalizeEnvValue(process.env.INVITE_DELIVERY_KEY_VERSION),
  ADMIN_MFA_SECRET_ENCRYPTION_KEYS: normalizeEnvValue(process.env.ADMIN_MFA_SECRET_ENCRYPTION_KEYS),
  ADMIN_MFA_SECRET_KEY_VERSION: normalizeEnvValue(process.env.ADMIN_MFA_SECRET_KEY_VERSION),
  ADMIN_ELEVATION_MAX_AGE_SECONDS: normalizeEnvValue(process.env.ADMIN_ELEVATION_MAX_AGE_SECONDS),
  SEED_ADMIN_PASSWORD: normalizeEnvValue(process.env.SEED_ADMIN_PASSWORD),
  SEED_USER_PASSWORD: normalizeEnvValue(process.env.SEED_USER_PASSWORD),
  SEED_OAUTH_CLIENT_SECRET: normalizeEnvValue(process.env.SEED_OAUTH_CLIENT_SECRET),
  SEED_CONFIRMATION: normalizeEnvValue(process.env.SEED_CONFIRMATION),
  ALLOW_USER_BOOTSTRAP: normalizeEnvValue(process.env.ALLOW_USER_BOOTSTRAP),
};

const parsed = (shouldSkipValidation ? EnvSchema.partial() : EnvSchemaProd).safeParse(rawEnv);
if (!parsed.success) {
  throw parsed.error;
}

export const env = parsed.data as z.infer<typeof EnvSchema>;
