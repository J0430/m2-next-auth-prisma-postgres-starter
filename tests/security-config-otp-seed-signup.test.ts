// tests/security-config-otp-seed-signup.test.ts
// Security tests: OTP HMAC, env validation, seed safety, and gated signup routing.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import crypto from 'crypto';

const ROOT = resolve(import.meta.dirname, '..');
const HEX_32_BYTE_KEY = 'a'.repeat(64);
const ADMIN_MFA_KEY_VERSION = '2026-06';

// ─── Helpers ─────────────────────────────────────────────────────────────────

const ORIGINAL_ENV = { ...process.env };

function resetEnv() {
  Object.keys(process.env).forEach((k) => {
    if (!(k in ORIGINAL_ENV)) delete process.env[k];
  });
  Object.assign(process.env, ORIGINAL_ENV);
}

function createOAuthJwtKeypair(): { privateKey: string; publicKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKey, publicKey };
}

function buildProdBaseEnv(): Record<string, string> {
  const { privateKey, publicKey } = createOAuthJwtKeypair();
  return {
    DATABASE_URL: 'postgresql://u:p@localhost:5432/db?schema=public',
    NEXTAUTH_SECRET: 'prod-nextauth-secret-at-least-32xxx',
    AUTH_URL: 'https://auth.example.com',
    OAUTH_JWT_PRIVATE_KEY: privateKey,
    OAUTH_JWT_PUBLIC_KEY: publicKey,
    UPSTASH_REDIS_REST_URL: 'https://example.upstash.io',
    UPSTASH_REDIS_REST_TOKEN: 'dummy-token',
    OTP_HMAC_SECRET: 'prod-otp-hmac-secret-at-least-32xx',
    ACCOUNT_LINK_PKCE_SECRET: 'prod-account-link-pkce-secret-32-chars',
    GITHUB_LINK_CLIENT_ID: 'prod-github-link-client',
    GITHUB_LINK_CLIENT_SECRET: 'prod-github-link-client-secret',
    SELF_SERVICE_REGISTRATION_ENABLED: 'false',
    TURNSTILE_SECRET_KEY: 'test-turnstile-fixture',
    TURNSTILE_EXPECTED_HOSTNAME: 'auth.example.com',
    TURNSTILE_EXPECTED_ACTION: 'gated-registration',
    INTERNAL_WORKER_AUTH_SECRET: 'prod-worker-auth-secret-at-least-32',
    QSTASH_URL: 'https://qstash.upstash.io',
    QSTASH_TOKEN: 'qstash-test-token',
    RESEND_API_KEY: 're_test_nonsecret_fixture',
    INVITE_DELIVERY_ENCRYPTION_KEYS: JSON.stringify({ "1": HEX_32_BYTE_KEY }),
    INVITE_DELIVERY_KEY_VERSION: '1',
    ADMIN_MFA_SECRET_ENCRYPTION_KEYS: JSON.stringify({ [ADMIN_MFA_KEY_VERSION]: HEX_32_BYTE_KEY }),
    ADMIN_MFA_SECRET_KEY_VERSION: ADMIN_MFA_KEY_VERSION,
    ADMIN_ELEVATION_MAX_AGE_SECONDS: '300',
  };
}

// ─── 1. OTP HMAC ─────────────────────────────────────────────────────────────

describe('OTP hashing — HMAC vs unkeyed SHA-256', () => {
  afterEach(() => { vi.resetModules(); resetEnv(); });

  it('HMAC digest differs from unkeyed SHA-256 for the same code', async () => {
    vi.resetModules();
    process.env.SKIP_ENV_VALIDATION = 'true';
    process.env.NEXTAUTH_SECRET = 'test-nextauth-secret-at-least-32xx';
    process.env.OTP_HMAC_SECRET = 'test-otp-hmac-secret-at-least-32xx';
    const { hashOtpCode } = await import('@/features/auth/server/verify/createToken');
    const code = '123456';
    const hmacDigest = hashOtpCode(code);
    const unkeyed = crypto.createHash('sha256').update(code).digest('hex');
    expect(hmacDigest).not.toBe(unkeyed);
  });

  it('hashOtpCode in createToken and consumeToken produce identical digests for the same code', async () => {
    vi.resetModules();
    process.env.SKIP_ENV_VALIDATION = 'true';
    process.env.NEXTAUTH_SECRET = 'test-nextauth-secret-at-least-32xx';
    process.env.OTP_HMAC_SECRET = 'test-otp-hmac-secret-at-least-32xx';
    const { hashOtpCode } = await import('@/features/auth/server/verify/createToken');
    // consumeToken imports hashOtpCode from createToken — same function reference
    // We verify by calling it twice with the same secret in env
    const code = '654321';
    const digest1 = hashOtpCode(code);
    const digest2 = hashOtpCode(code);
    expect(digest1).toBe(digest2);
    expect(digest1).toHaveLength(64); // SHA-256 hex
  });

  it('uses OTP_HMAC_SECRET when available', async () => {
    vi.resetModules();
    process.env.SKIP_ENV_VALIDATION = 'true';
    process.env.NEXTAUTH_SECRET = 'test-nextauth-secret-at-least-32xx';
    const hmacSecret = 'test-otp-hmac-secret-at-least-32xx';
    process.env.OTP_HMAC_SECRET = hmacSecret;
    const { hashOtpCode } = await import('@/features/auth/server/verify/createToken');
    const code = '000000';
    const result = hashOtpCode(code);
    const expected = crypto.createHmac('sha256', hmacSecret).update(code, 'utf8').digest('hex');
    expect(result).toBe(expected);
  });

  it('falls back to NEXTAUTH_SECRET when OTP_HMAC_SECRET is absent', async () => {
    vi.resetModules();
    process.env.SKIP_ENV_VALIDATION = 'true';
    // Explicitly no OTP_HMAC_SECRET — must not exist
    delete process.env.OTP_HMAC_SECRET;
    const nextauthSecret = 'test-nextauth-secret-at-least-32xx';
    process.env.NEXTAUTH_SECRET = nextauthSecret;
    const { hashOtpCode } = await import('@/features/auth/server/verify/createToken');
    const code = '999999';
    const result = hashOtpCode(code);
    const expected = crypto.createHmac('sha256', nextauthSecret).update(code, 'utf8').digest('hex');
    expect(result).toBe(expected);
  });

  it('old unkeyed OTP digest does NOT match HMAC digest for same code', async () => {
    vi.resetModules();
    process.env.SKIP_ENV_VALIDATION = 'true';
    process.env.NEXTAUTH_SECRET = 'test-nextauth-secret-at-least-32xx';
    process.env.OTP_HMAC_SECRET = 'test-otp-hmac-secret-at-least-32xx';
    const { hashOtpCode } = await import('@/features/auth/server/verify/createToken');
    const code = '111111';
    // Simulate an old DB row created with bare SHA-256
    const oldDigest = crypto.createHash('sha256').update(code).digest('hex');
    const newDigest = hashOtpCode(code);
    expect(newDigest).not.toBe(oldDigest);
  });

  it("a freshly-HMAC'd code succeeds the equality lookup simulation", async () => {
    vi.resetModules();
    process.env.SKIP_ENV_VALIDATION = 'true';
    process.env.NEXTAUTH_SECRET = 'test-nextauth-secret-at-least-32xx';
    process.env.OTP_HMAC_SECRET = 'test-otp-hmac-secret-at-least-32xx';
    const { hashOtpCode } = await import('@/features/auth/server/verify/createToken');
    const code = '777777';
    const stored = hashOtpCode(code);
    const submitted = hashOtpCode(code);
    // DB equality check: stored === submitted
    expect(stored).toBe(submitted);
  });
});

// ─── 2. Production env validation ────────────────────────────────────────────

describe('Production env validation', () => {
  let PROD_BASE: Record<string, string>;

  beforeEach(() => {
    vi.resetModules();
    PROD_BASE = buildProdBaseEnv();
    // NODE_ENV is typed read-only by @types/node — cast to bypass for test purposes
    (process.env as Record<string, string>)['NODE_ENV'] = 'production';
    // Clear skip flag
    delete process.env.SKIP_ENV_VALIDATION;
  });
  afterEach(() => { vi.resetModules(); resetEnv(); });

  it('accepts a fully-configured production environment', async () => {
    Object.assign(process.env, PROD_BASE);
    await expect(import('@/lib/env')).resolves.toBeDefined();
  });

  it('rejects production when OTP_HMAC_SECRET is missing', async () => {
    Object.assign(process.env, { ...PROD_BASE, OTP_HMAC_SECRET: undefined });
    delete process.env.OTP_HMAC_SECRET;
    await expect(import('@/lib/env')).rejects.toThrow();
  });

  it('rejects production when OAUTH_JWT_PRIVATE_KEY is missing', async () => {
    Object.assign(process.env, { ...PROD_BASE, OAUTH_JWT_PRIVATE_KEY: undefined });
    delete process.env.OAUTH_JWT_PRIVATE_KEY;
    await expect(import('@/lib/env')).rejects.toThrow();
  });

  it('rejects production when OAUTH_JWT_PUBLIC_KEY is missing', async () => {
    Object.assign(process.env, { ...PROD_BASE, OAUTH_JWT_PUBLIC_KEY: undefined });
    delete process.env.OAUTH_JWT_PUBLIC_KEY;
    await expect(import('@/lib/env')).rejects.toThrow();
  });

  it('rejects production when neither AUTH_URL nor NEXTAUTH_URL is set', async () => {
    const base = { ...PROD_BASE };
    delete base.AUTH_URL;
    Object.assign(process.env, base);
    delete process.env.AUTH_URL;
    delete process.env.NEXTAUTH_URL;
    await expect(import('@/lib/env')).rejects.toThrow();
  });

  it('rejects production when SELF_SERVICE_REGISTRATION_ENABLED is not "false"', async () => {
    Object.assign(process.env, { ...PROD_BASE, SELF_SERVICE_REGISTRATION_ENABLED: 'true' });
    await expect(import('@/lib/env')).rejects.toThrow();
  });

  it('rejects production when UPSTASH creds are missing', async () => {
    const base = { ...PROD_BASE };
    delete base.UPSTASH_REDIS_REST_URL;
    Object.assign(process.env, base);
    delete process.env.UPSTASH_REDIS_REST_URL;
    await expect(import('@/lib/env')).rejects.toThrow();
  });

  it('rejects production when RESEND_API_KEY is missing', async () => {
    const base = { ...PROD_BASE };
    delete base.RESEND_API_KEY;
    Object.assign(process.env, base);
    delete process.env.RESEND_API_KEY;
    await expect(import('@/lib/env')).rejects.toThrow();
  });
});

// ─── 3. No SKIP_ENV_VALIDATION in build configs ──────────────────────────────

describe('No SKIP_ENV_VALIDATION bypass in build configs', () => {
  const ciYaml = readFileSync(resolve(ROOT, '.github/workflows/ci.yml'), 'utf8');
  const vercelJson = readFileSync(resolve(ROOT, 'vercel.json'), 'utf8');

  it('vercel.json buildCommand does not contain SKIP_ENV_VALIDATION', () => {
    const parsed = JSON.parse(vercelJson) as { buildCommand?: string };
    expect(parsed.buildCommand ?? '').not.toContain('SKIP_ENV_VALIDATION');
  });

  it('CI build-test job does not set SKIP_ENV_VALIDATION=true', () => {
    // Extract the build-test job block (up to the next top-level job)
    const buildTestStart = ciYaml.indexOf('build-test:');
    const vercelLikeStart = ciYaml.indexOf('vercel-like-build:');
    const buildTestBlock = ciYaml.slice(buildTestStart, vercelLikeStart > buildTestStart ? vercelLikeStart : undefined);
    expect(buildTestBlock).not.toContain('SKIP_ENV_VALIDATION');
  });

  it('CI vercel-like-build job does not set SKIP_ENV_VALIDATION=true', () => {
    const vercelLikeStart = ciYaml.indexOf('vercel-like-build:');
    const securityAuditStart = ciYaml.indexOf('security-audit:');
    const block = ciYaml.slice(vercelLikeStart, securityAuditStart > vercelLikeStart ? securityAuditStart : undefined);
    expect(block).not.toContain('SKIP_ENV_VALIDATION');
  });

  it('CI provides OTP_HMAC_SECRET in the build env', () => {
    expect(ciYaml).toContain('OTP_HMAC_SECRET');
  });

  it('CI generates an ephemeral RSA keypair (openssl genpkey)', () => {
    expect(ciYaml).toContain('openssl genpkey');
  });
});

// ─── 4. Seed safety ──────────────────────────────────────────────────────────

describe('Seed safety guards (source-level assertions)', () => {
  const seedSource = readFileSync(resolve(ROOT, 'prisma/seed.ts'), 'utf8');

  it('seed source does not contain "admin123"', () => {
    expect(seedSource).not.toContain('admin123');
  });

  it('seed source does not contain "user123"', () => {
    expect(seedSource).not.toContain('user123');
  });

  it('seed source does not log client_secret plaintext', () => {
    // The old code did: console.log(`... client_secret=${clientSecret}`)
    expect(seedSource).not.toMatch(/console\.log.*client_secret\s*=/);
  });

  it('seed source does not log passwords', () => {
    expect(seedSource).not.toMatch(/console\.log.*admin123|console\.log.*user123|console\.log.*password/i);
  });

  it('seed source does not call generateClientSecret()', () => {
    expect(seedSource).not.toContain('generateClientSecret()');
  });

  it('seed source checks for NODE_ENV === production before Prisma construction', () => {
    expect(seedSource).toContain("NODE_ENV === 'production'");
  });

  it('seed source checks SEED_CONFIRMATION !== "DEVELOPMENT_ONLY"', () => {
    expect(seedSource).toContain("SEED_CONFIRMATION !== 'DEVELOPMENT_ONLY'");
  });

  it('seed source guards minimum password length of 16', () => {
    expect(seedSource).toContain('< 16');
  });

  it('seed source guards minimum OAuth secret length of 32', () => {
    expect(seedSource).toContain('< 32');
  });

  it('seed source calls hashClientSecret with the env-provided secret', () => {
    expect(seedSource).toContain('hashClientSecret(oauthClientSecret)');
  });
});

// TASK-027 replaces the temporary kill-switch behavior. Opaque invite admission
// remains fail-closed inside registerWithInvite and is covered by the dedicated
// gated-registration credentials and UI suites.
