// tests/gated-registration-admission.test.ts
// Verifies Packet 02 admission controls, fail-closed env contracts, and limiter dimensions.
import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_ENV = { ...process.env };
const HEX_32_BYTE_KEY = "a".repeat(64);
const ADMIN_MFA_KEY_VERSION = "2026-06";
const INVITE_HASH = "b".repeat(64);

const PACKET_02_REQUIRED_PROD_KEYS = [
  "TURNSTILE_SECRET_KEY",
  "TURNSTILE_EXPECTED_HOSTNAME",
  "TURNSTILE_EXPECTED_ACTION",
  "INTERNAL_WORKER_AUTH_SECRET",
  "QSTASH_URL",
  "QSTASH_TOKEN",
  "RESEND_API_KEY",
  "INVITE_DELIVERY_ENCRYPTION_KEYS",
  "INVITE_DELIVERY_KEY_VERSION",
  "ADMIN_MFA_SECRET_ENCRYPTION_KEYS",
  "ADMIN_MFA_SECRET_KEY_VERSION",
  "ACCOUNT_LINK_PKCE_SECRET",
  "GITHUB_LINK_CLIENT_ID",
  "GITHUB_LINK_CLIENT_SECRET",
];

function resetEnv() {
  Object.keys(process.env).forEach((key) => {
    if (!(key in ORIGINAL_ENV)) delete process.env[key];
  });
  Object.assign(process.env, ORIGINAL_ENV);
}

function buildProdEnv(): Record<string, string> {
  return {
    DATABASE_URL: "postgresql://user:password@localhost:5432/app?schema=public",
    NEXTAUTH_SECRET: "prod-nextauth-secret-at-least-32-characters",
    AUTH_URL: "https://auth.example.com",
    OAUTH_JWT_PRIVATE_KEY: "test-private-key",
    OAUTH_JWT_PUBLIC_KEY: "test-public-key",
    UPSTASH_REDIS_REST_URL: "https://example.upstash.io",
    UPSTASH_REDIS_REST_TOKEN: "prod-upstash-token",
    OTP_HMAC_SECRET: "prod-otp-hmac-secret-at-least-32-chars",
    ACCOUNT_LINK_PKCE_SECRET: "prod-account-link-pkce-secret-32-chars",
    GITHUB_LINK_CLIENT_ID: "prod-github-link-client",
    GITHUB_LINK_CLIENT_SECRET: "prod-github-link-client-secret",
    SELF_SERVICE_REGISTRATION_ENABLED: "false",
    TURNSTILE_SECRET_KEY: "test-turnstile-fixture",
    TURNSTILE_EXPECTED_HOSTNAME: "auth.example.com",
    TURNSTILE_EXPECTED_ACTION: "gated-registration",
    INTERNAL_WORKER_AUTH_SECRET: "prod-worker-auth-secret-at-least-32",
    QSTASH_URL: "https://qstash.upstash.io",
    QSTASH_TOKEN: "qstash-test-token",
    RESEND_API_KEY: "re_test_nonsecret_fixture",
    INVITE_DELIVERY_ENCRYPTION_KEYS: JSON.stringify({ "1": HEX_32_BYTE_KEY }),
    INVITE_DELIVERY_KEY_VERSION: "1",
    ADMIN_MFA_SECRET_ENCRYPTION_KEYS: JSON.stringify({ [ADMIN_MFA_KEY_VERSION]: HEX_32_BYTE_KEY }),
    ADMIN_MFA_SECRET_KEY_VERSION: ADMIN_MFA_KEY_VERSION,
    ADMIN_ELEVATION_MAX_AGE_SECONDS: "300",
  };
}

function sha256Hex(value: string) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function setEnvValue(key: string, value: string) {
  process.env[key] = value;
}

async function importEnvWith(values: Record<string, string>) {
  vi.resetModules();
  resetEnv();
  setEnvValue("NODE_ENV", "production");
  delete process.env.SKIP_ENV_VALIDATION;
  Object.assign(process.env, values);
  return import("@/lib/env");
}

afterEach(() => {
  vi.resetModules();
  vi.doUnmock("@/lib/rateLimit");
  vi.doUnmock("@/features/auth/server/verify/resend");
  vi.doUnmock("@/lib/prisma");
  vi.doUnmock("next/headers");
  resetEnv();
});

describe("Packet 02 production env contract", () => {
  it("accepts a production environment with every Packet 02 control active", async () => {
    const { env } = await importEnvWith(buildProdEnv());

    expect(env.TURNSTILE_SECRET_KEY).toBe("test-turnstile-fixture");
    expect(env.TURNSTILE_EXPECTED_HOSTNAME).toBe("auth.example.com");
    expect(env.TURNSTILE_EXPECTED_ACTION).toBe("gated-registration");
    expect(env.INTERNAL_WORKER_AUTH_SECRET).toBe("prod-worker-auth-secret-at-least-32");
    expect(env.INVITE_DELIVERY_ENCRYPTION_KEYS).toEqual({ "1": HEX_32_BYTE_KEY });
    expect(env.INVITE_DELIVERY_KEY_VERSION).toBe("1");
    expect(env.ADMIN_MFA_SECRET_ENCRYPTION_KEYS).toEqual({
      [ADMIN_MFA_KEY_VERSION]: HEX_32_BYTE_KEY,
    });
    expect(env.ADMIN_MFA_SECRET_KEY_VERSION).toBe(ADMIN_MFA_KEY_VERSION);
    expect(env.ADMIN_ELEVATION_MAX_AGE_SECONDS).toBe(300);
  });

  it.each(PACKET_02_REQUIRED_PROD_KEYS)("rejects production when %s is missing", async (key) => {
    const values = buildProdEnv();
    delete values[key];

    await expect(importEnvWith(values)).rejects.toThrow();
  });

  it("rejects production when the Admin-MFA keyring is malformed JSON", async () => {
    await expect(
      importEnvWith({
        ...buildProdEnv(),
        ADMIN_MFA_SECRET_ENCRYPTION_KEYS: "{not-json",
      })
    ).rejects.toThrow();
  });

  it("keeps admin elevation fixed at the safe 300-second default when omitted", async () => {
    const values = buildProdEnv();
    delete values.ADMIN_ELEVATION_MAX_AGE_SECONDS;
    const { env } = await importEnvWith(values);
    expect(env.ADMIN_ELEVATION_MAX_AGE_SECONDS).toBe(300);
  });

  it("rejects production when the Admin-MFA write version is absent from the keyring", async () => {
    await expect(
      importEnvWith({
        ...buildProdEnv(),
        ADMIN_MFA_SECRET_ENCRYPTION_KEYS: JSON.stringify({ old: HEX_32_BYTE_KEY }),
      })
    ).rejects.toThrow();
  });
});

describe("Packet 02 rate-limit dimensions", () => {
  beforeEach(() => {
    vi.resetModules();
    resetEnv();
    process.env.SKIP_ENV_VALIDATION = "true";
    process.env.DATABASE_URL = "postgresql://user:password@localhost:5432/app?schema=public";
    process.env.NEXTAUTH_SECRET = "test-nextauth-secret-at-least-32";
  });

  it("wires the six public surfaces plus admin operations to their independent dimensions", async () => {
    const { buildAdmissionRateLimitChecks } = await import("@/lib/rateLimit");

    const base = {
      ip: "203.0.113.10",
      accountIdentifier: "User@Example.com",
      inviteTokenHash: INVITE_HASH,
      adminActorId: "admin-user-1",
    };

    expect(buildAdmissionRateLimitChecks({ ...base, surface: "fragment-exchange" }).map((check) => check.scope)).toEqual([
      "ip",
      "invite",
      "global-exchange-write",
    ]);
    expect(buildAdmissionRateLimitChecks({ ...base, surface: "registration" }).map((check) => check.scope)).toEqual([
      "ip",
      "account",
      "invite",
    ]);
    expect(buildAdmissionRateLimitChecks({ ...base, surface: "invite-redemption" }).map((check) => check.scope)).toEqual([
      "ip",
      "invite",
    ]);
    expect(buildAdmissionRateLimitChecks({ ...base, surface: "login" }).map((check) => check.scope)).toEqual([
      "ip",
      "account",
    ]);
    expect(buildAdmissionRateLimitChecks({ ...base, surface: "password-reset" }).map((check) => check.scope)).toEqual([
      "ip",
      "account",
    ]);
    expect(buildAdmissionRateLimitChecks({ ...base, surface: "otp-verify" }).map((check) => check.scope)).toEqual([
      "ip",
      "account",
    ]);
    expect(buildAdmissionRateLimitChecks({ ...base, surface: "admin-operation" }).map((check) => check.scope)).toEqual([
      "admin",
      "ip",
    ]);
  });

  it("hashes account identifiers and raw fragment tokens before building limiter keys", async () => {
    const { buildAdmissionRateLimitChecks, buildRateLimitKey } = await import("@/lib/rateLimit");
    const rawToken = "raw-fragment-token-secret";
    const rawEmail = "User@Example.com";

    const legacyKey = buildRateLimitKey({
      scope: "password_reset",
      ip: "203.0.113.10",
      email: rawEmail,
    });
    const checks = buildAdmissionRateLimitChecks({
      surface: "registration",
      ip: "203.0.113.10",
      accountIdentifier: rawEmail,
      inviteTokenHash: rawToken,
    });
    const combinedKeys = [legacyKey, ...checks.map((check) => check.key)].join("\n");

    expect(combinedKeys).not.toContain(rawEmail);
    expect(combinedKeys).not.toContain(rawEmail.toLowerCase());
    expect(combinedKeys).not.toContain(rawToken);
    expect(combinedKeys).toContain(sha256Hex(rawEmail.toLowerCase()));
    expect(combinedKeys).toContain(sha256Hex(rawToken));
  });

  it("exhausting one dimension does not consume another dimension bucket", async () => {
    const { buildAdmissionRateLimitChecks, memoryLimit, memoryStore } = await import("@/lib/rateLimit");
    memoryStore.clear();

    const checks = buildAdmissionRateLimitChecks({
      surface: "registration",
      ip: "203.0.113.10",
      accountIdentifier: "user@example.com",
      inviteTokenHash: INVITE_HASH,
    });
    const ipCheck = checks.find((check) => check.scope === "ip");
    const accountCheck = checks.find((check) => check.scope === "account");

    expect(ipCheck).toBeDefined();
    expect(accountCheck).toBeDefined();

    if (!ipCheck || !accountCheck) throw new Error("missing limiter dimensions");

    for (let attempt = 0; attempt < 6; attempt += 1) {
      memoryLimit(ipCheck.key, ipCheck.policy);
    }

    const accountResult = memoryLimit(accountCheck.key, accountCheck.policy);
    expect(accountResult.success).toBe(true);
    expect(accountResult.remaining).toBe(accountResult.limit - 1);
  });

  it.each([
    ["ip", "account"],
    ["account", "ip"],
    ["ip", "invite"],
    ["invite", "ip"],
    ["account", "invite"],
    ["invite", "account"],
  ] as const)(
    "rejects registration atomically when %s is exhausted without consuming %s",
    async (exhaustedScope, untouchedScope) => {
      const { buildAdmissionRateLimitChecks, memoryLimit, memoryStore, rateLimitAll } =
        await import("@/lib/rateLimit");
      memoryStore.clear();
      const checks = buildAdmissionRateLimitChecks({
        surface: "registration",
        ip: "203.0.113.21",
        accountIdentifier: "atomic@example.com",
        inviteTokenHash: INVITE_HASH,
      });
      const exhausted = checks.find((check) => check.scope === exhaustedScope);
      const untouched = checks.find((check) => check.scope === untouchedScope);
      if (!exhausted || !untouched) throw new Error("missing registration limiter dimension");

      let seed = memoryLimit(exhausted.key, exhausted.policy);
      for (let attempt = 1; attempt < seed.limit; attempt += 1) {
        seed = memoryLimit(exhausted.key, exhausted.policy);
      }

      await expect(rateLimitAll(checks)).resolves.toMatchObject({ success: false });
      const untouchedResult = memoryLimit(untouched.key, untouched.policy);
      expect(untouchedResult.remaining).toBe(untouchedResult.limit - 1);
    },
  );

  it.each([
    ["ip", "invite"],
    ["invite", "ip"],
    ["ip", "global-exchange-write"],
    ["global-exchange-write", "ip"],
    ["invite", "global-exchange-write"],
    ["global-exchange-write", "invite"],
  ] as const)(
    "rejects exchange atomically when %s is exhausted without consuming %s",
    async (exhaustedScope, untouchedScope) => {
      const { buildAdmissionRateLimitChecks, memoryLimit, memoryStore, rateLimitAll } =
        await import("@/lib/rateLimit");
      memoryStore.clear();
      const checks = buildAdmissionRateLimitChecks({
        surface: "fragment-exchange",
        ip: "203.0.113.22",
        inviteTokenHash: INVITE_HASH,
      });
      const exhausted = checks.find((check) => check.scope === exhaustedScope);
      const untouched = checks.find((check) => check.scope === untouchedScope);
      if (!exhausted || !untouched) throw new Error("missing exchange limiter dimension");

      let seed = memoryLimit(exhausted.key, exhausted.policy);
      for (let attempt = 1; attempt < seed.limit; attempt += 1) {
        seed = memoryLimit(exhausted.key, exhausted.policy);
      }

      await expect(rateLimitAll(checks)).resolves.toMatchObject({ success: false });
      const untouchedResult = memoryLimit(untouched.key, untouched.policy);
      expect(untouchedResult.remaining).toBe(untouchedResult.limit - 1);
    },
  );

  it("admits one concurrent exchange at the global boundary and charges every dimension once", async () => {
    const { buildAdmissionRateLimitChecks, memoryLimit, memoryStore, rateLimitAll } =
      await import("@/lib/rateLimit");
    memoryStore.clear();
    const checks = buildAdmissionRateLimitChecks({
      surface: "fragment-exchange",
      ip: "203.0.113.23",
      inviteTokenHash: INVITE_HASH,
    });
    const global = checks.find((check) => check.scope === "global-exchange-write");
    const ip = checks.find((check) => check.scope === "ip");
    const invite = checks.find((check) => check.scope === "invite");
    if (!global || !ip || !invite) throw new Error("missing exchange limiter dimension");

    const firstSeed = memoryLimit(global.key, global.policy);
    for (let attempt = 1; attempt < firstSeed.limit - 1; attempt += 1) {
      memoryLimit(global.key, global.policy);
    }

    const results = await Promise.all([rateLimitAll(checks), rateLimitAll(checks)]);
    expect(results.filter((result) => result.success)).toHaveLength(1);
    const ipProbe = memoryLimit(ip.key, ip.policy);
    const inviteProbe = memoryLimit(invite.key, invite.policy);
    expect(ipProbe.remaining).toBe(ipProbe.limit - 2);
    expect(inviteProbe.remaining).toBe(inviteProbe.limit - 2);
  });
});

describe("Packet 02 Turnstile verifier", () => {
  beforeEach(() => {
    vi.resetModules();
    resetEnv();
    process.env.SKIP_ENV_VALIDATION = "true";
    process.env.DATABASE_URL = "postgresql://user:password@localhost:5432/app?schema=public";
    process.env.NEXTAUTH_SECRET = "test-nextauth-secret-at-least-32";
    process.env.TURNSTILE_SECRET_KEY = "turnstile-secret-for-tests";
    process.env.TURNSTILE_EXPECTED_HOSTNAME = "auth.example.com";
    process.env.TURNSTILE_EXPECTED_ACTION = "gated-registration";
  });

  it("accepts a fresh siteverify success for the configured hostname and action", async () => {
    let capturedBody: BodyInit | null | undefined;
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedBody = init?.body;
      return Response.json({
        success: true,
        challenge_ts: new Date().toISOString(),
        hostname: "auth.example.com",
        action: "gated-registration",
      });
    });
    const { verifyTurnstileToken } = await import("@/features/auth/lib/turnstile");

    const result = await verifyTurnstileToken({
      token: "single-use-token",
      remoteIp: "203.0.113.10",
      fetcher,
    });

    expect(result).toEqual({ ok: true });
    expect(String(capturedBody)).toContain("secret=turnstile-secret-for-tests");
    expect(String(capturedBody)).toContain("response=single-use-token");
    expect(String(capturedBody)).toContain("remoteip=203.0.113.10");
  });

  it.each([
    {
      name: "duplicate token",
      payload: { success: false, "error-codes": ["timeout-or-duplicate"] },
    },
    {
      name: "wrong action",
      payload: {
        success: true,
        challenge_ts: new Date().toISOString(),
        hostname: "auth.example.com",
        action: "other-action",
      },
    },
    {
      name: "wrong hostname",
      payload: {
        success: true,
        challenge_ts: new Date().toISOString(),
        hostname: "evil.example.com",
        action: "gated-registration",
      },
    },
    {
      name: "stale token",
      payload: {
        success: true,
        challenge_ts: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
        hostname: "auth.example.com",
        action: "gated-registration",
      },
    },
    {
      name: "malformed response",
      payload: { success: true, hostname: "auth.example.com" },
    },
  ])("fails closed for $name with only a support id", async ({ payload }) => {
    const fetcher = vi.fn(async () => Response.json(payload));
    const { verifyTurnstileToken } = await import("@/features/auth/lib/turnstile");

    const result = await verifyTurnstileToken({
      token: "single-use-token",
      remoteIp: "203.0.113.10",
      fetcher,
    });

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected fail-closed Turnstile result");
    expect(result.supportId).toMatch(/^turnstile_/);
    expect(JSON.stringify(result)).not.toContain("single-use-token");
  });

  it("fails closed when siteverify is unavailable", async () => {
    const fetcher = vi.fn(async () => {
      throw new Error("network down");
    });
    const { verifyTurnstileToken } = await import("@/features/auth/lib/turnstile");

    const result = await verifyTurnstileToken({
      token: "single-use-token",
      fetcher,
    });

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected fail-closed Turnstile result");
    expect(result.supportId).toMatch(/^turnstile_/);
  });
});

describe("Packet 02 shared admission helpers", () => {
  it("returns one generic failure envelope for public and admin admission denials", async () => {
    const { createGenericAdmissionFailure } = await import("@/features/auth/server/admission");

    const publicFailure = createGenericAdmissionFailure();
    const adminFailure = createGenericAdmissionFailure();

    expect(publicFailure.ok).toBe(false);
    expect(adminFailure.ok).toBe(false);
    expect(publicFailure.status).toBe(adminFailure.status);
    expect(publicFailure.body.message).toBe(adminFailure.body.message);
    expect(publicFailure.body.supportId).toMatch(/^admission_/);
    expect(adminFailure.body.supportId).toMatch(/^admission_/);
    expect(JSON.stringify(publicFailure)).not.toMatch(/csrf|turnstile|allowlist|invite|mfa|capability/i);
  });

  it("validates Origin, Sec-Fetch-Site, and the per-session CSRF token", async () => {
    const { validateCsrf } = await import("@/features/auth/server/admission");
    const validHeaders = new Headers({
      origin: "https://auth.example.com",
      "sec-fetch-site": "same-origin",
    });

    expect(
      validateCsrf({
        headers: validHeaders,
        expectedOrigin: "https://auth.example.com",
        sessionToken: "csrf-session-token",
        submittedToken: "csrf-session-token",
      })
    ).toEqual({ ok: true });

    const failures = [
      validateCsrf({
        headers: new Headers({ "sec-fetch-site": "same-origin" }),
        expectedOrigin: "https://auth.example.com",
        sessionToken: "csrf-session-token",
        submittedToken: "csrf-session-token",
      }),
      validateCsrf({
        headers: new Headers({ origin: "https://auth.example.com", "sec-fetch-site": "cross-site" }),
        expectedOrigin: "https://auth.example.com",
        sessionToken: "csrf-session-token",
        submittedToken: "csrf-session-token",
      }),
      validateCsrf({
        headers: validHeaders,
        expectedOrigin: "https://auth.example.com",
        sessionToken: "csrf-session-token",
        submittedToken: "different-token",
      }),
      validateCsrf({
        headers: validHeaders,
        expectedOrigin: "https://auth.example.com",
        sessionToken: "csrf-session-token",
        submittedToken: null,
      }),
    ];

    const normalized = failures.map((failure) => {
      if (failure.ok) throw new Error("expected CSRF failure");
      return {
        ok: failure.ok,
        status: failure.status,
        message: failure.body.message,
      };
    });

    expect(normalized).toEqual([
      normalized[0],
      normalized[0],
      normalized[0],
      normalized[0],
    ]);
    for (const failure of failures) {
      expect(failure.ok).toBe(false);
      if (failure.ok) throw new Error("expected CSRF failure");
      expect(failure.body.supportId).toMatch(/^admission_/);
      expect(JSON.stringify(failure)).not.toContain("csrf-session-token");
    }
  });
});

describe("OTP resend admission wiring", () => {
  beforeEach(() => {
    vi.resetModules();
    resetEnv();
    process.env.SKIP_ENV_VALIDATION = "true";
    process.env.DATABASE_URL = "postgresql://user:password@localhost:5432/app?schema=public";
    process.env.NEXTAUTH_SECRET = "test-nextauth-secret-at-least-32";
  });

  it("applies independent OTP admission limits before resending", async () => {
    const buildAdmissionRateLimitChecks = vi.fn(() => [
      { scope: "ip", key: "otp:ip-key", policy: "otp-verify-ip" },
      { scope: "account", key: "otp:account-key", policy: "otp-verify-account" },
    ]);
    const rateLimit = vi.fn(async () => ({
      success: true,
      limit: 3,
      remaining: 2,
      reset: Date.now(),
    }));
    const resendVerificationToken = vi.fn(async () => ({ ok: true }));

    vi.doMock("@/lib/rateLimit", () => ({
      buildAdmissionRateLimitChecks,
      buildRateLimitKey: vi.fn(),
      getClientIp: vi.fn(() => "203.0.113.10"),
      rateLimit,
    }));
    vi.doMock("@/features/auth/server/verify/resend", () => ({
      resendVerificationToken,
    }));

    const { POST } = await import("@/app/api/auth/verify/resend/route");
    const response = await POST(
      new Request("https://auth.example.com/api/auth/verify/resend", {
        method: "POST",
        body: JSON.stringify({ email: "User@Example.com" }),
      })
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true });
    expect(buildAdmissionRateLimitChecks).toHaveBeenCalledWith({
      surface: "otp-verify",
      ip: "203.0.113.10",
      accountIdentifier: "User@Example.com",
    });
    expect(rateLimit).toHaveBeenCalledWith("otp:ip-key", "otp-verify-ip");
    expect(rateLimit).toHaveBeenCalledWith("otp:account-key", "otp-verify-account");
    expect(resendVerificationToken).toHaveBeenCalledWith("User@Example.com");
  });

  it("returns the generic admission envelope when any OTP resend dimension is limited", async () => {
    vi.doMock("@/lib/rateLimit", () => ({
      buildAdmissionRateLimitChecks: vi.fn(() => [
        { scope: "ip", key: "otp:ip-key", policy: "otp-verify-ip" },
        { scope: "account", key: "otp:account-key", policy: "otp-verify-account" },
      ]),
      buildRateLimitKey: vi.fn(),
      getClientIp: vi.fn(() => "203.0.113.10"),
      rateLimit: vi
        .fn()
        .mockResolvedValueOnce({ success: true, limit: 3, remaining: 2, reset: Date.now() })
        .mockResolvedValueOnce({ success: false, limit: 3, remaining: 0, reset: Date.now() }),
    }));
    const resendVerificationToken = vi.fn(async () => ({ ok: true }));
    vi.doMock("@/features/auth/server/verify/resend", () => ({
      resendVerificationToken,
    }));

    const { POST } = await import("@/app/api/auth/verify/resend/route");
    const response = await POST(
      new Request("https://auth.example.com/api/auth/verify/resend", {
        method: "POST",
        body: JSON.stringify({ email: "User@Example.com" }),
      })
    );
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toMatchObject({
      ok: false,
      message: "Unable to complete this request.",
    });
    expect(body.supportId).toMatch(/^admission_/);
    expect(body.reason).toBeUndefined();
    expect(resendVerificationToken).not.toHaveBeenCalled();
  });
});

describe("Password reset admission wiring", () => {
  beforeEach(() => {
    vi.resetModules();
    resetEnv();
    process.env.SKIP_ENV_VALIDATION = "true";
    process.env.DATABASE_URL = "postgresql://user:password@localhost:5432/app?schema=public";
    process.env.NEXTAUTH_SECRET = "test-nextauth-secret-at-least-32";
  });

  it("applies independent password-reset admission limits before account lookup", async () => {
    const buildAdmissionRateLimitChecks = vi.fn(() => [
      { scope: "ip", key: "reset:ip-key", policy: "password-reset-ip" },
      { scope: "account", key: "reset:account-key", policy: "password-reset-account" },
    ]);
    const rateLimit = vi.fn(async () => ({
      success: true,
      limit: 3,
      remaining: 2,
      reset: Date.now(),
    }));
    const findUnique = vi.fn(async () => null);

    vi.doMock("@/lib/rateLimit", () => ({
      buildAdmissionRateLimitChecks,
      buildRateLimitKey: vi.fn(),
      getClientIp: vi.fn(() => "203.0.113.10"),
      rateLimit,
    }));
    vi.doMock("@/lib/prisma", () => ({
      prisma: {
        user: { findUnique },
      },
    }));
    vi.doMock("next/headers", () => ({
      headers: vi.fn(async () => new Headers()),
    }));

    const { requestPasswordReset } = await import("@/features/auth/server/actions/requestPasswordReset");
    const formData = new FormData();
    formData.set("email", "User@Example.com");

    await expect(requestPasswordReset(formData)).resolves.toEqual({ ok: true });
    expect(buildAdmissionRateLimitChecks).toHaveBeenCalledWith({
      surface: "password-reset",
      ip: "203.0.113.10",
      accountIdentifier: "user@example.com",
    });
    expect(rateLimit).toHaveBeenCalledWith("reset:ip-key", "password-reset-ip");
    expect(rateLimit).toHaveBeenCalledWith("reset:account-key", "password-reset-account");
    expect(findUnique).toHaveBeenCalledWith({
      where: { email: "user@example.com" },
      select: { name: true, password: true },
    });
  });

  it("returns a generic form error before account lookup when password-reset admission is limited", async () => {
    const findUnique = vi.fn(async () => null);

    vi.doMock("@/lib/rateLimit", () => ({
      buildAdmissionRateLimitChecks: vi.fn(() => [
        { scope: "ip", key: "reset:ip-key", policy: "password-reset-ip" },
        { scope: "account", key: "reset:account-key", policy: "password-reset-account" },
      ]),
      buildRateLimitKey: vi.fn(),
      getClientIp: vi.fn(() => "203.0.113.10"),
      rateLimit: vi
        .fn()
        .mockResolvedValueOnce({ success: true, limit: 3, remaining: 2, reset: Date.now() })
        .mockResolvedValueOnce({ success: false, limit: 3, remaining: 0, reset: Date.now() }),
    }));
    vi.doMock("@/lib/prisma", () => ({
      prisma: {
        user: { findUnique },
      },
    }));
    vi.doMock("next/headers", () => ({
      headers: vi.fn(async () => new Headers()),
    }));

    const { requestPasswordReset } = await import("@/features/auth/server/actions/requestPasswordReset");
    const formData = new FormData();
    formData.set("email", "User@Example.com");

    await expect(requestPasswordReset(formData)).resolves.toEqual({
      ok: false,
      errors: { formErrors: ["Unable to complete this request."] },
    });
    expect(findUnique).not.toHaveBeenCalled();
  });
});
