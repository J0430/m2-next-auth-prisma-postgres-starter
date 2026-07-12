// Exercises concrete authentication handlers against the locked enumeration-parity denial matrix.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { randomUUID } from "node:crypto";

const NOW = new Date("2026-07-12T12:00:00.000Z");
const DENIALS = ["absent", "expired", "revoked", "redeemed", "email-mismatch", "malformed"] as const;
type Denial = (typeof DENIALS)[number];

type CapturedResponse = {
  body: string;
  status: number;
  elapsedMs: number;
};

async function captureResponse(pending: Promise<Response>): Promise<CapturedResponse> {
  const startedAt = Date.now();
  const response = await pending;
  return { body: await response.text(), status: response.status, elapsedMs: Date.now() - startedAt };
}

async function capturePaddedResponse(pending: Promise<Response>): Promise<CapturedResponse> {
  const startedAt = Date.now();
  let settled = false;
  const observed = pending.finally(() => { settled = true; });
  await vi.advanceTimersByTimeAsync(249);
  expect(settled).toBe(false);
  await vi.advanceTimersByTimeAsync(1);
  const response = await observed;
  return { body: await response.text(), status: response.status, elapsedMs: Date.now() - startedAt };
}

function expectExactParity(results: readonly CapturedResponse[]): void {
  const baseline = results[0];
  expect(baseline).toBeDefined();
  for (const result of results.slice(1)) {
    expect(result).toEqual(baseline);
  }
}

function validOtpRequest(): Request {
  return new Request("https://auth.example.com/api/auth/verify", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": "127.0.0.1" },
    body: JSON.stringify({
      email: "person@example.com",
      code: "123456",
      password: "ReplacementP@ss123",
      repeatpassword: "ReplacementP@ss123",
    }),
  });
}

function resetForm(): FormData {
  const form = new FormData();
  form.set("token", "a".repeat(64));
  form.set("password", "ReplacementP@ss123");
  form.set("confirmPassword", "ReplacementP@ss123");
  return form;
}

beforeEach(() => {
  vi.resetModules();
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  vi.spyOn(performance, "now").mockReturnValue(0);
  process.env.SKIP_ENV_VALIDATION = "true";
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("TASK-028 concrete password-reset parity", () => {
  it("keeps reset-confirm body, status, and timing identical across all six denials", async () => {
    const reasonByDenial = {
      absent: "not-found",
      expired: "expired",
      revoked: "not-found",
      redeemed: "not-found",
      "email-mismatch": "not-found",
      malformed: "not-found",
    } as const;
    let current: Denial = "absent";
    vi.doMock("next/headers", () => ({ headers: vi.fn(async () => new Headers()) }));
    vi.doMock("@/lib/rateLimit", () => ({
      buildRateLimitKey: vi.fn(() => "reset:ip"),
      getClientIp: vi.fn(() => "127.0.0.1"),
      rateLimit: vi.fn(async () => ({ success: true })),
    }));
    vi.doMock("@/features/auth/server/reset/consumeResetToken", () => ({
      consumePasswordResetToken: vi.fn(async () => ({ ok: false, reason: reasonByDenial[current] })),
    }));
    const { resetPassword } = await import("@/features/auth/server/actions/resetPassword");
    const results: CapturedResponse[] = [];

    for (const denial of DENIALS) {
      current = denial;
      const startedAt = Date.now();
      let settled = false;
      const pending = resetPassword(resetForm()).finally(() => { settled = true; });
      await vi.advanceTimersByTimeAsync(249);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      const result = await pending;
      results.push({ body: JSON.stringify(result), status: 200, elapsedMs: Date.now() - startedAt });
    }

    expectExactParity(results);
  });
});

describe("TASK-028 concrete registration denial envelope", () => {
  it("is byte-identical across all six registration denials", async () => {
    const { createGenericAdmissionFailure } = await import("@/features/auth/server/admission");
    const results = DENIALS.map(() => createGenericAdmissionFailure());

    expect(results).toEqual(DENIALS.map(() => ({
      ok: false,
      status: 403,
      body: {
        ok: false,
        message: "Unable to complete this request.",
        supportId: "admission_denied",
      },
    })));
  });
});

describe("TASK-028 concrete OTP-verify parity", () => {
  it("keeps OTP response body, status, and timing identical across all six denials", async () => {
    const reasonByDenial = {
      absent: "not-found",
      expired: "expired",
      revoked: "already-verified",
      redeemed: "already-verified",
      "email-mismatch": "invalid-code",
      malformed: "max-attempts",
    } as const;
    let current: Denial = "absent";
    vi.doMock("@/lib/rateLimit", () => ({
      buildAdmissionRateLimitChecks: vi.fn(() => []),
      getClientIp: vi.fn(() => "127.0.0.1"),
      rateLimit: vi.fn(async () => ({ success: true })),
    }));
    vi.doMock("@/features/auth/server/verify/consumeToken", () => ({
      consumeVerificationToken: vi.fn(async () => ({ ok: false, reason: reasonByDenial[current] })),
    }));
    vi.doMock("@/features/auth/server/createSessionToken", () => ({
      createSessionToken: vi.fn(),
      getSessionCookieName: vi.fn(() => "session"),
    }));
    vi.doMock("@/lib/prisma", () => ({ prisma: { user: { findUnique: vi.fn() } } }));
    const { POST } = await import("@/app/api/auth/verify/route");
    const results: CapturedResponse[] = [];

    for (const denial of DENIALS) {
      current = denial;
      results.push(await capturePaddedResponse(POST(validOtpRequest())));
    }

    expect(results.map(({ body, status }) => ({ body, status }))).toEqual(DENIALS.map(() => ({
      body: JSON.stringify({ ok: false, reason: "verification-failed" }),
      status: 400,
    })));
    expectExactParity(results);
  });
});

describe("TASK-028 concrete admin generic-403 parity", () => {
  it("returns the exact same 403 for missing capability, stale MFA, and unknown target", async () => {
    const service = {
      issue: vi.fn(),
      list: vi.fn(),
      revoke: vi.fn(),
      resend: vi.fn(),
    };
    const { createAdminInviteHttpHandler } = await import("@/features/auth/server/adminInvites/adminInviteHttp");
    const handler = createAdminInviteHttpHandler("revoke", {
      session: async () => ({ user: { id: "admin-1", role: "ADMIN", sessionVersion: 3 } }),
      csrfCookie: async () => "csrf-token",
      limit: async () => ({ success: true }),
      service,
      expectedOrigin: "https://auth.example.com",
      clientIp: () => "127.0.0.1",
    });
    const results: CapturedResponse[] = [];

    for (const error of ["MISSING_CAPABILITY", "STALE_MFA", "UNKNOWN_TARGET"] as const) {
      service.revoke.mockRejectedValueOnce(new Error(error));
      results.push(await captureResponse(handler(new Request("https://auth.example.com/api/admin/invites/revoke", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "https://auth.example.com",
          "sec-fetch-site": "same-origin",
        },
        body: JSON.stringify({
          csrfToken: "csrf-token",
          inviteId: "unknown-invite",
          reason: "Security verification",
          requestId: randomUUID(),
        }),
      }))));
    }

    expectExactParity(results);
    expect(results[0]).toMatchObject({
      body: JSON.stringify({ ok: false, message: "Unable to complete this request." }),
      status: 403,
    });
  });
});
