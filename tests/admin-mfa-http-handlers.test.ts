// Exercises admin MFA POST admission, rate-limit, audit, and response parity contracts.
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  session: vi.fn(), cookieGet: vi.fn(), validateCsrf: vi.fn(), pad: vi.fn(),
  rateLimit: vi.fn(), getClientIp: vi.fn(), compare: vi.fn(), userFind: vi.fn(),
  factorFind: vi.fn(), transaction: vi.fn(), auditCreate: vi.fn(), enroll: vi.fn(),
  verify: vi.fn(), authorizeElevation: vi.fn(),
}));

vi.mock("next-auth", () => ({ getServerSession: mocks.session }));
vi.mock("next/headers", () => ({ cookies: vi.fn(async () => ({ get: mocks.cookieGet })) }));
vi.mock("bcryptjs", () => ({ compare: mocks.compare }));
vi.mock("@/features/auth/server/options", () => ({ authOptions: {} }));
vi.mock("@/features/auth/server/admission", () => ({
  validateCsrf: mocks.validateCsrf,
  padAdmissionTiming: mocks.pad,
  createGenericAdmissionFailure: vi.fn((status: number) => ({ status, body: { error: "Forbidden" } })),
}));
vi.mock("@/lib/rateLimit", () => ({
  buildAdmissionRateLimitChecks: vi.fn(() => [
    { key: "admin:actor", policy: "actor" },
    { key: "admin:ip", policy: "ip" },
  ]),
  getClientIp: mocks.getClientIp,
  rateLimit: mocks.rateLimit,
}));
vi.mock("@/lib/env", () => ({
  env: { AUTH_URL: "https://auth.example.test", NEXTAUTH_URL: "https://auth.example.test", MFA_ISSUER: "Example" },
}));
vi.mock("@/lib/prisma", () => ({
  prisma: {
    user: { findUnique: mocks.userFind },
    adminMfaFactor: { findFirst: mocks.factorFind },
    $transaction: mocks.transaction,
  },
}));
vi.mock("@/features/auth/server/adminMfa/adminMfaService", () => ({
  enrollAdminMfaFactor: mocks.enroll,
  verifyAdminMfaFactor: mocks.verify,
}));
vi.mock("@/features/auth/server/adminElevation/requireAdminElevation", () => ({
  authorizeAdminElevationForDomainMutation: mocks.authorizeElevation,
}));

import {
  handleAdminElevationRefresh,
  handleAdminMfaEnroll,
  handleAdminMfaVerify,
} from "@/features/auth/server/adminMfa/adminMfaHttp";

const tx = {
  user: { findUnique: mocks.userFind },
  adminMfaFactor: { findFirst: mocks.factorFind },
  auditEvent: { create: mocks.auditCreate },
};

function request(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("https://auth.example.test/api/admin/mfa", {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://auth.example.test", "sec-fetch-site": "same-origin", ...headers },
    body: JSON.stringify(body),
  });
}

async function expectGeneric(result: Response): Promise<void> {
  expect(result.status).toBe(403);
  expect(await result.json()).toEqual({ error: "Forbidden" });
}

describe("admin MFA POST handlers", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.session.mockResolvedValue({ user: { id: "admin-1", role: "ADMIN", sessionVersion: 4 } });
    mocks.cookieGet.mockReturnValue({ value: "csrf" });
    mocks.validateCsrf.mockReturnValue({ ok: true });
    mocks.rateLimit.mockResolvedValue({ success: true });
    mocks.getClientIp.mockReturnValue("203.0.113.8");
    mocks.userFind.mockResolvedValue({ role: "ADMIN", status: "ACTIVE", sessionVersion: 4, email: "admin@example.test", hasPasswordCredential: true, passwordHash: "hash" });
    mocks.factorFind.mockResolvedValue(null);
    mocks.compare.mockResolvedValue(true);
    mocks.enroll.mockResolvedValue({ factorId: "factor-1", provisioningUri: "otpauth://totp/example" });
    mocks.transaction.mockImplementation(async (run: (client: typeof tx) => Promise<unknown>) => run(tx));
  });

  it.each([
    ["unauthenticated", null, { ok: true }],
    ["non-admin", { user: { id: "user-1", role: "USER", sessionVersion: 4 } }, { ok: true }],
    ["missing CSRF", { user: { id: "admin-1", role: "ADMIN", sessionVersion: 4 } }, { ok: false }],
    ["mismatched CSRF", { user: { id: "admin-1", role: "ADMIN", sessionVersion: 4 } }, { ok: false }],
    ["cross-site", { user: { id: "admin-1", role: "ADMIN", sessionVersion: 4 } }, { ok: false }],
  ])("returns the same generic body for %s", async (_case, session, csrf) => {
    mocks.session.mockResolvedValue(session);
    mocks.validateCsrf.mockReturnValue(csrf);
    if (_case === "non-admin") mocks.userFind.mockResolvedValue({ role: "USER", status: "ACTIVE", sessionVersion: 4 });
    await expectGeneric(await handleAdminMfaVerify(request({ csrfToken: "csrf", factorId: "factor-1", code: "123456" })));
    expect(mocks.pad).toHaveBeenCalledOnce();
  });

  it.each([0, 1])("denies when limiter bucket %i is exhausted and uses trusted IP", async (bucket) => {
    mocks.rateLimit.mockResolvedValueOnce(bucket === 0 ? { success: false } : { success: true });
    if (bucket === 1) mocks.rateLimit.mockResolvedValueOnce({ success: false });
    await expectGeneric(await handleAdminMfaVerify(request({ csrfToken: "csrf", factorId: "factor-1", code: "123456" }, { "x-forwarded-for": "attacker" })));
    expect(mocks.getClientIp).toHaveBeenCalled();
    expect(mocks.verify).not.toHaveBeenCalled();
  });

  it.each([
    ["enroll", handleAdminMfaEnroll, { csrfToken: "csrf", currentPassword: "correct" }],
    ["verify", handleAdminMfaVerify, { csrfToken: "csrf", factorId: "factor-1", code: "123456" }],
    ["refresh", handleAdminElevationRefresh, { csrfToken: "csrf", factorId: "factor-1", code: "123456" }],
  ])("enforces both actor and IP limiter buckets for %s", async (_surface, handler, body) => {
    for (const bucket of [0, 1]) {
      mocks.rateLimit.mockReset();
      mocks.rateLimit.mockResolvedValueOnce(bucket === 0 ? { success: false } : { success: true });
      if (bucket === 1) mocks.rateLimit.mockResolvedValueOnce({ success: false });
      await expectGeneric(await handler(request(body, { "x-forwarded-for": "198.51.100.99" })));
    }
    expect(mocks.getClientIp).toHaveBeenCalled();
  });

  it("allows only the owned pending replacement on a session one version behind", async () => {
    mocks.userFind.mockResolvedValue({ role: "ADMIN", status: "ACTIVE", sessionVersion: 5 });
    mocks.factorFind.mockResolvedValueOnce({ id: "owned-pending" });
    expect((await handleAdminMfaVerify(request({ csrfToken: "csrf", factorId: "owned-pending", code: "123456" }))).status).toBe(200);

    mocks.factorFind.mockResolvedValueOnce(null);
    await expectGeneric(await handleAdminMfaVerify(request({ csrfToken: "csrf", factorId: "cross-admin", code: "123456" })));
  });

  it("rejects stale sessions beyond the replacement allowance before mutation", async () => {
    mocks.userFind.mockResolvedValue({ role: "ADMIN", status: "ACTIVE", sessionVersion: 6 });
    await expectGeneric(await handleAdminMfaVerify(request({ csrfToken: "csrf", factorId: "factor-1", code: "123456" })));
    expect(mocks.verify).not.toHaveBeenCalled();
  });

  it("supports first-factor password enrollment with exactly one domain success", async () => {
    const result = await handleAdminMfaEnroll(request({ csrfToken: "csrf", currentPassword: "correct" }));
    expect(result.status).toBe(201);
    expect(mocks.compare).toHaveBeenCalledWith("correct", "hash");
    expect(mocks.enroll).toHaveBeenCalledOnce();
    expect(mocks.authorizeElevation).not.toHaveBeenCalled();
  });

  it("denies passwordless first enrollment generically", async () => {
    mocks.userFind.mockResolvedValue({
      role: "ADMIN", status: "ACTIVE", sessionVersion: 4,
      email: "admin@example.test", hasPasswordCredential: false, passwordHash: null,
    });
    await expectGeneric(await handleAdminMfaEnroll(request({ csrfToken: "csrf", currentPassword: null })));
    expect(mocks.enroll).not.toHaveBeenCalled();
    expect(mocks.auditCreate).toHaveBeenCalledTimes(1);
  });

  it("uses elevation for subsequent enrollment without a route success audit", async () => {
    mocks.factorFind.mockResolvedValue({ id: "active-factor" });
    const result = await handleAdminMfaEnroll(request({ csrfToken: "csrf", currentPassword: null }));
    expect(result.status).toBe(201);
    expect(mocks.authorizeElevation).toHaveBeenCalledWith(
      expect.anything(), "admin:mfa:manage", "admin.mfa.enroll.denied",
    );
    expect(mocks.enroll).toHaveBeenCalledOnce();
    expect(mocks.auditCreate).not.toHaveBeenCalled();
  });

  it("aligns refresh success and denial on admin.elevation.refresh", async () => {
    expect((await handleAdminElevationRefresh(request({ csrfToken: "csrf", factorId: "factor-1", code: "123456" }))).status).toBe(200);
    expect(mocks.verify).toHaveBeenCalledWith(expect.objectContaining({ auditAction: "admin.elevation.refresh", actorId: "admin-1" }));

    mocks.verify.mockRejectedValueOnce(new Error("bad assertion"));
    await expectGeneric(await handleAdminElevationRefresh(request({ csrfToken: "csrf", factorId: "other-admin-factor", code: "123456" })));
    expect(mocks.auditCreate).toHaveBeenCalledTimes(1);
    expect(mocks.auditCreate).toHaveBeenCalledWith(expect.objectContaining({ data: expect.objectContaining({ action: "admin.elevation.refresh" }) }));
  });

  it.each([
    ["parse", request({ code: "secret-code" })],
    ["admission", request({ csrfToken: "wrong", factorId: "factor-1", code: "123456" })],
  ])("uses the redacted refresh action for %s failures before assertion", async (stage, input) => {
    if (stage === "admission") mocks.validateCsrf.mockReturnValue({ ok: false });
    await expectGeneric(await handleAdminElevationRefresh(input));
    expect(mocks.verify).not.toHaveBeenCalled();
    expect(mocks.auditCreate).toHaveBeenCalledTimes(1);
    const auditInput: unknown = mocks.auditCreate.mock.calls[0]?.[0];
    expect(auditInput).toEqual(expect.objectContaining({
      data: expect.objectContaining({ action: "admin.elevation.refresh", metadata: { outcome: "DENIAL" } }),
    }));
    expect(JSON.stringify(auditInput)).not.toMatch(/secret-code|123456|wrong/u);
  });

  it("never leaks denial-audit failure and still applies minimum timing", async () => {
    mocks.validateCsrf.mockReturnValue({ ok: false });
    mocks.transaction.mockRejectedValueOnce(new Error("audit unavailable"));
    await expectGeneric(await handleAdminMfaVerify(request({ csrfToken: "wrong", factorId: "factor-1", code: "123456" })));
    expect(mocks.pad).toHaveBeenCalledOnce();
  });
});
