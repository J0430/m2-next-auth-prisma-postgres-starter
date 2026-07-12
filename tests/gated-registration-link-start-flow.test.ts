// Verifies provider preflight and atomic cleanup around link-start orchestration.
import { beforeEach, describe, expect, it, vi } from "vitest";

const createIntent = vi.fn();
const assertConfigured = vi.fn();
const buildAuthorizationUrl = vi.fn();
const cleanupUpdate = vi.fn(async () => ({ count: 1 }));
const cleanupAudit = vi.fn(async () => undefined);
const denialAudit = vi.fn(async () => undefined);
const tx = {
  accountLinkIntent: { updateMany: cleanupUpdate },
  auditEvent: { create: cleanupAudit },
};
const transaction = vi.fn(async (callback: (value: typeof tx) => Promise<void>) => callback(tx));

vi.mock("@/features/auth/server/linking/createLinkIntent", () => ({ createAccountLinkIntent: createIntent }));
vi.mock("@/features/auth/server/linking/providerOAuth", () => ({
  assertLinkProviderConfigured: assertConfigured,
  buildAuthorizationUrl,
}));
vi.mock("@/lib/prisma", () => ({ prisma: { $transaction: transaction } }));
vi.mock("@/features/auth/server/linking/audit", () => ({ recordLinkDenied: denialAudit }));
vi.mock("@/features/auth/server/linking/pkce", () => ({
  createS256Challenge: vi.fn(() => "challenge"),
  deriveLinkVerifier: vi.fn(() => "verifier"),
}));

const input = {
  userId: "user-1", provider: "github" as const, currentPassword: "password",
  lastAuthAtMs: Date.now(), currentAuthProvider: "credentials", sessionVersion: 4,
};

describe("account-link start orchestration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    assertConfigured.mockReturnValue(undefined);
    createIntent.mockResolvedValue({ ok: true, rawState: "opaque-state-that-is-long-enough-123", expiresAt: new Date() });
    buildAuthorizationUrl.mockReturnValue("https://github.example/authorize");
  });

  it("audits disabled or misconfigured providers before creating an intent", async () => {
    assertConfigured.mockImplementation(() => { throw new Error("disabled"); });
    const { startAccountLinkFlow } = await import("@/features/auth/server/linking/startLinkFlow");
    await expect(startAccountLinkFlow(input)).resolves.toEqual({ ok: false, reason: "provider_unavailable" });
    expect(createIntent).not.toHaveBeenCalled();
    expect(transaction).not.toHaveBeenCalled();
    expect(cleanupUpdate).not.toHaveBeenCalled();
    expect(denialAudit).toHaveBeenCalledTimes(1);
    expect(denialAudit).toHaveBeenCalledWith("github", "provider_unavailable", "user-1");
  });

  it("atomically consumes the just-created intent and appends one redacted denial when URL construction throws", async () => {
    buildAuthorizationUrl.mockImplementation(() => { throw new Error("url failed with secret"); });
    const { startAccountLinkFlow } = await import("@/features/auth/server/linking/startLinkFlow");
    await expect(startAccountLinkFlow(input)).resolves.toEqual({ ok: false, reason: "authorization_url_failed" });
    expect(cleanupUpdate).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ userId: "user-1", provider: "github", consumedAt: null }),
    }));
    expect(cleanupAudit).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(cleanupAudit.mock.calls)).not.toMatch(/opaque-state|secret/u);
  });

  it("audits an unexpected intent-creation failure exactly once", async () => {
    createIntent.mockRejectedValueOnce(new Error("database unavailable"));
    const { startAccountLinkFlow } = await import("@/features/auth/server/linking/startLinkFlow");
    await expect(startAccountLinkFlow(input)).resolves.toEqual({ ok: false, reason: "intent_persistence_failed" });
    expect(denialAudit).toHaveBeenCalledTimes(1);
    expect(denialAudit).toHaveBeenCalledWith("github", "intent_persistence_failed", "user-1");
  });
});
