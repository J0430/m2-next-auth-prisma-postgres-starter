// Adversarial completion tests for session binding, replay, collision, and redaction.
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = "opaque-state-that-is-long-enough-for-security";
interface IntentFixture {
  id: string; userId: string; provider: string; sessionVersion: number;
  nonceHash: Buffer; expiresAt: Date; consumedAt: Date | null;
  user: { id: string; status: string; sessionVersion: number };
}

const intent: IntentFixture = {
  id: "intent-1", userId: "user-1", provider: "github", sessionVersion: 4,
  nonceHash: Buffer.from("placeholder"), expiresAt: new Date(Date.now() + 60_000), consumedAt: null,
  user: { id: "user-1", status: "ACTIVE", sessionVersion: 4 },
};

async function scenario(overrides: Partial<typeof intent> = {}, collision: string | null = null) {
  vi.resetModules();
  const { hashLinkNonce } = await import("@/features/auth/server/linking/nonce");
  const record = { ...intent, ...overrides, nonceHash: hashLinkNonce(state) };
  const denialAudit = vi.fn(async () => undefined);
  const accountCreate = vi.fn(async () => ({ id: "account-1" }));
  const userUpdate = vi.fn(async () => ({ count: 1 }));
  const successAudit = vi.fn(async () => ({ id: "audit-1" }));
  const claimIntent = vi.fn(async () => ({ count: 1 }));
  const tx = { account: { create: accountCreate }, user: { updateMany: userUpdate }, auditEvent: { create: successAudit } };
  vi.doMock("@/features/auth/server/linking/audit", () => ({ recordLinkDenied: denialAudit }));
  vi.doMock("@/features/auth/server/linking/providerOAuth", () => ({ fetchProviderSubject: vi.fn(async () => "subject-1") }));
  vi.doMock("@/features/auth/server/linking/pkce", () => ({ deriveLinkVerifier: vi.fn(() => "verifier") }));
  vi.doMock("@/lib/prisma", () => ({ prisma: {
    accountLinkIntent: { findUnique: vi.fn(async () => record), updateMany: claimIntent },
    account: { findUnique: vi.fn(async () => collision ? { userId: collision } : null) },
    $transaction: vi.fn(async (callback: (value: typeof tx) => Promise<void>) => callback(tx)),
  } }));
  const { completeAccountLink } = await import("@/features/auth/server/linking/completeLink");
  return { accountCreate, claimIntent, completeAccountLink, denialAudit, successAudit, userUpdate };
}

describe("dedicated link completion", () => {
  beforeEach(() => vi.clearAllMocks());

  it("requires the same current user and session generation before exchange", async () => {
    const flow = await scenario();
    await expect(flow.completeAccountLink({ provider: "github", state, code: "code", providerError: false,
      session: { userId: "other-user", sessionVersion: 4 } })).resolves.toEqual({ ok: false, reason: "session_mismatch" });
    expect(flow.accountCreate).not.toHaveBeenCalled();
  });

  it.each([
    [{ consumedAt: new Date() }, "replayed_intent"],
    [{ expiresAt: new Date(0) }, "expired_intent"],
    [{ sessionVersion: 3 }, "session_mismatch"],
  ] as const)("rejects stale intent context", async (override, reason) => {
    const flow = await scenario(override);
    await expect(flow.completeAccountLink({ provider: "github", state, code: "code", providerError: false,
      session: { userId: "user-1", sessionVersion: 4 } })).resolves.toEqual({ ok: false, reason });
  });

  it("rejects a provider subject linked to any existing user", async () => {
    const flow = await scenario({}, "other-user");
    await expect(flow.completeAccountLink({ provider: "github", state, code: "code", providerError: false,
      session: { userId: "user-1", sessionVersion: 4 } })).resolves.toEqual({ ok: false, reason: "provider_already_linked" });
    expect(flow.accountCreate).not.toHaveBeenCalled();
  });

  it("allows exactly one concurrent completion to claim the intent", async () => {
    const flow = await scenario();
    flow.claimIntent.mockResolvedValueOnce({ count: 1 }).mockResolvedValueOnce({ count: 0 });
    const input = { provider: "github" as const, state, code: "code", providerError: false,
      session: { userId: "user-1", sessionVersion: 4 } };
    const outcomes = await Promise.all([flow.completeAccountLink(input), flow.completeAccountLink(input)]);
    expect(outcomes).toContainEqual({ ok: true });
    expect(outcomes).toContainEqual({ ok: false, reason: "replayed_intent" });
    expect(flow.accountCreate).toHaveBeenCalledTimes(1);
  });

  it("keeps the denial audit durable when the transactional success audit rolls back", async () => {
    const flow = await scenario();
    flow.successAudit.mockRejectedValueOnce(new Error("audit unavailable"));
    await expect(flow.completeAccountLink({ provider: "github", state, code: "code", providerError: false,
      session: { userId: "user-1", sessionVersion: 4 } })).resolves.toEqual({ ok: false, reason: "link_transaction_failed" });
    expect(flow.successAudit).toHaveBeenCalledTimes(1);
    expect(flow.denialAudit).toHaveBeenCalledWith("github", "link_transaction_failed", "user-1");
  });

  it("links without tokens/email, bumps the exact version, and redacts success audit", async () => {
    const flow = await scenario();
    await expect(flow.completeAccountLink({ provider: "github", state, code: "secret-code", providerError: false,
      session: { userId: "user-1", sessionVersion: 4 } })).resolves.toEqual({ ok: true });
    expect(flow.accountCreate).toHaveBeenCalledWith({ data: {
      userId: "user-1", type: "oauth", provider: "github", providerAccountId: "subject-1",
    } });
    expect(flow.userUpdate).toHaveBeenCalledWith(expect.objectContaining({ where: expect.objectContaining({ sessionVersion: 4 }) }));
    const audit = JSON.stringify(flow.successAudit.mock.calls);
    expect(audit).not.toContain(state);
    expect(audit).not.toContain("secret-code");
    expect(audit).not.toContain("subject-1");
  });
});
