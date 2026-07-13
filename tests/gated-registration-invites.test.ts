// gated-registration-invites.test.ts - Invite lifecycle service invariants.
import crypto from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_ENV = { ...process.env };
const NOW = new Date("2026-06-21T00:00:00.000Z");
const testMonotonicClock = (): number => Date.now();

vi.mock("@/lib/prisma", () => ({
  prisma: {
    invite: {
      create: vi.fn(),
      findUnique: vi.fn(),
      updateMany: vi.fn(),
    },
    auditEvent: { create: vi.fn() },
    $transaction: vi.fn(),
  },
}));

beforeEach(async () => {
  vi.resetModules();
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  process.env.SKIP_ENV_VALIDATION = "true";
  process.env.DATABASE_URL = "postgres://localhost/test";
  process.env.NEXTAUTH_SECRET = "x".repeat(32);
  const { prisma } = await import("@/lib/prisma");
  vi.mocked(prisma.$transaction).mockImplementation(async (callback) => callback({
    invite: { findUnique: prisma.invite.findUnique },
    auditEvent: { create: prisma.auditEvent.create },
  } as never));
});

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
  Object.keys(process.env).forEach((key) => {
    if (!(key in ORIGINAL_ENV)) delete process.env[key];
  });
  Object.assign(process.env, ORIGINAL_ENV);
});

describe("createInvite", () => {
  it("returns a 256-bit token once and persists only its SHA-256 hash", async () => {
    const { prisma } = await import("@/lib/prisma");
    const createInviteRecord = vi.mocked(prisma.invite.create);
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    createInviteRecord.mockResolvedValue({
      id: "invite-1",
      tokenHash: Buffer.alloc(32),
      normalizedEmail: "person@example.com",
      status: "ISSUED",
      expiresAt: new Date(NOW.getTime() + 7 * 24 * 60 * 60 * 1000),
      issuerUserId: "admin-1",
      redeemedByUserId: null,
      redeemedAt: null,
      revokedAt: null,
      createdAt: NOW,
      updatedAt: NOW,
    });

    const { createInvite } = await import("@/features/auth/server/invites");

    const result = await createInvite({
      issuerUserId: "admin-1",
      email: "  Person@Example.COM  ",
    });

    const rawToken = result.rawToken;
    const decoded = Buffer.from(rawToken, "base64url");
    const expectedHash = crypto.createHash("sha256").update(rawToken).digest();

    expect(decoded).toHaveLength(32);
    expect(result.inviteId).toBe("invite-1");
    expect(result.normalizedEmail).toBe("person@example.com");
    expect(result.expiresAt).toEqual(new Date(NOW.getTime() + 7 * 24 * 60 * 60 * 1000));
    expect(createInviteRecord).toHaveBeenCalledWith({
      data: {
        issuerUserId: "admin-1",
        normalizedEmail: "person@example.com",
        tokenHash: expectedHash,
        expiresAt: new Date(NOW.getTime() + 7 * 24 * 60 * 60 * 1000),
      },
      select: {
        id: true,
        normalizedEmail: true,
        expiresAt: true,
      },
    });
    expect(JSON.stringify(createInviteRecord.mock.calls)).not.toContain(rawToken);
    expect(JSON.stringify(logSpy.mock.calls)).not.toContain(rawToken);
    expect(JSON.stringify(errorSpy.mock.calls)).not.toContain(rawToken);
  });

  it("exposes transaction-aware issuance so invite and encrypted outbox can commit atomically", async () => {
    const create = vi.fn().mockResolvedValue({
      id: "invite-atomic",
      normalizedEmail: null,
      expiresAt: new Date(NOW.getTime() + 7 * 24 * 60 * 60 * 1000),
    });
    const createOutbox = vi.fn().mockResolvedValue({ id: "outbox-atomic" });
    const tx = { invite: { create }, outboxEmail: { create: createOutbox } };
    const { createInviteInTx } = await import("@/features/auth/server/invites");
    const { encryptInviteDeliveryToken } = await import("@/features/auth/server/outbox");

    const result = await createInviteInTx(tx, { issuerUserId: "admin-1", email: null });
    await tx.outboxEmail.create({
      data: {
        eventType: "INVITATION_DELIVERY",
        aggregateId: result.inviteId,
        dedupId: "invite-atomic-v1",
        inviteCiphertext: encryptInviteDeliveryToken(result.rawToken, "a".repeat(64)),
        keyVersion: 1,
      },
    });

    expect(result.normalizedEmail).toBeNull();
    expect(create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ normalizedEmail: null, tokenHash: expect.any(Buffer) }),
    }));
    expect(createOutbox).toHaveBeenCalledWith({
      data: expect.objectContaining({
        eventType: "INVITATION_DELIVERY",
        aggregateId: "invite-atomic",
        inviteCiphertext: expect.any(Uint8Array),
        keyVersion: 1,
      }),
    });
    expect(JSON.stringify(createOutbox.mock.calls)).not.toContain(result.rawToken);
  });
});

describe("lookupInviteByToken", () => {
  it.each([
    ["absent", null, "person@example.com"],
    ["expired", { status: "ISSUED", expiresAt: new Date(NOW.getTime() - 1) }, "person@example.com"],
    ["revoked", { status: "REVOKED", expiresAt: new Date(NOW.getTime() + 60_000) }, "person@example.com"],
    ["redeemed", { status: "REDEEMED", expiresAt: new Date(NOW.getTime() + 60_000) }, "person@example.com"],
    ["email mismatch", { status: "ISSUED", expiresAt: new Date(NOW.getTime() + 60_000) }, "other@example.com"],
    ["malformed", null, "person@example.com"],
  ])("returns the uniform public failure for %s", async (_outcome, state, expectedEmail) => {
    const { prisma } = await import("@/lib/prisma");
    const findInvite = vi.mocked(prisma.invite.findUnique);
    const token = _outcome === "malformed" ? "" : `${_outcome}-token`;
    const tokenHash = crypto.createHash("sha256").update(token).digest();
    findInvite.mockResolvedValue(state === null ? null : {
      id: "invite-1",
      tokenHash,
      normalizedEmail: "person@example.com",
      status: state.status === "ISSUED" ? "ISSUED" : state.status === "REVOKED" ? "REVOKED" : "REDEEMED",
      expiresAt: state.expiresAt,
      issuerUserId: "admin-1",
      redeemedByUserId: null,
      redeemedAt: null,
      revokedAt: null,
      createdAt: NOW,
      updatedAt: NOW,
    });

    const { lookupInviteByToken } = await import("@/features/auth/server/invites");
    const timingSpy = vi.spyOn(crypto, "timingSafeEqual");
    let settled = false;
    const pending = lookupInviteByToken(token, expectedEmail, testMonotonicClock).finally(() => { settled = true; });
    await vi.advanceTimersByTimeAsync(249);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);

    await expect(pending).resolves.toEqual({
      ok: false,
      status: 403,
      body: { ok: false, message: "Unable to complete this request." },
    });
    expect(timingSpy).toHaveBeenCalledOnce();
    expect(timingSpy.mock.calls[0]?.[0]).toHaveLength(32);
    expect(timingSpy.mock.calls[0]?.[1]).toHaveLength(32);
  });

  it("returns one generic failure shape and compares a miss in constant time", async () => {
    const { prisma } = await import("@/lib/prisma");
    const findInvite = vi.mocked(prisma.invite.findUnique);
    const timingSpy = vi.spyOn(crypto, "timingSafeEqual");

    findInvite.mockResolvedValue(null);

    const { lookupInviteByToken } = await import("@/features/auth/server/invites");

    const absentPending = lookupInviteByToken("absent-token", "person@example.com", testMonotonicClock);
    await vi.advanceTimersByTimeAsync(250);
    const absent = await absentPending;
    const malformedPending = lookupInviteByToken("", "person@example.com", testMonotonicClock);
    await vi.advanceTimersByTimeAsync(250);
    const malformed = await malformedPending;

    expect(absent).toEqual(malformed);
    expect(timingSpy).toHaveBeenCalledTimes(2);
    expect(timingSpy.mock.calls[0]?.[0]).toHaveLength(32);
    expect(timingSpy.mock.calls[0]?.[1]).toHaveLength(32);
    expect(findInvite).toHaveBeenCalledWith({
      where: {
        tokenHash: crypto.createHash("sha256").update("absent-token").digest(),
      },
      select: {
        id: true,
        tokenHash: true,
        normalizedEmail: true,
        status: true,
        expiresAt: true,
      },
    });
    expect(vi.mocked(prisma.invite.updateMany)).not.toHaveBeenCalled();
  });

  it("uses a 32-byte decoy when a stored digest has the wrong length", async () => {
    const { prisma } = await import("@/lib/prisma");
    vi.mocked(prisma.invite.findUnique).mockResolvedValue({
      id: "invite-corrupt",
      tokenHash: Buffer.alloc(31),
      normalizedEmail: null,
      status: "ISSUED",
      expiresAt: new Date(NOW.getTime() + 60_000),
      issuerUserId: "admin-1",
      redeemedByUserId: null,
      redeemedAt: null,
      revokedAt: null,
      createdAt: NOW,
      updatedAt: NOW,
    });
    const timingSpy = vi.spyOn(crypto, "timingSafeEqual");
    const { lookupInviteByToken } = await import("@/features/auth/server/invites");

    const pending = lookupInviteByToken("x".repeat(100_000), null, testMonotonicClock);
    await vi.advanceTimersByTimeAsync(250);

    await expect(pending).resolves.toMatchObject({ ok: false, status: 403 });
    expect(timingSpy).toHaveBeenCalledWith(expect.any(Buffer), expect.any(Buffer));
    expect(timingSpy.mock.calls[0]?.[0]).toHaveLength(32);
    expect(timingSpy.mock.calls[0]?.[1]).toHaveLength(32);
  });

  it("keeps successful lookup read-only and pads it to the same exact target", async () => {
    const { prisma } = await import("@/lib/prisma");
    const token = "valid-token";
    vi.mocked(prisma.invite.findUnique).mockResolvedValue({
      id: "invite-valid",
      tokenHash: crypto.createHash("sha256").update(token).digest(),
      normalizedEmail: null,
      status: "ISSUED",
      expiresAt: new Date(NOW.getTime() + 60_000),
      issuerUserId: "admin-1",
      redeemedByUserId: null,
      redeemedAt: null,
      revokedAt: null,
      createdAt: NOW,
      updatedAt: NOW,
    });
    const { lookupInviteByToken } = await import("@/features/auth/server/invites");
    let settled = false;

    const pending = lookupInviteByToken(token, null, testMonotonicClock).finally(() => { settled = true; });
    await vi.advanceTimersByTimeAsync(249);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);

    await expect(pending).resolves.toMatchObject({ ok: true });
    expect(vi.mocked(prisma.invite.updateMany)).not.toHaveBeenCalled();
  });

  it("maps a bounded lookup transaction timeout to the exact generic timing target", async () => {
    const { prisma } = await import("@/lib/prisma");
    vi.mocked(prisma.$transaction).mockImplementation(() => new Promise(() => undefined));
    const { lookupInviteByToken } = await import("@/features/auth/server/invites");
    const startedAtMs = Date.now();

    const pending = lookupInviteByToken("lookup-timeout", "person@example.com", testMonotonicClock);
    await vi.advanceTimersByTimeAsync(250);

    await expect(pending).resolves.toEqual({
      ok: false,
      status: 403,
      body: { ok: false, message: "Unable to complete this request." },
    });
    expect(Date.now() - startedAtMs).toBe(250);
    expect(prisma.$transaction).toHaveBeenCalledWith(expect.any(Function), {
      maxWait: 20,
      timeout: 50,
    });
    expect(vi.mocked(prisma.invite.updateMany)).not.toHaveBeenCalled();
  });
});

describe("redeemInviteInTx", () => {
  it("uses a server-resolved CAS and writes redeemedByUserId from the normalized email user", async () => {
    const tokenHash = crypto.createHash("sha256").update("server-resolved").digest();
    const updateMany = vi.fn().mockResolvedValue({ count: 1 });
    const findFirst = vi.fn().mockResolvedValue({
      id: "invite-1",
      tokenHash,
      normalizedEmail: "person@example.com",
      status: "REDEEMED",
      expiresAt: new Date(NOW.getTime() + 60_000),
      redeemedByUserId: "user-1",
      redeemedAt: NOW,
      revokedAt: null,
    });
    const createAuditEvent = vi.fn();

    const tx = {
      redeemerUserId: "user-1",
      invite: { updateMany, findFirst },
    };

    const { createInviteRedemptionContext, redeemInviteInTx } = await import("@/features/auth/server/invites");

    const result = await redeemInviteInTx(
      createInviteRedemptionContext(tx, vi.fn()),
      { tokenHash },
      " Person@Example.COM ",
    );

    expect(result.ok).toBe(true);
    expect(updateMany).toHaveBeenCalledWith({
      where: {
        tokenHash,
        status: "ISSUED",
        expiresAt: { gt: NOW },
        normalizedEmail: "person@example.com",
      },
      data: {
        status: "REDEEMED",
        redeemedAt: NOW,
        redeemedByUserId: "user-1",
      },
    });
    expect(createAuditEvent).not.toHaveBeenCalled();
  });

  it("keeps the canonical public failure shape on redeemed reuse", async () => {
    const tokenHash = crypto.createHash("sha256").update("server-resolved").digest();
    const updateMany = vi.fn().mockResolvedValue({ count: 0 });
    const findFirst = vi.fn().mockResolvedValue({
      id: "invite-1",
      tokenHash,
      normalizedEmail: "person@example.com",
      status: "REDEEMED",
      expiresAt: new Date(NOW.getTime() + 60_000),
      redeemedByUserId: "user-1",
      redeemedAt: NOW,
      revokedAt: null,
    });
    const createAuditEvent = vi.fn().mockResolvedValue({ id: "audit-1" });
    const alertReuse = vi.fn();

    const tx = {
      redeemerUserId: "user-1",
      invite: { updateMany, findFirst },
    };

    const { createInviteRedemptionContext, redeemInviteInTx } = await import("@/features/auth/server/invites");

    const signalReuse = vi.fn();
    const result = await redeemInviteInTx(
      createInviteRedemptionContext(tx, signalReuse),
      { tokenHash },
      "person@example.com",
    );

    expect(result).toEqual({ ok: false });
    expect(signalReuse).toHaveBeenCalledWith("invite-1");
    expect(createAuditEvent).not.toHaveBeenCalled();
    expect(alertReuse).not.toHaveBeenCalled();
  });

  it("commits redacted reuse audit before invoking the production alert sink", async () => {
    const { prisma } = await import("@/lib/prisma");
    const createAuditEvent = vi.mocked(prisma.auditEvent.create).mockResolvedValue({ id: "audit-1" } as never);
    const transaction = vi.mocked(prisma.$transaction).mockImplementation(async (callback) => callback({
      auditEvent: { create: createAuditEvent },
    } as never));
    const alertReuse = vi.fn();
    const { recordInviteReuseEvidence, setInviteReuseAlertHandler } = await import(
      "@/features/auth/server/invites"
    );
    const reset = setInviteReuseAlertHandler(alertReuse);

    await recordInviteReuseEvidence("invite-1");
    reset();

    expect(createAuditEvent).toHaveBeenCalledWith({
      data: {
        action: "invite.reuse_detected",
        targetType: "Invite",
        targetId: "invite-1",
        metadata: {
          inviteStatus: "REDEEMED",
        },
      },
    });
    expect(transaction).toHaveBeenCalledWith(expect.any(Function), { maxWait: 500, timeout: 750 });
    expect(alertReuse).toHaveBeenCalledWith({
      inviteId: "invite-1",
      status: "REDEEMED",
      auditPersisted: true,
    });
    expect(JSON.stringify(createAuditEvent.mock.calls)).not.toContain("server-resolved");
    expect(JSON.stringify(createAuditEvent.mock.calls)).not.toContain("person@example.com");
  });

  it("alerts with redacted auditPersisted false when durable audit storage fails", async () => {
    const { prisma } = await import("@/lib/prisma");
    vi.mocked(prisma.$transaction).mockRejectedValue(new Error("database unavailable"));
    const alertReuse = vi.fn();
    const { recordInviteReuseEvidence, setInviteReuseAlertHandler } = await import(
      "@/features/auth/server/invites"
    );
    const reset = setInviteReuseAlertHandler(alertReuse);

    await recordInviteReuseEvidence("invite-1");
    reset();

    expect(alertReuse).toHaveBeenCalledWith({
      inviteId: "invite-1",
      status: "REDEEMED",
      auditPersisted: false,
    });
  });

  it("CASes normalizedEmail null for an explicitly unbound invite", async () => {
    const updateMany = vi.fn().mockResolvedValue({ count: 0 });
    const tx = {
      redeemerUserId: "user-1",
      invite: { updateMany, findFirst: vi.fn().mockResolvedValue(null) },
    };
    const { createInviteRedemptionContext, redeemInviteInTx } = await import("@/features/auth/server/invites");

    await redeemInviteInTx(createInviteRedemptionContext(tx, vi.fn()), { inviteId: "invite-unbound" }, null);

    expect(updateMany.mock.calls[0]?.[0].where).toHaveProperty("normalizedEmail", null);
  });

  it("throws an invariant error when CAS succeeds but the redeemed row cannot be fetched", async () => {
    const tx = {
      redeemerUserId: "user-1",
      invite: {
        updateMany: vi.fn().mockResolvedValue({ count: 1 }),
        findFirst: vi.fn().mockResolvedValue(null),
      },
    };
    const { createInviteRedemptionContext, redeemInviteInTx } = await import("@/features/auth/server/invites");

    await expect(redeemInviteInTx(createInviteRedemptionContext(tx, vi.fn()), { inviteId: "invite-1" }, null))
      .rejects.toThrow("INVITE_REDEMPTION_INVARIANT");
  });

  it("preserves the one-winner CAS contract across concurrent calls", async () => {
    let remainingWinners = 1;
    const updateMany = vi.fn(async () => ({ count: remainingWinners-- > 0 ? 1 : 0 }));
    const redeemed = {
      id: "invite-1", tokenHash: Buffer.alloc(32), normalizedEmail: null,
      status: "REDEEMED" as const, expiresAt: new Date(NOW.getTime() + 60_000),
      redeemedByUserId: "user-1", redeemedAt: NOW, revokedAt: null,
    };
    const tx = {
      redeemerUserId: "user-1",
      invite: { updateMany, findFirst: vi.fn(async () => redeemed) },
    };
    const { createInviteRedemptionContext, redeemInviteInTx } = await import("@/features/auth/server/invites");
    const context = createInviteRedemptionContext(tx, vi.fn());

    const results = await Promise.all(Array.from({ length: 8 }, () =>
      redeemInviteInTx(context, { inviteId: "invite-1" }, null)));

    expect(results.filter(({ ok }) => ok)).toHaveLength(1);
    expect(results.filter(({ ok }) => !ok)).toHaveLength(7);
    expect(updateMany).toHaveBeenCalledTimes(8);
  });
});

describe("revokeInvite", () => {
  it("idempotently revokes only issued, unexpired invites", async () => {
    const { prisma } = await import("@/lib/prisma");
    const revokeInviteRecord = vi.mocked(prisma.invite.updateMany);
    revokeInviteRecord.mockResolvedValue({ count: 1 });

    const { revokeInvite } = await import("@/features/auth/server/invites");

    const result = await revokeInvite({ inviteId: "invite-1" });

    expect(result).toEqual({ ok: true });
    expect(revokeInviteRecord).toHaveBeenCalledWith({
      where: {
        id: "invite-1",
        status: "ISSUED",
        expiresAt: { gt: NOW },
      },
      data: {
        status: "REVOKED",
        revokedAt: NOW,
      },
    });
  });
});
