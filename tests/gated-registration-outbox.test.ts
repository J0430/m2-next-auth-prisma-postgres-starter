// gated-registration-outbox.test.ts - Packet 02 transactional email outbox worker invariants.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_ENV = { ...process.env };
const WORKER_SECRET = "worker-secret-for-tests-at-least-32";

function resetEnv(): void {
  Object.keys(process.env).forEach((key) => {
    if (!(key in ORIGINAL_ENV)) delete process.env[key];
  });
  Object.assign(process.env, ORIGINAL_ENV);
}

function setBaseEnv(): void {
  process.env.SKIP_ENV_VALIDATION = "true";
  process.env.DATABASE_URL = "postgresql://user:password@localhost:5432/app?schema=public";
  process.env.NEXTAUTH_SECRET = "test-nextauth-secret-at-least-32";
}

function buildWorkerRequest(headers?: Record<string, string>): Request {
  return new Request("https://auth.example.com/api/internal/outbox-email", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...headers,
    },
    body: JSON.stringify({
      id: "outbox_123",
    }),
  });
}

const CLAIMABLE_VERIFICATION_ROW = {
  id: "outbox_123",
  eventType: "EMAIL_VERIFICATION",
  aggregateId: "user_123",
  recipientUserId: "user_123",
  attempts: 0,
  inviteCiphertext: null,
  keyVersion: null,
};

const INVITE_KEY_HEX = "a".repeat(64);
const WRONG_INVITE_KEY_HEX = "b".repeat(64);

type InvitationEmailCall = {
  to: string;
  inviteUrl: string;
  name?: string;
};

describe("Packet 02 transactional email outbox worker", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
    vi.doUnmock("@/features/auth/server/outbox");
    vi.doUnmock("@/lib/rateLimit");
    resetEnv();
    setBaseEnv();
  });

  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
    vi.doUnmock("@/features/auth/server/outbox");
    vi.doUnmock("@/lib/rateLimit");
    resetEnv();
  });

  it("rejects absent or empty worker secrets fail-closed before processing", async () => {
    const processOutboxEmailMessage = vi.fn(async () => ({ ok: true }));
    vi.doMock("@/features/auth/server/outbox", async (importOriginal) => {
      const actual = await importOriginal<typeof import("@/features/auth/server/outbox")>();
      return {
        ...actual,
        processOutboxEmailMessage,
      };
    });

    const { POST } = await import("@/app/api/internal/outbox-email/route");

    await expect(POST(buildWorkerRequest())).resolves.toMatchObject({ status: 401 });

    process.env.INTERNAL_WORKER_AUTH_SECRET = "";
    await expect(
      POST(buildWorkerRequest({ authorization: `Bearer ${WORKER_SECRET}` }))
    ).resolves.toMatchObject({ status: 401 });

    expect(processOutboxEmailMessage).not.toHaveBeenCalled();
  });

  it("accepts a valid worker secret, rate-limits the worker, and delegates by opaque id", async () => {
    process.env.INTERNAL_WORKER_AUTH_SECRET = WORKER_SECRET;
    const processOutboxEmailMessage = vi.fn(async () => ({ ok: true }));
    const runRegistrationSessionCleanup = vi.fn(async () => 0);
    const buildAdmissionRateLimitChecks = vi.fn(() => [
      { scope: "admin", key: "outbox:admin-key", policy: "admin-operation-admin" },
      { scope: "ip", key: "outbox:ip-key", policy: "admin-operation-ip" },
    ]);
    const rateLimit = vi.fn(async () => ({
      success: true,
      limit: 30,
      remaining: 29,
      reset: Date.now(),
    }));

    vi.doMock("@/features/auth/server/outbox", async (importOriginal) => {
      const actual = await importOriginal<typeof import("@/features/auth/server/outbox")>();
      return {
        ...actual,
        processOutboxEmailMessage,
        runRegistrationSessionCleanup,
      };
    });
    vi.doMock("@/lib/rateLimit", () => ({
      buildAdmissionRateLimitChecks,
      buildRateLimitKey: vi.fn(),
      getClientIp: vi.fn(() => "203.0.113.10"),
      rateLimit,
    }));

    const { POST } = await import("@/app/api/internal/outbox-email/route");
    const response = await POST(buildWorkerRequest({ authorization: `Bearer ${WORKER_SECRET}` }));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true });
    expect(buildAdmissionRateLimitChecks).toHaveBeenCalledWith({
      surface: "admin-operation",
      ip: "203.0.113.10",
      adminActorId: "internal-outbox-email-worker",
    });
    expect(rateLimit).toHaveBeenCalledWith("outbox:admin-key", "admin-operation-admin");
    expect(rateLimit).toHaveBeenCalledWith("outbox:ip-key", "admin-operation-ip");
    expect(processOutboxEmailMessage).toHaveBeenCalledWith({
      id: "outbox_123",
    });
    expect(runRegistrationSessionCleanup).toHaveBeenCalledOnce();
  });

  it("runs authenticated cleanup from the one-minute production maintenance cadence", async () => {
    process.env.INTERNAL_WORKER_AUTH_SECRET = WORKER_SECRET;
    const runRegistrationSessionCleanup = vi.fn(async () => 3);
    const drainDueOutboxEmails = vi.fn(async () => ({ processed: 2, batchFull: false }));
    vi.doMock("@/features/auth/server/outbox", async (importOriginal) => {
      const actual = await importOriginal<typeof import("@/features/auth/server/outbox")>();
      return { ...actual, runRegistrationSessionCleanup, drainDueOutboxEmails };
    });
    vi.doMock("@/lib/rateLimit", () => ({
      buildAdmissionRateLimitChecks: vi.fn(() => []),
      buildRateLimitKey: vi.fn(),
      getClientIp: vi.fn(() => "203.0.113.10"),
      rateLimit: vi.fn(),
    }));

    const { GET } = await import("@/app/api/internal/outbox-email/route");
    const request = new Request("https://auth.example.com/api/internal/outbox-email", {
      headers: { authorization: `Bearer ${WORKER_SECRET}` },
    });
    const response = await GET(request);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true, deleted: 3, processed: 2, batchFull: false });
    expect(runRegistrationSessionCleanup).toHaveBeenCalledOnce();
  });

  it("builds QStash-safe worker bodies without payload or secret material", async () => {
    const { buildOutboxWorkerMessage } = await import("@/features/auth/server/outbox");
    const body = buildOutboxWorkerMessage({
      id: "outbox_123",
    });

    expect(body).toEqual({ id: "outbox_123" });
    expect(JSON.stringify(body)).not.toContain("payload");
    expect(JSON.stringify(body)).not.toContain("recipient");
    expect(JSON.stringify(body)).not.toContain("inviteCiphertext");
    expect(JSON.stringify(body)).not.toContain("raw");
    expect(JSON.stringify(body)).not.toContain("otp");
  });

  it("builds deterministic dedup ids without embedding raw token or email", async () => {
    const { buildOutboxDedupId } = await import("@/features/auth/server/outbox");
    const dedupId = buildOutboxDedupId({
      eventType: "INVITATION_DELIVERY",
      subjectId: "invite_123",
      keyVersion: 1,
      contentVersion: "v1",
    });

    expect(dedupId).toBe(
      buildOutboxDedupId({
        eventType: "INVITATION_DELIVERY",
        subjectId: "invite_123",
        keyVersion: 1,
        contentVersion: "v1",
      })
    );
    expect(dedupId).toMatch(/^[a-f0-9]{64}$/);
    expect(dedupId).not.toContain("invite_123");
    expect(dedupId).not.toContain("invitee@example.com");
    expect(dedupId).not.toContain("raw-invite-token");
  });

  it("builds QStash publish requests with dedup header and opaque worker body", async () => {
    const { buildQStashPublishRequest } = await import("@/features/auth/server/outbox");
    const request = buildQStashPublishRequest({
      qstashBaseUrl: "https://qstash.upstash.io",
      qstashToken: "qstash-token",
      workerAuthorizationSecret: WORKER_SECRET,
      destinationUrl: "https://auth.example.com/api/internal/outbox-email",
      dedupId: "dedup_123",
      message: {
        id: "outbox_123",
      },
    });

    expect(request).toEqual({
      url: "https://qstash.upstash.io/v2/publish/https://auth.example.com/api/internal/outbox-email",
      init: {
        method: "POST",
        headers: {
          Authorization: "Bearer qstash-token",
          "Content-Type": "application/json",
          "Upstash-Deduplication-Id": "dedup_123",
          "Upstash-Forward-Authorization": `Bearer ${WORKER_SECRET}`,
        },
        body: JSON.stringify({ id: "outbox_123" }),
      },
    });
    expect(request.init.body).not.toContain("payload");
    expect(request.init.body).not.toContain("invitee@example.com");
    expect(request.init.body).not.toContain("raw-invite-token");
    expect(request.init.body).not.toContain("inviteCiphertext");
  });

  it("aborts an in-flight provider request before reporting timeout", async () => {
    vi.useFakeTimers();
    const observed: { signal: AbortSignal | null } = { signal: null };
    const { deliverClaimedOutboxEmail, OUTBOX_PROVIDER_TIMEOUT_MS } = await import(
      "@/features/auth/server/outbox"
    );
    const delivery = deliverClaimedOutboxEmail(CLAIMABLE_VERIFICATION_ROW, {
      db: {
        $transaction: vi.fn(), queryClaimableOutboxEmails: vi.fn(), updateOutboxEmailMany: vi.fn(),
        findRecipientUser: vi.fn(async () => ({ id: "user_123", email: "user@example.com", name: null, status: "INACTIVE" })),
      },
      now: () => new Date(), generateClaimToken: () => "claim",
      createVerificationToken: vi.fn(async () => ({ ok: true as const, code: "123456" })),
      sendVerificationEmail: vi.fn(async ({ signal }) => {
        observed.signal = signal ?? null;
        await new Promise<void>(() => undefined);
      }),
      decryptInviteToken: vi.fn(), buildInviteAcceptUrl: vi.fn(), sendInvitationEmail: vi.fn(),
    });
    const rejection = expect(delivery).rejects.toThrow("EMAIL_SEND_TIMEOUT");
    await vi.advanceTimersByTimeAsync(OUTBOX_PROVIDER_TIMEOUT_MS);
    await rejection;
    expect(observed.signal?.aborted).toBe(true);
    vi.useRealTimers();
  });

  it("cannot miss a parent abort between the initial check and listener subscription", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const reason = new Error("OUTBOX_CRON_DEADLINE");
    const operation = vi.fn(async (_signal: AbortSignal) => {
      await new Promise<void>(() => undefined);
    });
    const { OUTBOX_PROVIDER_TIMEOUT_MS, withProviderTimeout } = await import(
      "@/features/auth/server/outbox/delivery"
    );

    const delivery = withProviderTimeout(operation, controller.signal, () => controller.abort(reason));
    const rejection = expect(delivery).rejects.toBe(reason);
    await vi.advanceTimersByTimeAsync(OUTBOX_PROVIDER_TIMEOUT_MS);
    await rejection;

    expect(operation).not.toHaveBeenCalled();
    vi.useRealTimers();
  });

  it("rejects an already-aborted parent before OTP or provider work starts", async () => {
    const controller = new AbortController();
    controller.abort(new Error("OUTBOX_CRON_DEADLINE"));
    const createVerificationToken = vi.fn(async () => ({ ok: true as const, code: "raw-otp-654321" }));
    const sendVerificationEmail = vi.fn(async () => undefined);
    const { deliverClaimedOutboxEmail } = await import("@/features/auth/server/outbox");

    await expect(deliverClaimedOutboxEmail(CLAIMABLE_VERIFICATION_ROW, {
      db: {
        $transaction: vi.fn(), queryClaimableOutboxEmails: vi.fn(), updateOutboxEmailMany: vi.fn(),
        findRecipientUser: vi.fn(async () => ({ id: "user_123", email: "secret@example.test", name: null, status: "INACTIVE" })),
      },
      now: () => new Date(), generateClaimToken: () => "claim",
      createVerificationToken, sendVerificationEmail,
      decryptInviteToken: vi.fn(), buildInviteAcceptUrl: vi.fn(), sendInvitationEmail: vi.fn(),
    }, controller.signal)).rejects.toThrow("OUTBOX_CRON_DEADLINE");

    expect(createVerificationToken).not.toHaveBeenCalled();
    expect(sendVerificationEmail).not.toHaveBeenCalled();
  });

  it("does not enter direct fallback after the deadline aborts a failed QStash publish", async () => {
    const controller = new AbortController();
    const process = vi.fn(async () => ({ ok: true as const, outcome: "sent" as const }));
    const publish = vi.fn(async () => {
      controller.abort(new Error("OUTBOX_CRON_DEADLINE"));
      throw new Error("QSTASH_PUBLISH_FAILED");
    });
    const { deliverOutboxRowWithFallback } = await import("@/features/auth/server/outbox");

    await expect(deliverOutboxRowWithFallback(
      { id: "outbox_123", dedupId: "dedup_123" }, controller.signal, publish, process,
    )).rejects.toThrow("OUTBOX_CRON_DEADLINE");
    expect(process).not.toHaveBeenCalled();
  });

  it("starts neither QStash nor direct fallback when the cron signal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort(new Error("OUTBOX_CRON_DEADLINE"));
    const publish = vi.fn(async () => "message-id");
    const process = vi.fn(async () => ({ ok: true as const, outcome: "sent" as const }));
    const { deliverOutboxRowWithFallback } = await import("@/features/auth/server/outbox");

    await expect(deliverOutboxRowWithFallback(
      { id: "outbox_123", dedupId: "dedup_123" }, controller.signal, publish, process,
    )).rejects.toThrow("OUTBOX_CRON_DEADLINE");
    expect(publish).not.toHaveBeenCalled();
    expect(process).not.toHaveBeenCalled();
  });

  it("starts no claim or retry mutation when processing begins after the deadline", async () => {
    const controller = new AbortController();
    controller.abort(new Error("OUTBOX_CRON_DEADLINE"));
    const transaction = vi.fn();
    const updateOutboxEmailMany = vi.fn();
    const createVerificationToken = vi.fn();
    const sendVerificationEmail = vi.fn();
    const { processOutboxEmailMessage } = await import("@/features/auth/server/outbox");

    await expect(processOutboxEmailMessage({ id: "outbox_123" }, {
      db: {
        $transaction: transaction, queryClaimableOutboxEmails: vi.fn(),
        updateOutboxEmailMany, findRecipientUser: vi.fn(),
      },
      now: () => new Date(), generateClaimToken: () => "claim",
      createVerificationToken, sendVerificationEmail,
      decryptInviteToken: vi.fn(), buildInviteAcceptUrl: vi.fn(), sendInvitationEmail: vi.fn(),
    }, controller.signal)).rejects.toThrow("OUTBOX_CRON_DEADLINE");

    expect(transaction).not.toHaveBeenCalled();
    expect(updateOutboxEmailMany).not.toHaveBeenCalled();
    expect(createVerificationToken).not.toHaveBeenCalled();
    expect(sendVerificationEmail).not.toHaveBeenCalled();
  });

  it("publishes an id-only QStash message and returns only its message id", async () => {
    const fetcher = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect(init?.body).toBe(JSON.stringify({ id: "outbox_123" }));
      return Response.json({ messageId: "qstash-message-1" });
    });
    const { publishOutboxEmailId } = await import("@/features/auth/server/outbox");
    await expect(publishOutboxEmailId({
      qstashBaseUrl: "https://qstash.upstash.io", qstashToken: "token",
      workerAuthorizationSecret: WORKER_SECRET,
      destinationUrl: "https://auth.example.com/api/internal/outbox-email",
      dedupId: "dedup", message: { id: "outbox_123" },
    }, fetcher)).resolves.toBe("qstash-message-1");
  });

  it("fails readiness when a stored invite key version is absent", async () => {
    const { validateStoredInviteKeyVersions } = await import("@/features/auth/server/outbox");
    const reader = { outboxEmail: { findMany: vi.fn(async () => [{ keyVersion: 1 }, { keyVersion: 2 }]) } };
    await expect(validateStoredInviteKeyVersions(reader, new Map([[2, INVITE_KEY_HEX]])))
      .rejects.toThrow("INVITE_DELIVERY_KEY_VERSION_MISSING");
  });

  it("claims one due row with SKIP LOCKED, sends OTP email, and finalizes with the claim token", async () => {
    const now = new Date("2026-06-21T00:00:00.000Z");
    const tx = {
      queryClaimableOutboxEmails: vi.fn(async () => [CLAIMABLE_VERIFICATION_ROW]),
      updateOutboxEmailMany: vi.fn(async () => ({ count: 1 })),
      findRecipientUser: vi.fn(async () => ({
        id: "user_123",
        email: "user@example.com",
        name: "Ada",
        status: "INACTIVE",
      })),
    };
    const deps = {
      db: {
        $transaction: vi.fn(async (callback) => callback(tx)),
        queryClaimableOutboxEmails: tx.queryClaimableOutboxEmails,
        updateOutboxEmailMany: tx.updateOutboxEmailMany,
        findRecipientUser: tx.findRecipientUser,
      },
      now: vi.fn(() => now),
      generateClaimToken: vi.fn(() => "claim_123"),
      createVerificationToken: vi.fn(async () => ({ ok: true as const, code: "123456" })),
      sendVerificationEmail: vi.fn(async () => undefined),
      decryptInviteToken: vi.fn(),
      buildInviteAcceptUrl: vi.fn(),
      sendInvitationEmail: vi.fn(),
    };
    const { CLAIM_DUE_OUTBOX_EMAIL_SQL, processOutboxEmailMessage } = await import(
      "@/features/auth/server/outbox"
    );

    const result = await processOutboxEmailMessage({ id: "outbox_123" }, deps);

    expect(CLAIM_DUE_OUTBOX_EMAIL_SQL).toMatch(/FOR UPDATE SKIP LOCKED/);
    expect(result).toEqual({ ok: true, outcome: "sent" });
    expect(tx.queryClaimableOutboxEmails).toHaveBeenCalledWith("outbox_123", now);
    expect(tx.updateOutboxEmailMany).toHaveBeenNthCalledWith(1, {
      where: { id: "outbox_123", status: { in: ["PENDING", "CLAIMED"] } },
      data: {
        status: "CLAIMED",
        claimedAt: now,
        claimToken: "claim_123",
        leaseExpiresAt: new Date("2026-06-21T00:05:00.000Z"),
        lastErrorCode: null,
      },
    });
    expect(deps.createVerificationToken).toHaveBeenCalledWith("user@example.com");
    expect(deps.sendVerificationEmail).toHaveBeenCalledWith(expect.objectContaining({
      to: "user@example.com",
      code: "123456",
      name: "Ada",
    }));
    expect(tx.updateOutboxEmailMany).toHaveBeenNthCalledWith(2, {
      where: { id: "outbox_123", claimToken: "claim_123", status: "CLAIMED" },
      data: {
        status: "SENT",
        sentAt: now,
        claimToken: null,
        leaseExpiresAt: null,
        inviteCiphertext: null,
        keyVersion: null,
        clearedAt: now,
      },
    });
  });

  it("keeps the user inactive and credential-free when provider delivery fails", async () => {
    const userUpdate = vi.fn(async () => undefined);
    const sessionCreate = vi.fn(async () => undefined);
    const auditCreate = vi.fn(async () => undefined);
    const updateOutboxEmailMany = vi.fn(async () => ({ count: 1 }));
    const prisma = {
      $queryRawUnsafe: vi.fn(async () => [CLAIMABLE_VERIFICATION_ROW]),
      $transaction: vi.fn(async (callback: (transaction: typeof prisma) => Promise<unknown>) => callback(prisma)),
      outboxEmail: { updateMany: updateOutboxEmailMany },
      user: {
        findUnique: vi.fn(async () => ({
          id: "user_123", email: "private@example.test", name: null, status: "INACTIVE",
        })),
        update: userUpdate,
      },
      invite: { findUnique: vi.fn() },
      session: { create: sessionCreate },
      auditEvent: { create: auditCreate },
    };
    vi.doMock("@/lib/prisma", () => ({ prisma }));
    const { createPrismaOutboxDb } = await import("@/features/auth/server/outbox/db");
    const deps = {
      db: createPrismaOutboxDb(),
      now: () => new Date("2026-06-21T00:00:00.000Z"), generateClaimToken: () => "claim_123",
      createVerificationToken: vi.fn(async () => ({ ok: true as const, code: "654321" })),
      sendVerificationEmail: vi.fn(async () => { throw new Error("EMAIL_SEND_FAILED"); }),
      decryptInviteToken: vi.fn(), buildInviteAcceptUrl: vi.fn(), sendInvitationEmail: vi.fn(),
    };
    const { processOutboxEmailMessage } = await import("@/features/auth/server/outbox");

    await expect(processOutboxEmailMessage({ id: "outbox_123" }, deps)).resolves.toEqual({ ok: true, outcome: "retry" });
    expect(userUpdate).not.toHaveBeenCalled();
    expect(sessionCreate).not.toHaveBeenCalled();
    expect(auditCreate).not.toHaveBeenCalled();
    expect(updateOutboxEmailMany).toHaveBeenLastCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: "PENDING", lastErrorCode: "EMAIL_SEND_FAILED" }),
    }));
  });

  it("prevents stale claim tokens from finalizing a re-claimed row", async () => {
    const now = new Date("2026-06-21T00:00:00.000Z");
    const updateOutboxEmailMany = vi.fn(async () => ({ count: 0 }));
    const { finalizeOutboxEmailSent } = await import("@/features/auth/server/outbox");

    const finalized = await finalizeOutboxEmailSent("outbox_123", "stale_claim", {
      db: { updateOutboxEmailMany },
      now: vi.fn(() => now),
    });

    expect(finalized).toBe(false);
    expect(updateOutboxEmailMany).toHaveBeenCalledWith({
      where: { id: "outbox_123", claimToken: "stale_claim", status: "CLAIMED" },
      data: {
        status: "SENT",
        sentAt: now,
        claimToken: null,
        leaseExpiresAt: null,
        inviteCiphertext: null,
        keyVersion: null,
        clearedAt: now,
      },
    });
  });

  it("runs one scoped RegistrationSession cleanup batch on the worker cadence", async () => {
    const now = new Date("2026-06-21T00:10:00.000Z");
    const deleteEligibleRegistrationSessions = vi.fn(async () => 2);
    const {
      REGISTRATION_SESSION_CLEANUP_BATCH_SIZE,
      REGISTRATION_SESSION_CLEANUP_SLO_SECONDS,
      runRegistrationSessionCleanup,
    } = await import("@/features/auth/server/outbox");

    await expect(runRegistrationSessionCleanup({
      deleteEligibleRegistrationSessions,
      now: () => now,
    })).resolves.toBe(2);

    expect(REGISTRATION_SESSION_CLEANUP_SLO_SECONDS).toBe(660);
    expect(deleteEligibleRegistrationSessions).toHaveBeenCalledWith({
      now,
      consumedBefore: new Date("2026-06-21T00:09:00.000Z"),
      limit: REGISTRATION_SESSION_CLEANUP_BATCH_SIZE,
    });
  });

  it("terminal failure clears invite ciphertext while preserving row identity", async () => {
    const now = new Date("2026-06-21T00:00:00.000Z");
    const updateOutboxEmailMany = vi.fn(async () => ({ count: 1 }));
    const { recordOutboxEmailFailure } = await import("@/features/auth/server/outbox");

    await recordOutboxEmailFailure(
      {
        id: "outbox_456",
        eventType: "INVITATION_DELIVERY",
        aggregateId: "invite_123",
        recipientUserId: "user_456",
        attempts: 4,
        inviteCiphertext: new Uint8Array([1, 2, 3]),
        keyVersion: 1,
      },
      "claim_456",
      new Error("EMAIL_SEND_FAILED"),
      {
        db: { updateOutboxEmailMany },
        now: vi.fn(() => now),
      }
    );

    expect(updateOutboxEmailMany).toHaveBeenCalledWith({
      where: { id: "outbox_456", claimToken: "claim_456", status: "CLAIMED" },
      data: {
        status: "FAILED",
        attempts: 5,
        failedAt: now,
        nextAttemptAt: null,
        claimToken: null,
        leaseExpiresAt: null,
        lastErrorCode: "EMAIL_SEND_FAILED",
        inviteCiphertext: null,
        keyVersion: null,
        clearedAt: now,
      },
    });
  });

  it("rejects unsupported outbox event types without sending email", async () => {
    const now = new Date("2026-06-21T00:00:00.000Z");
    const tx = {
      queryClaimableOutboxEmails: vi.fn(async () => [
        {
          id: "outbox_admin",
          eventType: "ADMIN_STEP_UP",
          aggregateId: "challenge_123",
          recipientUserId: "user_123",
          attempts: 4,
          inviteCiphertext: null,
          keyVersion: null,
        },
      ]),
      updateOutboxEmailMany: vi.fn(async () => ({ count: 1 })),
      findRecipientUser: vi.fn(async () => ({
        id: "user_123",
        email: "user@example.com",
        name: null,
        status: "INACTIVE",
      })),
    };
    const deps = {
      db: {
        $transaction: vi.fn(async (callback) => callback(tx)),
        queryClaimableOutboxEmails: tx.queryClaimableOutboxEmails,
        updateOutboxEmailMany: tx.updateOutboxEmailMany,
        findRecipientUser: tx.findRecipientUser,
      },
      now: vi.fn(() => now),
      generateClaimToken: vi.fn(() => "claim_admin"),
      createVerificationToken: vi.fn(async () => ({ ok: true as const, code: "123456" })),
      sendVerificationEmail: vi.fn(async () => undefined),
      decryptInviteToken: vi.fn(),
      buildInviteAcceptUrl: vi.fn(),
      sendInvitationEmail: vi.fn(),
    };
    const { processOutboxEmailMessage } = await import("@/features/auth/server/outbox");

    await expect(processOutboxEmailMessage({ id: "outbox_admin" }, deps)).resolves.toEqual({
      ok: true,
      outcome: "failed",
    });

    expect(deps.createVerificationToken).not.toHaveBeenCalled();
    expect(deps.sendVerificationEmail).not.toHaveBeenCalled();
    expect(deps.sendInvitationEmail).not.toHaveBeenCalled();
    expect(tx.updateOutboxEmailMany).toHaveBeenLastCalledWith({
      where: { id: "outbox_admin", claimToken: "claim_admin", status: "CLAIMED" },
      data: {
        status: "FAILED",
        attempts: 5,
        failedAt: now,
        nextAttemptAt: null,
        claimToken: null,
        leaseExpiresAt: null,
        lastErrorCode: "OUTBOX_UNSUPPORTED_EVENT_TYPE",
        inviteCiphertext: null,
        keyVersion: null,
        clearedAt: now,
      },
    });
  });

  it("rejects invite ciphertext encrypted for the wrong key", async () => {
    const { decryptInviteDeliveryToken, encryptInviteDeliveryToken } = await import(
      "@/features/auth/server/outbox"
    );
    const ciphertext = encryptInviteDeliveryToken("raw-invite-token", INVITE_KEY_HEX);

    expect(() => decryptInviteDeliveryToken(ciphertext, WRONG_INVITE_KEY_HEX)).toThrow(
      "INVITE_DELIVERY_DECRYPT_FAILED"
    );
  });

  it("decrypts pending invite rows with their original key version after rotation", async () => {
    const { createInviteTokenDecryptor, encryptInviteDeliveryToken } = await import(
      "@/features/auth/server/outbox"
    );
    const ciphertext = encryptInviteDeliveryToken("raw-invite-token", INVITE_KEY_HEX);
    const decrypt = createInviteTokenDecryptor(
      new Map([
        [1, INVITE_KEY_HEX],
        [2, WRONG_INVITE_KEY_HEX],
      ])
    );

    expect(decrypt(ciphertext, 1)).toBe("raw-invite-token");
    expect(() => decrypt(ciphertext, 2)).toThrow("INVITE_DELIVERY_DECRYPT_FAILED");
  });

  it("decrypts invitation tokens in memory and emits the raw token only in the URL fragment", async () => {
    const now = new Date("2026-06-21T00:00:00.000Z");
    const rawToken = "raw-invite-token";
    const { buildInviteAcceptUrl, decryptInviteDeliveryToken, encryptInviteDeliveryToken } =
      await import("@/features/auth/server/outbox");
    const ciphertext = encryptInviteDeliveryToken(rawToken, INVITE_KEY_HEX);
    const tx = {
      queryClaimableOutboxEmails: vi.fn(async () => [
        {
          id: "outbox_456",
          eventType: "INVITATION_DELIVERY",
          aggregateId: "invite_123",
          recipientUserId: null,
          attempts: 0,
          inviteCiphertext: ciphertext,
          keyVersion: 1,
        },
      ]),
      updateOutboxEmailMany: vi.fn(async () => ({ count: 1 })),
      findRecipientUser: vi.fn(),
      findInviteRecipient: vi.fn(async () => ({
        id: "invite_123", normalizedEmail: "invitee@example.com",
        status: "ISSUED", expiresAt: new Date("2026-06-22T00:00:00.000Z"),
      })),
    };
    const sendInvitationEmail = vi.fn(async (_args: InvitationEmailCall) => undefined);
    const deps = {
      db: {
        $transaction: vi.fn(async (callback) => callback(tx)),
        queryClaimableOutboxEmails: tx.queryClaimableOutboxEmails,
        updateOutboxEmailMany: tx.updateOutboxEmailMany,
        findRecipientUser: tx.findRecipientUser,
        findInviteRecipient: tx.findInviteRecipient,
      },
      now: vi.fn(() => now),
      generateClaimToken: vi.fn(() => "claim_456"),
      createVerificationToken: vi.fn(async () => ({ ok: true as const, code: "123456" })),
      sendVerificationEmail: vi.fn(async () => undefined),
      decryptInviteToken: vi.fn((value: Uint8Array, _keyVersion: number | null) =>
        decryptInviteDeliveryToken(value, INVITE_KEY_HEX)
      ),
      buildInviteAcceptUrl: vi.fn((token: string) =>
        buildInviteAcceptUrl(token, "https://auth.example.com")
      ),
      sendInvitationEmail,
    };
    const { processOutboxEmailMessage } = await import("@/features/auth/server/outbox");

    await expect(processOutboxEmailMessage({ id: "outbox_456" }, deps)).resolves.toEqual({
      ok: true,
      outcome: "sent",
    });

    const sentArgs = sendInvitationEmail.mock.calls[0]?.[0];
    if (!sentArgs) throw new Error("Expected invitation email to be sent");

    const inviteUrl = new URL(sentArgs.inviteUrl);
    expect(inviteUrl.pathname).toBe("/invite");
    expect(inviteUrl.search).toBe("");
    expect(inviteUrl.hash).toBe(`#token=${rawToken}`);
    expect(sentArgs).toEqual(expect.objectContaining({
      to: "invitee@example.com",
      inviteUrl: "https://auth.example.com/invite#token=raw-invite-token",
    }));
    expect(sentArgs.inviteUrl.split("#")[0]).not.toContain(rawToken);
    expect(tx.findRecipientUser).not.toHaveBeenCalled();
    expect(tx.findInviteRecipient).toHaveBeenCalledWith("invite_123");
    expect(tx.updateOutboxEmailMany).toHaveBeenLastCalledWith({
      where: { id: "outbox_456", claimToken: "claim_456", status: "CLAIMED" },
      data: {
        status: "SENT",
        sentAt: now,
        claimToken: null,
        leaseExpiresAt: null,
        inviteCiphertext: null,
        keyVersion: null,
        clearedAt: now,
      },
    });
  });

  it("rejects invitation rows whose aggregate is not an issued unexpired invite", async () => {
    const { deliverClaimedOutboxEmail } = await import("@/features/auth/server/outbox");
    const deps = {
      db: {
        $transaction: vi.fn(), queryClaimableOutboxEmails: vi.fn(), updateOutboxEmailMany: vi.fn(),
        findRecipientUser: vi.fn(),
        findInviteRecipient: vi.fn(async () => ({
          id: "different_invite", normalizedEmail: "invitee@example.com",
          status: "ISSUED", expiresAt: new Date("2026-06-22T00:00:00.000Z"),
        })),
      },
      now: () => new Date("2026-06-21T00:00:00.000Z"), generateClaimToken: () => "claim",
      createVerificationToken: vi.fn(), sendVerificationEmail: vi.fn(),
      decryptInviteToken: vi.fn(() => "token"), buildInviteAcceptUrl: vi.fn(), sendInvitationEmail: vi.fn(),
    };
    await expect(deliverClaimedOutboxEmail({
      id: "outbox", eventType: "INVITATION_DELIVERY", aggregateId: "invite_123",
      recipientUserId: null, attempts: 0, inviteCiphertext: new Uint8Array([1]), keyVersion: 1,
    }, deps)).rejects.toThrow("OUTBOX_INVITE_INVALID");
    expect(deps.sendInvitationEmail).not.toHaveBeenCalled();
  });

  it("fails closed when the verification provider key is absent", async () => {
    vi.doMock("@/lib/env", () => ({ env: { RESEND_API_KEY: undefined, RESEND_FROM: undefined } }));
    const { sendVerificationEmail } = await import("@/features/auth/lib/email/provider");
    const { sendInvitationEmail } = await import("@/features/auth/server/outbox/invitationEmail");
    await expect(sendVerificationEmail({ to: "user@example.com", code: "123456" }))
      .rejects.toThrow("EMAIL_PROVIDER_NOT_CONFIGURED");
    await expect(sendInvitationEmail({ to: "invitee@example.com", inviteUrl: "https://example.test/#token=x" }))
      .rejects.toThrow("EMAIL_PROVIDER_NOT_CONFIGURED");
  });

  it("logs only a stable code when verification provider delivery fails", async () => {
    const secrets = {
      email: "sentinel-private-email@example.test",
      otp: "sentinel-raw-otp-938421",
      key: "sentinel-resend-api-key",
    };
    vi.stubEnv("NODE_ENV", "development");
    vi.doMock("@/lib/env", () => ({
      env: { RESEND_API_KEY: secrets.key, RESEND_FROM: "sender@example.test" },
    }));
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({
      message: `${secrets.email}:${secrets.otp}:${secrets.key}`,
    }, { status: 500 })));
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { sendVerificationEmail } = await import("@/features/auth/lib/email/provider");

    const failure = await sendVerificationEmail({ to: secrets.email, code: secrets.otp })
      .catch((error: unknown) => error);
    const emitted = JSON.stringify({
      logs: consoleError.mock.calls,
      failure: failure instanceof Error ? failure.message : "unknown",
    });

    expect(failure).toEqual(new Error("EMAIL_SEND_FAILED"));
    expect(emitted).toContain("EMAIL_SEND_FAILED");
    expect(emitted).not.toContain(secrets.email);
    expect(emitted).not.toContain(secrets.otp);
    expect(emitted).not.toContain(secrets.key);
  });

  it("redacts provider secrets from processor state, logs, and audit surfaces", async () => {
    const secrets = {
      email: "sentinel-invitee@example.test",
      otp: "sentinel-raw-otp-572901",
      invite: "sentinel-raw-invite-token",
      key: "sentinel-invite-key",
    };
    const consoleSpies = [
      vi.spyOn(console, "log").mockImplementation(() => undefined),
      vi.spyOn(console, "warn").mockImplementation(() => undefined),
      vi.spyOn(console, "error").mockImplementation(() => undefined),
    ];
    const auditCreate = vi.fn(async () => undefined);
    const updateOutboxEmailMany = vi.fn(async () => ({ count: 1 }));
    const prisma = {
      $queryRawUnsafe: vi.fn(async () => [{
        id: "outbox_secret", eventType: "INVITATION_DELIVERY", aggregateId: "invite_secret",
        recipientUserId: null, attempts: 0, inviteCiphertext: new Uint8Array([1]), keyVersion: 1,
      }]),
      $transaction: vi.fn(async (callback: (transaction: typeof prisma) => Promise<unknown>) => callback(prisma)),
      outboxEmail: { updateMany: updateOutboxEmailMany },
      user: { findUnique: vi.fn(), update: vi.fn() },
      invite: { findUnique: vi.fn(async () => ({
          id: "invite_secret", normalizedEmail: secrets.email,
          status: "ISSUED", expiresAt: new Date("2026-06-22T00:00:00.000Z"),
        })) },
      session: { create: vi.fn() },
      auditEvent: { create: auditCreate },
    };
    vi.doMock("@/lib/prisma", () => ({ prisma }));
    const { createPrismaOutboxDb } = await import("@/features/auth/server/outbox/db");
    const deps = {
      db: createPrismaOutboxDb(),
      now: () => new Date("2026-06-21T00:00:00.000Z"), generateClaimToken: () => "claim_secret",
      createVerificationToken: vi.fn(async () => ({ ok: true as const, code: secrets.otp })),
      sendVerificationEmail: vi.fn(), decryptInviteToken: vi.fn(() => secrets.invite),
      buildInviteAcceptUrl: vi.fn(() => `https://example.test/invite#token=${secrets.invite}`),
      sendInvitationEmail: vi.fn(async () => {
        throw new Error(`${secrets.email}:${secrets.invite}:${secrets.key}`);
      }),
    };
    const { processOutboxEmailMessage } = await import("@/features/auth/server/outbox");

    await expect(processOutboxEmailMessage({ id: "outbox_secret" }, deps))
      .resolves.toEqual({ ok: true, outcome: "retry" });
    const emitted = JSON.stringify({
      logs: consoleSpies.flatMap((spy) => spy.mock.calls),
      audit: auditCreate.mock.calls,
      state: updateOutboxEmailMany.mock.calls,
    });

    expect(emitted).toContain("OUTBOX_DELIVERY_FAILED");
    Object.values(secrets).forEach((secret) => expect(emitted).not.toContain(secret));
    expect(auditCreate).not.toHaveBeenCalled();
  });

  it("maps QStash transport failures to a stable redacted error", async () => {
    const secrets = [
      "sentinel-private-email@example.test", "sentinel-raw-otp-125709",
      "sentinel-raw-invite-token", "sentinel-qstash-key",
    ];
    const consoleSpies = [
      vi.spyOn(console, "log").mockImplementation(() => undefined),
      vi.spyOn(console, "warn").mockImplementation(() => undefined),
      vi.spyOn(console, "error").mockImplementation(() => undefined),
    ];
    const fetcher = vi.fn(async () => {
      throw new Error(secrets.join(":"));
    });
    const { publishOutboxEmailId } = await import("@/features/auth/server/outbox");

    const failure = await publishOutboxEmailId({
      qstashBaseUrl: "https://qstash.upstash.io", qstashToken: secrets[3] ?? "missing",
      workerAuthorizationSecret: "sentinel-worker-key",
      destinationUrl: "https://auth.example.test/api/internal/outbox-email",
      dedupId: "dedup-secret", message: { id: "outbox-secret" },
    }, fetcher).catch((error: unknown) => error);
    const emitted = JSON.stringify({
      logs: consoleSpies.flatMap((spy) => spy.mock.calls),
      failure: failure instanceof Error ? failure.message : "unknown",
    });

    expect(failure).toEqual(new Error("QSTASH_PUBLISH_FAILED"));
    expect(emitted).toContain("QSTASH_PUBLISH_FAILED");
    secrets.forEach((secret) => expect(emitted).not.toContain(secret));
  });

  it("bounds cron count and concurrency while reporting remaining backlog", async () => {
    const {
      drainDueOutboxEmails, OUTBOX_CRON_CONCURRENCY, OUTBOX_CRON_DELIVERY_CAPACITY,
    } = await import("@/features/auth/server/outbox");
    const rows = Array.from({ length: OUTBOX_CRON_DELIVERY_CAPACITY + 1 }, (_, index) => ({
      id: `outbox_${index}`, dedupId: `dedup_${index}`,
    }));
    let active = 0;
    let peak = 0;
    const result = await drainDueOutboxEmails(new Date(), {
      monotonicNow: () => 0,
      findDueRows: vi.fn(async (_now, take) => rows.slice(0, take)),
      deliver: vi.fn(async () => {
        active += 1;
        peak = Math.max(peak, active);
        await Promise.resolve();
        active -= 1;
      }),
    });
    expect(result).toEqual({
      processed: OUTBOX_CRON_DELIVERY_CAPACITY, batchFull: true, deadlineExceeded: false,
    });
    expect(peak).toBe(OUTBOX_CRON_CONCURRENCY);
  });

  it("aborts in-flight cron delivery at the strict wall-time deadline", async () => {
    vi.useFakeTimers();
    const { drainDueOutboxEmails, OUTBOX_CRON_DEADLINE_MS } = await import(
      "@/features/auth/server/outbox"
    );
    const observed: { signal: AbortSignal | null } = { signal: null };
    const draining = drainDueOutboxEmails(new Date(), {
      monotonicNow: () => 0,
      findDueRows: vi.fn(async () => [{ id: "outbox_1", dedupId: "dedup_1" }]),
      deliver: vi.fn(async (_row, signal) => {
        observed.signal = signal;
        await new Promise<void>((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(signal.reason), { once: true });
        });
      }),
    });
    await vi.advanceTimersByTimeAsync(OUTBOX_CRON_DEADLINE_MS);
    await expect(draining).resolves.toEqual({ processed: 1, batchFull: true, deadlineExceeded: true });
    expect(observed.signal?.aborted).toBe(true);
    vi.useRealTimers();
  });
});
