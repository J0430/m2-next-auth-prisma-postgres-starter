// tests/gated-registration-credentials.test.ts
// Proves invite-gated credentials registration does not bind a password until OTP verification.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";

const ORIGINAL_ENV = { ...process.env };
const NOW = new Date("2026-06-21T00:00:00.000Z");
const TOKEN_HASH = Buffer.from("a".repeat(64), "hex");
const HANDLE = "opaque-registration-handle";
const testMonotonicClock = (): number => Date.now();

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
  process.env.AUTH_URL = "http://localhost";
  process.env.TURNSTILE_SECRET_KEY = "turnstile-secret";
  process.env.TURNSTILE_EXPECTED_HOSTNAME = "localhost";
  process.env.TURNSTILE_EXPECTED_ACTION = "register";
}

function buildForm(email = "Victim@Example.com"): FormData {
  const formData = new FormData();
  formData.set("firstname", "Victim");
  formData.set("lastname", "User");
  formData.set("email", email);
  formData.set("country", "US");
  formData.set("city", "New York");
  formData.set("address", "123 Test Street");
  formData.set("csrfToken", "csrf-token");
  formData.set("turnstileToken", "turnstile-token");
  formData.set("password", "AttackerP@ss123");
  formData.set("repeatpassword", "AttackerP@ss123");
  return formData;
}

function buildHeaders(): Headers {
  return new Headers({
    origin: "http://localhost",
    "sec-fetch-site": "same-origin",
    "x-forwarded-for": "127.0.0.1",
  });
}

function expectedHandleHash(): Buffer {
  return createHash("sha256").update(HANDLE, "utf8").digest();
}

function expectGenericRegistrationFailure(
  result: Awaited<ReturnType<typeof import("@/features/auth/server/registration").registerWithInvite>>
): void {
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.status).toBe(403);
    expect(result.body).toMatchObject({
      ok: false,
      message: "Unable to complete this request.",
    });
    expect(result.body.supportId).toMatch(/^admission_/);
  }
}

function buildTurnstileFetcher(): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
  return vi.fn(async () =>
    Response.json({
      success: true,
      challenge_ts: NOW.toISOString(),
      hostname: "localhost",
      action: "register",
    })
  );
}

beforeEach(() => {
  vi.resetModules();
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  vi.spyOn(performance, "now").mockReturnValue(0);
  resetEnv();
  setBaseEnv();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  resetEnv();
});

describe("TASK-019 shared signup entry", () => {
  it("routes both credentials signup actions to the same registerUser implementation", async () => {
    const sharedRegisterUser = vi.fn(async () => ({
      ok: true as const,
      meta: { requiresEmailVerification: true, email: "user@example.com" },
    }));
    vi.doMock("@/features/auth/server/registration/registerAction", () => ({
      registerUser: sharedRegisterUser,
    }));

    const [standard, oauth] = await Promise.all([
      import("@/features/auth/server/actions/signup"),
      import("@/features/auth/server/oauth/actions/signup"),
    ]);
    const formData = new FormData();

    await expect(standard.registerUser(formData)).resolves.toMatchObject({ ok: true });
    await expect(oauth.registerUser(formData)).resolves.toMatchObject({ ok: true });
    expect(sharedRegisterUser).toHaveBeenCalledTimes(2);
    expect(sharedRegisterUser).toHaveBeenNthCalledWith(1, formData);
    expect(sharedRegisterUser).toHaveBeenNthCalledWith(2, formData);
  });
});

describe("registerWithInvite", () => {
  function setupRegistrationMocks(
    overrides: {
      redeemOk?: boolean;
      reuseInviteId?: string;
      createThrows?: Error;
      registrationSession?: {
        id: string;
        handleHash: Buffer;
        inviteTokenHash: Buffer | null;
        inviteId: string | null;
        normalizedEmail: string | null;
        status: string;
        expiresAt: Date;
        consumedAt: Date | null;
      } | null;
      consumeCounts?: number[];
      userIds?: string[];
      transactionDelayMs?: number;
      sessionLookupDelayMs?: number;
      transactionThrows?: Error;
    } = {}
  ) {
    const defaultRegistrationSession = {
      id: "registration-session-1",
      handleHash: expectedHandleHash(),
      inviteTokenHash: TOKEN_HASH,
      inviteId: null,
      normalizedEmail: "victim@example.com",
      status: "PENDING",
      expiresAt: new Date(NOW.getTime() + 60_000),
      consumedAt: null,
    };
    const registrationSession =
      overrides.registrationSession === undefined
        ? defaultRegistrationSession
        : overrides.registrationSession;
    const consumeCounts = [...(overrides.consumeCounts ?? [1])];
    const userIds = [...(overrides.userIds ?? ["user-victim"])];
    const tx = {
      registrationSession: {
        findUnique: vi.fn(async () => {
          if (overrides.sessionLookupDelayMs) {
            await new Promise((resolve) => setTimeout(resolve, overrides.sessionLookupDelayMs));
          }
          return registrationSession;
        }),
        updateMany: vi.fn(async () => ({ count: consumeCounts.shift() ?? 1 })),
      },
      user: {
        create: vi.fn(async () => {
          if (overrides.createThrows) throw overrides.createThrows;
          return { id: userIds.shift() ?? "user-victim" };
        }),
        findUnique: vi.fn(async () => ({ id: "user-victim" })),
      },
      invite: {
        updateMany: vi.fn(),
        findFirst: vi.fn(),
      },
      auditEvent: {
        create: vi.fn(),
      },
      outboxEmail: {
        create: vi.fn(async () => ({ id: "outbox-1", dedupId: "email-verification:user-victim" })),
      },
    };
    let transactionCalls = 0;
    const prisma = {
      registrationSession: {
        findUnique: vi.fn(async () => registrationSession),
      },
      $transaction: vi.fn(async (callback: (transaction: typeof tx) => Promise<unknown>) => {
        transactionCalls += 1;
        if (overrides.transactionDelayMs && transactionCalls > 1) {
          await new Promise((resolve) => setTimeout(resolve, overrides.transactionDelayMs));
        }
        if (overrides.transactionThrows) throw overrides.transactionThrows;
        return callback(tx);
      }),
    };
    const redeemInviteInTx = vi.fn(async (client: { signalReuseDetected?: (inviteId: string) => never }) =>
      overrides.redeemOk === false && overrides.reuseInviteId && client.signalReuseDetected
        ? client.signalReuseDetected(overrides.reuseInviteId)
        : overrides.redeemOk === false
        ? { ok: false as const }
        : {
            ok: true as const,
            invite: {
              id: "invite-1",
              tokenHash: TOKEN_HASH,
              normalizedEmail: "victim@example.com",
              status: "REDEEMED" as const,
              expiresAt: new Date(NOW.getTime() + 60_000),
              redeemedByUserId: "user-victim",
              redeemedAt: NOW,
              revokedAt: null,
            },
          }
    );
    const recordInviteReuseEvidence = vi.fn(async () => undefined);

    vi.doMock("@/lib/prisma", () => ({ prisma }));
    vi.doMock("@/features/auth/server/invites", () => ({
      redeemInviteInTx,
      recordInviteReuseEvidence,
    }));

    return { prisma, tx, redeemInviteInTx, recordInviteReuseEvidence };
  }

  it("creates an INACTIVE user with no password and commits consume, redeem, user, and outbox in one transaction", async () => {
    const { prisma, tx, redeemInviteInTx } = setupRegistrationMocks();
    const { registerWithInvite } = await import("@/features/auth/server/registration");
    const startedAt = Date.now();

    let settled = false;
    const pending = registerWithInvite({
      formData: buildForm(),
      headers: buildHeaders(),
      expectedOrigin: "http://localhost",
      registrationHandle: HANDLE,
      csrfSessionToken: "csrf-token",
      monotonicClock: testMonotonicClock,
      now: NOW,
      fetcher: buildTurnstileFetcher(),
    }).finally(() => { settled = true; });
    await vi.advanceTimersByTimeAsync(249);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    const result = await pending;

    expect(Date.now() - startedAt).toBe(250);
    expect(result).toMatchObject({ ok: true, email: "victim@example.com", userId: "user-victim" });
    expect(prisma.$transaction).toHaveBeenCalledTimes(2);
    expect(prisma.$transaction).toHaveBeenLastCalledWith(expect.any(Function), {
      maxWait: 50,
      timeout: 150,
    });
    expect(tx.registrationSession.updateMany).toHaveBeenCalledWith({
      where: {
        handleHash: expectedHandleHash(),
        status: "PENDING",
        expiresAt: { gt: NOW },
        consumedAt: null,
      },
      data: { status: "CONSUMED", consumedAt: NOW },
    });
    expect(tx.user.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          email: "victim@example.com",
          password: null,
          passwordHash: null,
          hasPasswordCredential: true,
          emailVerified: null,
          status: "INACTIVE",
        }),
      })
    );
    expect(redeemInviteInTx).toHaveBeenCalledWith(
      expect.objectContaining({
        redeemerUserId: "user-victim",
        invite: expect.objectContaining({
          updateMany: expect.any(Function),
          findFirst: expect.any(Function),
        }),
      }),
      { tokenHash: TOKEN_HASH },
      "victim@example.com"
    );
    expect(tx.outboxEmail.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        eventType: "EMAIL_VERIFICATION",
        recipientUserId: "user-victim",
        dedupId: "email-verification:user-victim",
        status: "PENDING",
      }),
      select: { id: true, dedupId: true },
    });
  });

  it("[B1 opaque-ref isolation] rejects a submitted email/invite-B attempt that does not match invite A's server-resolved ref", async () => {
    const { prisma, tx, redeemInviteInTx } = setupRegistrationMocks();
    const { registerWithInvite } = await import("@/features/auth/server/registration");
    const startedAt = Date.now();
    const formData = buildForm("other-victim@example.com");
    formData.set("inviteToken", "invite-b-token-that-must-be-ignored");

    const pendingResult = registerWithInvite({
      formData,
      headers: buildHeaders(),
      expectedOrigin: "http://localhost",
      registrationHandle: HANDLE,
      csrfSessionToken: "csrf-token",
      monotonicClock: testMonotonicClock,
      now: NOW,
      fetcher: buildTurnstileFetcher(),
    });
    await vi.advanceTimersByTimeAsync(250);
    const result = await pendingResult;

    expect(Date.now() - startedAt).toBe(250);
    expectGenericRegistrationFailure(result);
    expect(tx.registrationSession.findUnique).toHaveBeenCalledWith({
      where: { handleHash: expectedHandleHash() },
      select: expect.any(Object),
    });
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(tx.user.create).not.toHaveBeenCalled();
    expect(redeemInviteInTx).not.toHaveBeenCalled();
  });

  it("[B2 consumed-handle replay] maps count 0 to generic failure and creates no second user", async () => {
    const { tx } = setupRegistrationMocks({
      consumeCounts: [1, 0],
      userIds: ["user-victim-first", "user-victim-second"],
    });
    const { registerWithInvite } = await import("@/features/auth/server/registration");
    const startedAt = Date.now();
    const input = {
      formData: buildForm(),
      headers: buildHeaders(),
      expectedOrigin: "http://localhost",
      registrationHandle: HANDLE,
      csrfSessionToken: "csrf-token",
      monotonicClock: testMonotonicClock,
      now: NOW,
      fetcher: buildTurnstileFetcher(),
    };

    const first = registerWithInvite(input);
    await vi.advanceTimersByTimeAsync(250);
    await expect(first).resolves.toMatchObject({
      ok: true,
      userId: "user-victim-first",
    });
    const replay = registerWithInvite(input);
    await vi.advanceTimersByTimeAsync(250);
    const replayResult = await replay;

    expect(Date.now() - startedAt).toBe(500);
    expectGenericRegistrationFailure(replayResult);
    expect(tx.registrationSession.updateMany).toHaveBeenCalledTimes(2);
    expect(tx.registrationSession.updateMany).toHaveBeenNthCalledWith(2, {
      where: {
        handleHash: expectedHandleHash(),
        status: "PENDING",
        expiresAt: { gt: NOW },
        consumedAt: null,
      },
      data: { status: "CONSUMED", consumedAt: NOW },
    });
    const consumeCalls = tx.registrationSession.updateMany.mock.calls as unknown as Array<[
      { where: Record<string, unknown> },
    ]>;
    expect(consumeCalls[1]?.[0].where).not.toHaveProperty("id");
    expect(tx.user.create).toHaveBeenCalledTimes(1);
  });

  it("writes replay evidence only after the registration transaction rolls back", async () => {
    const { prisma, recordInviteReuseEvidence } = setupRegistrationMocks({
      redeemOk: false,
      reuseInviteId: "invite-reused",
    });
    const { registerWithInvite } = await import("@/features/auth/server/registration");
    const startedAt = Date.now();

    const pending = registerWithInvite({
      formData: buildForm(), headers: buildHeaders(), expectedOrigin: "http://localhost",
      registrationHandle: HANDLE, csrfSessionToken: "csrf-token", now: NOW,
      monotonicClock: testMonotonicClock,
      fetcher: buildTurnstileFetcher(),
    });
    await vi.advanceTimersByTimeAsync(250);
    await expect(pending).resolves.toMatchObject({ ok: false, status: 403 });

    expect(Date.now() - startedAt).toBe(250);
    expect(prisma.$transaction).toHaveBeenCalledTimes(2);
    expect(recordInviteReuseEvidence).toHaveBeenCalledWith("invite-reused");
    expect(prisma.$transaction.mock.invocationCallOrder[0]).toBeLessThan(
      recordInviteReuseEvidence.mock.invocationCallOrder[0] ?? 0,
    );
  });

  it("rejects a malformed session that omits normalizedEmail instead of treating it as unbound", async () => {
    const malformedSession = {
      id: "registration-session-1",
      handleHash: expectedHandleHash(),
      inviteTokenHash: TOKEN_HASH,
      inviteId: null,
      status: "PENDING",
      expiresAt: new Date(NOW.getTime() + 60_000),
      consumedAt: null,
    };
    const { prisma, tx, redeemInviteInTx } = setupRegistrationMocks({
      registrationSession: malformedSession as never,
    });
    const { registerWithInvite } = await import("@/features/auth/server/registration");

    const pending = registerWithInvite({
      formData: buildForm(), headers: buildHeaders(), expectedOrigin: "http://localhost",
      registrationHandle: HANDLE, csrfSessionToken: "csrf-token", now: NOW,
      monotonicClock: testMonotonicClock,
      fetcher: buildTurnstileFetcher(),
    });
    await vi.advanceTimersByTimeAsync(250);

    expectGenericRegistrationFailure(await pending);
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(tx.registrationSession.updateMany).not.toHaveBeenCalled();
    expect(tx.user.create).not.toHaveBeenCalled();
    expect(redeemInviteInTx).not.toHaveBeenCalled();
  });

  it("aborts a Turnstile dependency at the admission deadline and starts no mutation transaction", async () => {
    const { prisma, tx } = setupRegistrationMocks();
    let observedSignal: AbortSignal | undefined;
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      observedSignal = init?.signal ?? undefined;
      return new Promise<Response>(() => undefined);
    });
    const { registerWithInvite } = await import("@/features/auth/server/registration");

    const pending = registerWithInvite({
      formData: buildForm(), headers: buildHeaders(), expectedOrigin: "http://localhost",
      registrationHandle: HANDLE, csrfSessionToken: "csrf-token", now: NOW, fetcher,
      monotonicClock: testMonotonicClock,
    });
    await vi.advanceTimersByTimeAsync(250);

    expectGenericRegistrationFailure(await pending);
    expect(observedSignal?.aborted).toBe(true);
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(tx.registrationSession.updateMany).not.toHaveBeenCalled();
    expect(tx.user.create).not.toHaveBeenCalled();
  });

  it("times out bounded registration-session lookup before any mutation starts", async () => {
    const { prisma, tx } = setupRegistrationMocks({ sessionLookupDelayMs: 100 });
    const { registerWithInvite } = await import("@/features/auth/server/registration");

    const pending = registerWithInvite({
      formData: buildForm(), headers: buildHeaders(), expectedOrigin: "http://localhost",
      registrationHandle: HANDLE, csrfSessionToken: "csrf-token", now: NOW,
      monotonicClock: testMonotonicClock,
      fetcher: buildTurnstileFetcher(),
    });
    await vi.advanceTimersByTimeAsync(250);

    expectGenericRegistrationFailure(await pending);
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(tx.registrationSession.updateMany).not.toHaveBeenCalled();
    expect(tx.user.create).not.toHaveBeenCalled();
  });

  it("preserves a committed success when transaction completion overruns the parity target", async () => {
    const { tx } = setupRegistrationMocks({ transactionDelayMs: 300 });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { registerWithInvite } = await import("@/features/auth/server/registration");
    let settled = false;

    const pending = registerWithInvite({
      formData: buildForm(), headers: buildHeaders(), expectedOrigin: "http://localhost",
      registrationHandle: HANDLE, csrfSessionToken: "csrf-token", now: NOW,
      monotonicClock: testMonotonicClock,
      fetcher: buildTurnstileFetcher(),
    }).finally(() => { settled = true; });
    await vi.advanceTimersByTimeAsync(250);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(50);

    await expect(pending).resolves.toMatchObject({
      ok: true,
      email: "victim@example.com",
      userId: "user-victim",
    });
    expect(tx.outboxEmail.create).toHaveBeenCalledOnce();
    expect(errorSpy).toHaveBeenCalledWith(
      "security.registration_timing_parity_breach",
      { targetMs: 250, elapsedMs: 300 },
    );
  });

  it("maps transaction timeouts to the same result at the exact public target", async () => {
    setupRegistrationMocks({ transactionThrows: new Error("P2028 transaction timeout") });
    const { registerWithInvite } = await import("@/features/auth/server/registration");
    const startedAt = Date.now();

    const pending = registerWithInvite({
      formData: buildForm(), headers: buildHeaders(), expectedOrigin: "http://localhost",
      registrationHandle: HANDLE, csrfSessionToken: "csrf-token", now: NOW,
      monotonicClock: testMonotonicClock,
      fetcher: buildTurnstileFetcher(),
    });
    await vi.advanceTimersByTimeAsync(250);

    expectGenericRegistrationFailure(await pending);
    expect(Date.now() - startedAt).toBe(250);
  });

  it("[B3 CSRF] rejects before ref resolution or redemption when CSRF validation fails", async () => {
    const { prisma, tx, redeemInviteInTx } = setupRegistrationMocks();
    const { registerWithInvite } = await import("@/features/auth/server/registration");

    const pendingResult = registerWithInvite({
      formData: buildForm(),
      headers: buildHeaders(),
      expectedOrigin: "http://localhost",
      registrationHandle: HANDLE,
      csrfSessionToken: "different-session-token",
      monotonicClock: testMonotonicClock,
      now: NOW,
      fetcher: buildTurnstileFetcher(),
    });
    await vi.advanceTimersByTimeAsync(250);
    const result = await pendingResult;

    expectGenericRegistrationFailure(result);
    expect(tx.registrationSession.findUnique).not.toHaveBeenCalled();
    expect(prisma.$transaction).not.toHaveBeenCalled();
    expect(tx.user.create).not.toHaveBeenCalled();
    expect(redeemInviteInTx).not.toHaveBeenCalled();
  });

  it("rejects registration when the atomic admission set is exhausted", async () => {
    const rateLimitAll = vi.fn(async () => ({ success: false }));
    vi.doMock("@/lib/rateLimit", async () => {
      const actual = await vi.importActual<typeof import("@/lib/rateLimit")>("@/lib/rateLimit");
      return { ...actual, rateLimitAll };
    });
    const { tx } = setupRegistrationMocks();
    const { registerWithInvite } = await import("@/features/auth/server/registration");

    const pending = registerWithInvite({
      formData: buildForm(),
      headers: buildHeaders(),
      expectedOrigin: "http://localhost",
      registrationHandle: HANDLE,
      csrfSessionToken: "csrf-token",
      monotonicClock: testMonotonicClock,
      now: NOW,
      fetcher: buildTurnstileFetcher(),
    });
    await vi.advanceTimersByTimeAsync(250);
    expectGenericRegistrationFailure(await pending);
    expect(rateLimitAll).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ policy: "registration-ip" }),
        expect.objectContaining({ policy: "registration-account" }),
        expect.objectContaining({ policy: "registration-invite" }),
      ]),
      expect.any(AbortSignal),
    );
    expect(tx.registrationSession.updateMany).not.toHaveBeenCalled();
    expect(tx.user.create).not.toHaveBeenCalled();
  });

  it("maps duplicate email races to the same generic admission result without leaking P2002", async () => {
    setupRegistrationMocks({ createThrows: Object.assign(new Error("duplicate"), { code: "P2002" }) });
    const { registerWithInvite } = await import("@/features/auth/server/registration");

    const pendingResult = registerWithInvite({
      formData: buildForm(),
      headers: buildHeaders(),
      expectedOrigin: "http://localhost",
      registrationHandle: HANDLE,
      csrfSessionToken: "csrf-token",
      monotonicClock: testMonotonicClock,
      now: NOW,
      fetcher: buildTurnstileFetcher(),
    });
    await vi.advanceTimersByTimeAsync(250);
    const result = await pendingResult;

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(403);
      expect(result.body.message).toBe("Unable to complete this request.");
    }
  });
});

describe("OTP activation", () => {
  it("rejects a superseded OTP and lets only its replacement activate once", async () => {
    const { createHmac } = await import("node:crypto");
    const secret = process.env.OTP_HMAC_SECRET ?? process.env.NEXTAUTH_SECRET ?? "";
    const digest = (code: string) => createHmac("sha256", secret).update(code, "utf8").digest("hex");
    const newestToken = { identifier: "victim@example.com", token: digest("222222"), expires: new Date(NOW.getTime() + 60_000) };
    let active = false;
    let consumed = false;
    const tx = {
      verificationToken: {
        findFirst: vi.fn(async ({ where }: { where: { token: string } }) =>
          !consumed && where.token === newestToken.token ? newestToken : null),
        deleteMany: vi.fn(async () => { consumed = true; return { count: 1 }; }),
      },
      user: {
        findUnique: vi.fn(async () => ({ id: "user-victim", emailVerified: active ? NOW : null, status: active ? "ACTIVE" : "INACTIVE" })),
        updateMany: vi.fn(async () => { active = true; return { count: 1 }; }),
      },
    };
    const prisma = {
      $transaction: vi.fn(async (callback: (transaction: typeof tx) => Promise<unknown>) => callback(tx)),
      verificationToken: {
        findFirst: vi.fn(async () => (!consumed ? newestToken : null)),
        update: vi.fn(async () => ({ attempts: 1 })),
        deleteMany: vi.fn(),
      },
    };
    vi.doMock("@/lib/prisma", () => ({ prisma }));
    vi.doMock("bcryptjs", () => ({ hash: vi.fn(async () => "replacement-password-hash") }));
    const { consumeVerificationToken } = await import("@/features/auth/server/verify/consumeToken");

    await expect(consumeVerificationToken("victim@example.com", "111111", "ReplacementP@ss123"))
      .resolves.toEqual({ ok: false, reason: "invalid-code" });
    expect(active).toBe(false);
    await expect(consumeVerificationToken("victim@example.com", "222222", "ReplacementP@ss123"))
      .resolves.toEqual({ ok: true });
    await expect(consumeVerificationToken("victim@example.com", "222222", "ReplacementP@ss123"))
      .resolves.toEqual({ ok: false, reason: "not-found" });
    expect(tx.user.updateMany).toHaveBeenCalledTimes(1);
  });

  it("[R3-1 pre-hijack] ignores attacker registration password and lets only the OTP holder activate with their password", async () => {
    const { tx } = (() => {
      const setup = {
        tx: {
          user: {
            findUnique: vi.fn(async () => ({
              id: "user-victim",
              emailVerified: null,
              status: "INACTIVE",
            })),
            updateMany: vi.fn(async () => ({ count: 1 })),
          },
          verificationToken: {
            findFirst: vi.fn(async () => ({
              identifier: "victim@example.com",
              token: "hmac:123456",
              expires: new Date(NOW.getTime() + 60_000),
            })),
            deleteMany: vi.fn(async () => ({ count: 1 })),
          },
        },
      };
      const prisma = {
        verificationToken: {
          findFirst: vi.fn(async () => ({ token: "hmac:123456" })),
        },
        $transaction: vi.fn(async (callback: (transaction: typeof setup.tx) => Promise<unknown>) =>
          callback(setup.tx)
        ),
      };
      vi.doMock("@/lib/prisma", () => ({ prisma }));
      vi.doMock("bcryptjs", () => ({ hash: vi.fn(async () => "hash:victim-password") }));
      return setup;
    })();

    const { consumeVerificationToken } = await import("@/features/auth/server/verify/consumeToken");
    const result = await consumeVerificationToken("victim@example.com", "123456", "VictimP@ss123");

    expect(result).toEqual({ ok: true });
    expect(tx.user.updateMany).toHaveBeenCalledWith({
      where: {
        id: "user-victim",
        status: "INACTIVE",
        emailVerified: null,
      },
      data: {
        passwordHash: "hash:victim-password",
        password: null,
        hasPasswordCredential: true,
        emailVerified: NOW,
        status: "ACTIVE",
        sessionVersion: { increment: 1 },
      },
    });
  });

  it("[R3-1 wrong-OTP] does not set a password or activate when the OTP does not match", async () => {
    const update = vi.fn();
    vi.doMock("@/lib/prisma", () => ({
      prisma: {
        verificationToken: {
          findFirst: vi
            .fn()
            .mockResolvedValueOnce({ token: "hmac:active", expires: new Date(NOW.getTime() + 60_000) }),
          update: vi.fn(async () => ({ attempts: 1 })),
          deleteMany: vi.fn(),
        },
        user: { update },
        $transaction: vi.fn(async () => null),
      },
    }));

    const { consumeVerificationToken } = await import("@/features/auth/server/verify/consumeToken");
    const result = await consumeVerificationToken("victim@example.com", "000000", "VictimP@ss123");

    expect(result).toEqual({ ok: false, reason: "invalid-code" });
    expect(update).not.toHaveBeenCalled();
  });

  it("[W2] consumes the matched OTP and activates the user inside one transaction-scoped compare-and-set", async () => {
    const hash = vi.fn(async () => "hash:victim-password");
    const tx = {
      verificationToken: {
        findFirst: vi.fn(async () => ({
          identifier: "victim@example.com",
          token: "hmac:123456",
          expires: new Date(NOW.getTime() + 60_000),
        })),
        deleteMany: vi.fn(async () => ({ count: 1 })),
      },
      user: {
        findUnique: vi.fn(async () => ({
          id: "user-victim",
          emailVerified: null,
          status: "INACTIVE",
        })),
        updateMany: vi.fn(async () => ({ count: 1 })),
      },
    };
    const prisma = {
      verificationToken: {
        findFirst: vi.fn(),
        update: vi.fn(),
        deleteMany: vi.fn(),
      },
      user: {
        findUnique: vi.fn(),
        update: vi.fn(),
        updateMany: vi.fn(),
      },
      $transaction: vi.fn(async (callback: (transaction: typeof tx) => Promise<unknown>) => {
        expect(hash).toHaveBeenCalledWith("VictimP@ss123", 10);
        return callback(tx);
      }),
    };
    vi.doMock("@/lib/prisma", () => ({ prisma }));
    vi.doMock("bcryptjs", () => ({ hash }));

    const { consumeVerificationToken } = await import("@/features/auth/server/verify/consumeToken");
    const result = await consumeVerificationToken("victim@example.com", "123456", "VictimP@ss123");

    expect(result).toEqual({ ok: true });
    expect(prisma.verificationToken.findFirst).not.toHaveBeenCalled();
    expect(prisma.user.findUnique).not.toHaveBeenCalled();
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    const tokenLookupCalls = tx.verificationToken.findFirst.mock.calls as unknown as Array<[
      { where: { token: string } },
    ]>;
    const matchedDigest = tokenLookupCalls[0]?.[0].where.token;
    expect(matchedDigest).toEqual(expect.stringMatching(/^[0-9a-f]{64}$/));
    expect(tx.verificationToken.findFirst).toHaveBeenCalledWith({
      where: { identifier: "victim@example.com", token: matchedDigest },
    });
    expect(tx.verificationToken.deleteMany).toHaveBeenCalledWith({
      where: {
        identifier: "victim@example.com",
        token: matchedDigest,
        expires: { gt: NOW },
      },
    });
    expect(tx.user.updateMany).toHaveBeenCalledWith({
      where: {
        id: "user-victim",
        status: "INACTIVE",
        emailVerified: null,
      },
      data: {
        passwordHash: "hash:victim-password",
        password: null,
        hasPasswordCredential: true,
        emailVerified: NOW,
        status: "ACTIVE",
        sessionVersion: { increment: 1 },
      },
    });
    expect(prisma.user.update).not.toHaveBeenCalled();
  });
});

describe("non-ACTIVE denial across session and OAuth/OIDC boundaries", () => {
  async function importAuthOptionsForUser(user: { status: string; sessionVersion: number } | null) {
    vi.doMock("@auth/prisma-adapter", () => ({ PrismaAdapter: vi.fn(() => ({})) }));
    vi.doMock("@/lib/prisma", () => ({
      prisma: {
        user: {
          findUnique: vi.fn(async () => user),
        },
        account: { findUnique: vi.fn() },
        auditEvent: { create: vi.fn() },
      },
    }));

    const { authOptions } = await import("@/features/auth/server/options");
    return authOptions;
  }

  it("[B4] rejects non-ACTIVE users at JWT/session, OAuth authorization, token claims, and UserInfo", async () => {
    const authOptions = await importAuthOptionsForUser({ status: "SUSPENDED", sessionVersion: 0 });
    const jwt = authOptions.callbacks?.jwt;
    const session = authOptions.callbacks?.session;
    if (!jwt || !session) throw new Error("auth callbacks missing");

    const rejectedToken = await jwt({
      token: { uid: "user-suspended", sessionVersion: 0 },
      user: undefined as never,
      account: null,
      profile: undefined,
      trigger: "update",
      session: undefined,
    });
    expect(rejectedToken).toMatchObject({ authRejected: true });
    expect(rejectedToken.uid).toBeUndefined();

    const rejectedSession = await session({
      session: { user: { id: "user-suspended", name: "Suspended", email: "suspended@example.com" }, expires: "" },
      token: rejectedToken,
      user: undefined as never,
      newSession: undefined,
      trigger: "update",
    });
    expect(rejectedSession.user?.id).toBe("");
    expect(rejectedSession.user?.role).toBeUndefined();

    vi.resetModules();
    vi.doMock("@/lib/prisma", () => ({
      prisma: {
        user: { findUnique: vi.fn(async () => ({ status: "INACTIVE" })) },
        oAuthAuthorizationCode: { create: vi.fn() },
      },
    }));
    const { createAuthorizationCode } = await import("@/features/auth/server/oauth/authorization");
    await expect(
      createAuthorizationCode({
        clientId: "client-1",
        userId: "user-inactive",
        redirectUri: "https://app.example.com/callback",
        scopes: ["openid"],
        codeChallenge: "challenge",
        codeChallengeMethod: "S256",
      })
    ).rejects.toThrow("OAUTH_USER_NOT_ACTIVE");

    vi.resetModules();
    const signAccessToken = vi.fn(() => "signed-token");
    vi.doMock("@/features/auth/server/oauth/clientRegistry", () => ({
      getOAuthClient: vi.fn(async () => ({
        clientId: "client-1",
        clientSecretHash: "hash",
        isActive: true,
      })),
      verifyClientSecret: vi.fn(() => true),
    }));
    vi.doMock("@/features/auth/server/oauth/pkce", () => ({
      isValidPkceValue: vi.fn(() => true),
      pkceChallengeMatches: vi.fn(() => true),
    }));
    vi.doMock("@/features/auth/server/oauth/jwt", () => ({
      signAccessToken,
    }));
    vi.doMock("@/lib/prisma", () => ({
      prisma: {
        oAuthAuthorizationCode: {
          findUnique: vi.fn(async () => ({
            id: "code-1",
            code: "code",
            clientId: "client-1",
            redirectUri: "https://app.example.com/callback",
            expiresAt: new Date(NOW.getTime() + 60_000),
            usedAt: null,
            codeChallenge: "challenge",
            codeChallengeMethod: "S256",
            scopes: ["openid", "email"],
            userId: "user-inactive",
            nonce: null,
          })),
          updateMany: vi.fn(async () => ({ count: 1 })),
        },
        user: {
          findUnique: vi.fn(async () => ({
            id: "user-inactive",
            email: "inactive@example.com",
            emailVerified: null,
            name: null,
            image: null,
            status: "INACTIVE",
          })),
        },
      },
    }));
    const { exchangeAuthorizationCode } = await import("@/features/auth/server/oauth/token");
    await expect(
      exchangeAuthorizationCode({
        code: "code",
        clientId: "client-1",
        clientSecret: "secret",
        redirectUri: "https://app.example.com/callback",
        codeVerifier: "valid-verifier",
      })
    ).resolves.toMatchObject({
      ok: false,
      status: 400,
      error: "invalid_grant",
    });
    expect(signAccessToken).not.toHaveBeenCalled();

    vi.resetModules();
    vi.doMock("@/features/auth/server/oauth/jwt", () => ({
      verifyAccessToken: vi.fn(() => ({ sub: "user-inactive", scope: "openid email" })),
    }));
    vi.doMock("@/lib/rateLimit", () => ({
      getClientIp: vi.fn(() => "127.0.0.1"),
      rateLimit: vi.fn(async () => ({ success: true, limit: 10, remaining: 9, reset: Date.now() })),
    }));
    vi.doMock("@/lib/prisma", () => ({
      prisma: {
        user: {
          findUnique: vi.fn(async () => ({
            id: "user-inactive",
            email: "inactive@example.com",
            emailVerified: null,
            name: null,
            image: null,
            status: "INACTIVE",
          })),
        },
      },
    }));
    const { GET } = await import("@/app/oauth/userinfo/route");
    const response = await GET(
      new Request("http://localhost/oauth/userinfo", {
        headers: { authorization: "Bearer inactive-user-token" },
      })
    );
    await expect(response.json()).resolves.toEqual({ error: "invalid_token" });
    expect(response.status).toBe(401);
  });

  it("[B4 token-claims] rejects an already-issued token when the subject is now INACTIVE", async () => {
    const findUnique = vi.fn(async () => ({
      id: "user-now-inactive",
      email: "inactive@example.com",
      emailVerified: NOW,
      name: "Inactive User",
      image: null,
      status: "INACTIVE",
    }));
    vi.doMock("@/lib/prisma", () => ({
      prisma: {
        user: { findUnique },
      },
    }));

    const { getUserClaims } = await import("@/features/auth/server/oauth/claims");
    const claims = await getUserClaims("user-now-inactive", ["openid", "email", "profile"]);

    expect(claims).toBeNull();
    expect(findUnique).toHaveBeenCalledWith({
      where: { id: "user-now-inactive" },
      select: {
        id: true,
        email: true,
        emailVerified: true,
        name: true,
        image: true,
        status: true,
      },
    });
  });

  it("[B5] accepts a legacy version-0 JWT while the user remains v0, then rejects after sessionVersion increments", async () => {
    const findUnique = vi
      .fn()
      .mockResolvedValueOnce({ status: "ACTIVE", sessionVersion: 0 })
      .mockResolvedValueOnce({ status: "ACTIVE", sessionVersion: 1 });
    vi.doMock("@auth/prisma-adapter", () => ({ PrismaAdapter: vi.fn(() => ({})) }));
    vi.doMock("@/lib/prisma", () => ({
      prisma: {
        user: { findUnique },
        account: { findUnique: vi.fn() },
        auditEvent: { create: vi.fn() },
      },
    }));

    const { authOptions } = await import("@/features/auth/server/options");
    const jwt = authOptions.callbacks?.jwt;
    if (!jwt) throw new Error("jwt callback missing");

    const legacyToken = await jwt({
      token: { uid: "user-active-v0", email: "user@example.com" },
      user: undefined as never,
      account: null,
      profile: undefined,
      trigger: "update",
      session: undefined,
    });
    expect(legacyToken).toMatchObject({
      uid: "user-active-v0",
      authRejected: false,
      sessionVersion: 0,
    });

    const invalidatedToken = await jwt({
      token: { uid: "user-active-v0", email: "user@example.com" },
      user: undefined as never,
      account: null,
      profile: undefined,
      trigger: "update",
      session: undefined,
    });
    expect(invalidatedToken).toMatchObject({ authRejected: true });
    expect(invalidatedToken.uid).toBeUndefined();
  });
});

describe("credentials authorize limiter and enumeration parity", () => {
  async function importCredentialsAuthorize(options: {
    user: unknown;
    compareResult: boolean;
    rateResults?: Array<{ success: boolean; limit: number; remaining: number; reset: number }>;
  }) {
    vi.doMock("@auth/prisma-adapter", () => ({ PrismaAdapter: vi.fn(() => ({})) }));
    const rateLimit = vi.fn(async () =>
      options.rateResults?.shift() ?? { success: true, limit: 10, remaining: 9, reset: Date.now() }
    );
    vi.doMock("@/lib/rateLimit", async () => {
      const actual = await vi.importActual<typeof import("@/lib/rateLimit")>("@/lib/rateLimit");
      return { ...actual, getClientIp: vi.fn(() => "127.0.0.1"), rateLimit };
    });
    vi.doMock("@/lib/prisma", () => ({
      prisma: {
        user: {
          findUnique: vi.fn(async () => options.user),
        },
        account: { findUnique: vi.fn() },
        auditEvent: { create: vi.fn() },
      },
    }));
    vi.doMock("bcryptjs", () => ({ compare: vi.fn(async () => options.compareResult) }));

    const { authOptions } = await import("@/features/auth/server/options");
    const credentialsProvider = authOptions.providers.find((provider) => provider.id === "credentials");
    if (!credentialsProvider || !("options" in credentialsProvider)) {
      throw new Error("credentials provider missing");
    }
    const authorize = credentialsProvider.options.authorize;
    if (typeof authorize !== "function") throw new Error("authorize missing");
    return { authorize, rateLimit };
  }

  it("uses independent per-IP and per-account login limiter dimensions", async () => {
    const { authorize, rateLimit } = await importCredentialsAuthorize({
      user: null,
      compareResult: false,
    });

    const pendingResult = authorize(
      { email: "unknown@example.com", password: "Password1!" },
      { headers: {} }
    );
    await vi.advanceTimersByTimeAsync(250);
    await pendingResult;

    expect(rateLimit).toHaveBeenCalledTimes(2);
    expect(rateLimit).toHaveBeenNthCalledWith(
      1,
      expect.stringContaining("login:ip:"),
      "login-ip"
    );
    expect(rateLimit).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining("login:account:"),
      "login-account"
    );
  });

  it("does not consume the account bucket when the IP bucket is exhausted", async () => {
    const { authorize, rateLimit } = await importCredentialsAuthorize({
      user: null,
      compareResult: false,
      rateResults: [{ success: false, limit: 10, remaining: 0, reset: Date.now() }],
    });

    await expect(
      authorize({ email: "user@example.com", password: "Password1!" }, { headers: {} })
    ).rejects.toThrow("RATE_LIMITED");
    expect(rateLimit).toHaveBeenCalledTimes(1);
  });

  it.each([
    { label: "absent account", user: null, compareResult: false },
    {
      label: "wrong password",
      user: {
        id: "user-1",
        email: "user@example.com",
        name: null,
        role: "USER",
        passwordHash: "hash",
        hasPasswordCredential: true,
        emailVerified: NOW,
        origin: "FIRST_PARTY",
        status: "ACTIVE",
        sessionVersion: 1,
      },
      compareResult: false,
    },
    {
      label: "inactive account",
      user: {
        id: "user-1",
        email: "user@example.com",
        name: null,
        role: "USER",
        passwordHash: "hash",
        hasPasswordCredential: true,
        emailVerified: null,
        origin: "FIRST_PARTY",
        status: "INACTIVE",
        sessionVersion: 1,
      },
      compareResult: true,
    },
    {
      label: "suspended account",
      user: {
        id: "user-2", email: "user@example.com", name: null, role: "USER",
        passwordHash: "hash", hasPasswordCredential: true, emailVerified: NOW,
        origin: "FIRST_PARTY", status: "SUSPENDED", sessionVersion: 1,
      },
      compareResult: true,
    },
    {
      label: "deleted account",
      user: {
        id: "user-3", email: "user@example.com", name: null, role: "USER",
        passwordHash: "hash", hasPasswordCredential: true, emailVerified: NOW,
        origin: "FIRST_PARTY", status: "DELETED", sessionVersion: 1,
      },
      compareResult: true,
    },
    {
      label: "email-mismatch equivalent wrong password",
      user: {
        id: "user-4", email: "user@example.com", name: null, role: "USER",
        passwordHash: "hash", hasPasswordCredential: true, emailVerified: NOW,
        origin: "FIRST_PARTY", status: "ACTIVE", sessionVersion: 1,
      },
      compareResult: false,
    },
    { label: "malformed credentials", user: null, compareResult: false, credentials: { email: "bad", password: "x" } },
  ])("returns the same generic null result for $label", async ({ user, compareResult, credentials }) => {
    const { authorize } = await importCredentialsAuthorize({ user, compareResult });

    let settled = false;
    const pendingResult = authorize(
      credentials ?? { email: "user@example.com", password: "Password1!" },
      { headers: {} }
    ).finally(() => { settled = true; });
    await vi.advanceTimersByTimeAsync(249);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await expect(pendingResult).resolves.toBeNull();
  });
});
