// Verifies TASK-026 admin invite authorization, atomicity, redaction, and replay safety.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { readFile } from "node:fs/promises";

const NOW = new Date("2026-07-12T12:00:00.000Z");
const elevationDelegates = () => ({
  user: { findUnique: vi.fn(), update: vi.fn() },
  adminMfaFactor: { findFirst: vi.fn(), findUnique: vi.fn(), create: vi.fn(), update: vi.fn(), updateMany: vi.fn() },
  adminCapabilityGrant: { findFirst: vi.fn(), createMany: vi.fn() },
});

describe("admin invite service", () => {
  beforeEach(() => vi.resetModules());

  it("denies before mutation when elevation is absent and keeps only a durable denial audit", async () => {
    const tx = { invite: { create: vi.fn(), findFirst: vi.fn(), findMany: vi.fn(), updateMany: vi.fn() }, outboxEmail: { create: vi.fn() }, auditEvent: { create: vi.fn() }, ...elevationDelegates() };
    const mutation = vi.fn(async (callback) => callback(tx));
    const { createAdminInviteService } = await import("@/features/auth/server/adminInvites/adminInviteService");
    const service = createAdminInviteService({
      transaction: mutation,
      authorize: vi.fn().mockRejectedValue(new Error("FORBIDDEN")),
      encryptToken: vi.fn(),
      deliveryKey: { keyHex: "a".repeat(64), version: 1 },
      now: () => NOW,
    });

    await expect(service.issue({ session: null, email: "person@example.com", reason: "Support request", requestId: "req-1" }))
      .rejects.toThrow("FORBIDDEN");
    expect(mutation).toHaveBeenCalledOnce();
    expect(tx.invite.create).not.toHaveBeenCalled();
    expect(tx.outboxEmail.create).not.toHaveBeenCalled();
    expect(tx.auditEvent.create).not.toHaveBeenCalled();
  });

  it("issues an email-bound invite, encrypted outbox row, and one redacted audit atomically", async () => {
    const writes: Array<{ kind: string; data: unknown }> = [];
    const tx = {
      invite: {
        findFirst: vi.fn().mockResolvedValue(null),
        create: vi.fn().mockImplementation(({ data }: { data: unknown }) => {
          writes.push({ kind: "invite", data });
          return { id: "invite-new", normalizedEmail: "person@example.com", expiresAt: new Date("2026-07-19T12:00:00Z") };
        }),
        updateMany: vi.fn(),
        findMany: vi.fn(),
      },
      outboxEmail: { create: vi.fn().mockImplementation(({ data }: { data: unknown }) => { writes.push({ kind: "outbox", data }); return { id: "outbox-1" }; }) },
      auditEvent: { create: vi.fn().mockImplementation(({ data }: { data: unknown }) => { writes.push({ kind: "audit", data }); return { id: "audit-1" }; }) },
      ...elevationDelegates(),
    };
    const { createAdminInviteService } = await import("@/features/auth/server/adminInvites/adminInviteService");
    const service = createAdminInviteService({
      transaction: async (callback) => callback(tx),
      authorize: vi.fn().mockResolvedValue({ actorId: "admin-1", capability: "admin:invite:issue", grantedAt: NOW }),
      encryptToken: vi.fn().mockReturnValue(new Uint8Array([7, 8, 9])),
      deliveryKey: { keyHex: "a".repeat(64), version: 1 }, now: () => NOW,
    });

    await expect(service.issue({ session: { userId: "admin-1", role: "ADMIN", sessionVersion: 4 }, email: "Person@Example.com", reason: "Customer onboarding", requestId: "req-2" }))
      .resolves.toEqual({ ok: true, inviteId: "invite-new" });
    expect(writes.map((write) => write.kind)).toEqual(["invite", "outbox", "audit"]);
    const serialized = JSON.stringify(writes);
    expect(serialized).not.toContain("Person@Example.com");
    expect(serialized).toContain("invite-new");
    expect(serialized).not.toContain("Customer onboarding");
    expect(serialized).toContain("reasonDigest");
    expect(JSON.stringify(tx.auditEvent.create.mock.calls)).not.toContain("person@example.com");
    expect(JSON.stringify(tx.auditEvent.create.mock.calls)).not.toContain("token");
  });

  it("revoke is idempotent for a redeemed invite and records a single no-op audit", async () => {
    const tx = {
      invite: { updateMany: vi.fn().mockResolvedValue({ count: 0 }), findFirst: vi.fn().mockResolvedValue({ id: "invite-redeemed", status: "REDEEMED" }), findMany: vi.fn(), create: vi.fn() },
      outboxEmail: { create: vi.fn() },
      auditEvent: { create: vi.fn().mockResolvedValue({ id: "audit-noop" }) },
      ...elevationDelegates(),
    };
    const { createAdminInviteService } = await import("@/features/auth/server/adminInvites/adminInviteService");
    const service = createAdminInviteService({
      transaction: async (callback) => callback(tx), authorize: vi.fn().mockResolvedValue({ actorId: "admin-1" }),
      encryptToken: vi.fn(), deliveryKey: { keyHex: "a".repeat(64), version: 1 }, now: () => NOW,
    });
    await expect(service.revoke({ session: { userId: "admin-1", role: "ADMIN", sessionVersion: 4 }, inviteId: "invite-redeemed", reason: "No longer needed", requestId: "req-3" }))
      .resolves.toEqual({ ok: true });
    expect(tx.auditEvent.create).toHaveBeenCalledOnce();
    expect(JSON.stringify(tx.auditEvent.create.mock.calls)).toContain("NO_OP");
  });

  it("resend atomically revokes the old invite and rotates to a new invite/outbox record", async () => {
    const tx = {
      invite: {
        updateMany: vi.fn().mockResolvedValue({ count: 1 }),
        findFirst: vi.fn().mockResolvedValue({ id: "old", status: "ISSUED", normalizedEmail: "person@example.com" }),
        create: vi.fn().mockResolvedValue({ id: "new", normalizedEmail: "person@example.com", expiresAt: new Date("2026-07-19T12:00:00Z") }), findMany: vi.fn(),
      },
      outboxEmail: { create: vi.fn().mockResolvedValue({ id: "outbox-new" }) },
      auditEvent: { create: vi.fn().mockResolvedValue({ id: "audit-resend" }) },
      ...elevationDelegates(),
    };
    const { createAdminInviteService } = await import("@/features/auth/server/adminInvites/adminInviteService");
    const service = createAdminInviteService({
      transaction: async (callback) => callback(tx), authorize: vi.fn().mockResolvedValue({ actorId: "admin-1" }),
      encryptToken: vi.fn().mockReturnValue(new Uint8Array([1])), deliveryKey: { keyHex: "a".repeat(64), version: 1 }, now: () => NOW,
    });
    await expect(service.resend({ session: { userId: "admin-1", role: "ADMIN", sessionVersion: 4 }, inviteId: "old", reason: "Delivery retry", requestId: "req-4" }))
      .resolves.toEqual({ ok: true, inviteId: "new" });
    expect(tx.invite.updateMany).toHaveBeenCalledWith(expect.objectContaining({ where: expect.objectContaining({ id: "old", status: "ISSUED" }) }));
    expect(tx.invite.create).toHaveBeenCalledOnce();
    expect(tx.outboxEmail.create).toHaveBeenCalledOnce();
    expect(tx.auditEvent.create).toHaveBeenCalledOnce();
  });

  it.each([
    { email: "", reason: "Support request" },
    { email: "not-an-email", reason: "Support request" },
    { email: "person@example.com", reason: "   " },
  ])("rejects invalid bound-email/reason input at the service boundary: $email/$reason", async (invalid) => {
    const transaction = vi.fn();
    const { createAdminInviteService } = await import("@/features/auth/server/adminInvites/adminInviteService");
    const service = createAdminInviteService({ transaction, authorize: vi.fn(), encryptToken: vi.fn(), deliveryKey: { keyHex: "a".repeat(64), version: 1 }, now: () => NOW });
    await expect(service.issue({ session: null, email: invalid.email, reason: invalid.reason, requestId: "req-invalid" }))
      .rejects.toThrow("ADMIN_INVITE_INVALID_INPUT");
    expect(transaction).not.toHaveBeenCalled();
  });

  it("returns an existing active invite without token/outbox duplication", async () => {
    const tx = {
      invite: { findFirst: vi.fn().mockResolvedValue({ id: "existing", status: "ISSUED" }), create: vi.fn(), findMany: vi.fn(), updateMany: vi.fn() },
      outboxEmail: { create: vi.fn() }, auditEvent: { create: vi.fn().mockResolvedValue({ id: "audit" }) }, ...elevationDelegates(),
    };
    const { createAdminInviteService } = await import("@/features/auth/server/adminInvites/adminInviteService");
    const service = createAdminInviteService({ transaction: async (callback) => callback(tx), authorize: vi.fn().mockResolvedValue({ actorId: "admin-1" }), encryptToken: vi.fn(), deliveryKey: { keyHex: "a".repeat(64), version: 1 }, now: () => NOW });
    await expect(service.issue({ session: { userId: "admin-1", role: "ADMIN", sessionVersion: 1 }, email: "person@example.com", reason: "Support", requestId: "req-duplicate" }))
      .resolves.toEqual({ ok: true, inviteId: "existing" });
    expect(tx.invite.create).not.toHaveBeenCalled();
    expect(tx.outboxEmail.create).not.toHaveBeenCalled();
    expect(JSON.stringify(tx.auditEvent.create.mock.calls)).toContain("NO_OP");
  });

  it.each(["revoke", "resend"] as const)("treats a %s compare-and-set race loser as a no-op", async (operation) => {
    const tx = {
      invite: { findFirst: vi.fn().mockResolvedValue({ id: "old", status: "ISSUED", normalizedEmail: "person@example.com" }), create: vi.fn(), findMany: vi.fn(), updateMany: vi.fn().mockResolvedValue({ count: 0 }) },
      outboxEmail: { create: vi.fn() }, auditEvent: { create: vi.fn().mockResolvedValue({ id: "audit" }) }, ...elevationDelegates(),
    };
    const { createAdminInviteService } = await import("@/features/auth/server/adminInvites/adminInviteService");
    const service = createAdminInviteService({ transaction: async (callback) => callback(tx), authorize: vi.fn().mockResolvedValue({ actorId: "admin-1" }), encryptToken: vi.fn(), deliveryKey: { keyHex: "a".repeat(64), version: 1 }, now: () => NOW });
    const input = { session: { userId: "admin-1", role: "ADMIN" as const, sessionVersion: 1 }, inviteId: "old", reason: "Support", requestId: "req-race" };
    await service[operation](input);
    expect(tx.invite.create).not.toHaveBeenCalled();
    expect(tx.outboxEmail.create).not.toHaveBeenCalled();
    expect(JSON.stringify(tx.auditEvent.create.mock.calls)).toContain("NO_OP");
  });

  it("rolls back invite and outbox when the SUCCESS audit write fails", async () => {
    const committed: string[] = [];
    const staged: string[] = [];
    const tx = {
      invite: { findFirst: vi.fn().mockResolvedValue(null), findMany: vi.fn(), updateMany: vi.fn(), create: vi.fn().mockImplementation(async () => { staged.push("invite"); return { id: "new", normalizedEmail: "person@example.com", expiresAt: NOW }; }) },
      outboxEmail: { create: vi.fn().mockImplementation(async () => { staged.push("outbox"); return { id: "outbox" }; }) },
      auditEvent: { create: vi.fn().mockRejectedValue(new Error("AUDIT_WRITE_FAILED")) }, ...elevationDelegates(),
    };
    async function transaction<T>(callback: (client: typeof tx) => Promise<T>): Promise<T> {
      try { const result = await callback(tx); committed.push(...staged); return result; }
      catch (error: unknown) { staged.length = 0; throw error; }
    }
    const { createAdminInviteService } = await import("@/features/auth/server/adminInvites/adminInviteService");
    const service = createAdminInviteService({ transaction, authorize: vi.fn().mockResolvedValue({ actorId: "admin-1" }), encryptToken: vi.fn().mockReturnValue(new Uint8Array([1])), deliveryKey: { keyHex: "a".repeat(64), version: 1 }, now: () => NOW });
    await expect(service.issue({ session: { userId: "admin-1", role: "ADMIN", sessionVersion: 1 }, email: "person@example.com", reason: "Support", requestId: "req-rollback" }))
      .rejects.toThrow("AUDIT_WRITE_FAILED");
    expect(committed).toEqual([]);
  });

  it("passes the raw token only to encryption and excludes it from response, audit, logs, and outbox metadata", async () => {
    let rawToken = "";
    const encryptToken = vi.fn((token: string) => { rawToken = token; return new Uint8Array([4, 5]); });
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const tx = {
      invite: { findFirst: vi.fn().mockResolvedValue(null), findMany: vi.fn(), updateMany: vi.fn(), create: vi.fn().mockResolvedValue({ id: "new", normalizedEmail: "person@example.com", expiresAt: NOW }) },
      outboxEmail: { create: vi.fn().mockResolvedValue({ id: "outbox" }) }, auditEvent: { create: vi.fn().mockResolvedValue({ id: "audit" }) }, ...elevationDelegates(),
    };
    const { createAdminInviteService } = await import("@/features/auth/server/adminInvites/adminInviteService");
    const service = createAdminInviteService({ transaction: async (callback) => callback(tx), authorize: vi.fn().mockResolvedValue({ actorId: "admin-1" }), encryptToken, deliveryKey: { keyHex: "a".repeat(64), version: 1 }, now: () => NOW });
    const result = await service.issue({ session: { userId: "admin-1", role: "ADMIN", sessionVersion: 1 }, email: "person@example.com", reason: "Support", requestId: "req-leak" });
    expect(rawToken).toHaveLength(43);
    expect(JSON.stringify(result)).not.toContain(rawToken);
    expect(JSON.stringify(tx.invite.create.mock.calls)).not.toContain(rawToken);
    expect(JSON.stringify(tx.auditEvent.create.mock.calls)).not.toContain(rawToken);
    expect(JSON.stringify(tx.outboxEmail.create.mock.calls)).not.toContain(rawToken);
    expect(JSON.stringify(log.mock.calls)).not.toContain(rawToken);
    log.mockRestore();
  });

  it("retains the database append-only trigger that rejects audit UPDATE and DELETE", async () => {
    const migration = await readFile("prisma/migrations/20260620173500_gated_registration_foundation/migration.sql", "utf8");
    expect(migration).toContain("raise_audit_event_immutable");
    expect(migration).toMatch(/BEFORE UPDATE OR DELETE ON "public"\."audit_events"/u);
  });

  it("consumes TASK-017 issuance and revocation primitives", async () => {
    const source = await readFile("src/features/auth/server/adminInvites/adminInviteService.ts", "utf8");
    expect(source).toContain("createInviteInTx");
    expect(source).toContain("revokeInviteInTx");
    expect(source).not.toContain("randomBytes");
    expect(source).not.toMatch(/createHash\("sha256"\)\.update\(rawToken/u);
    expect(source).not.toMatch(/tx\.invite\.updateMany/u);
  });

  it("keeps durable TASK-025 denial audit while the TASK-026 mutation writes nothing", async () => {
    vi.resetModules();
    const durableAudit = vi.fn().mockResolvedValue({ id: "denial" });
    const durableTransaction = vi.fn(async (callback) => callback({ auditEvent: { create: durableAudit } }));
    vi.doMock("@/lib/prisma", () => ({ prisma: { $transaction: durableTransaction } }));
    vi.doMock("@/lib/env", () => ({ env: { ADMIN_ELEVATION_MAX_AGE_SECONDS: 300 } }));
    const { authorizeAdminElevationForDomainMutation } = await import("@/features/auth/server/adminElevation/requireAdminElevation");
    const { createAdminInviteService } = await import("@/features/auth/server/adminInvites/adminInviteService");
    const tx = { invite: { create: vi.fn(), findFirst: vi.fn(), findMany: vi.fn(), updateMany: vi.fn() }, outboxEmail: { create: vi.fn() }, auditEvent: { create: vi.fn() }, ...elevationDelegates() };
    const service = createAdminInviteService({
      transaction: async (callback) => callback(tx),
      authorize: authorizeAdminElevationForDomainMutation,
      encryptToken: vi.fn(),
      deliveryKey: { keyHex: "a".repeat(64), version: 1 },
      now: () => NOW,
    });

    await expect(service.issue({ session: null, email: "person@example.com", reason: "Support", requestId: "req-denial" }))
      .rejects.toMatchObject({ name: "GenericForbiddenError" });
    expect(tx.invite.create).not.toHaveBeenCalled();
    expect(tx.outboxEmail.create).not.toHaveBeenCalled();
    expect(tx.auditEvent.create).not.toHaveBeenCalled();
    expect(durableAudit).toHaveBeenCalledWith(expect.objectContaining({ data: expect.objectContaining({ action: "admin.invite.issue.denied" }) }));
    vi.doUnmock("@/lib/prisma");
    vi.doUnmock("@/lib/env");
  });
});

describe("admin invite HTTP boundary", () => {
  it("imports route modules without resolving request-time delivery keys", async () => {
    vi.stubEnv("SKIP_ENV_VALIDATION", "true");
    vi.stubEnv("INVITE_DELIVERY_ENCRYPTION_KEYS", "");
    vi.stubEnv("INVITE_DELIVERY_KEY_VERSION", "");
    await expect(import("@/app/api/admin/invites/issue/route")).resolves.toHaveProperty("POST");
    await expect(import("@/app/api/admin/invites/resend/route")).resolves.toHaveProperty("POST");
    vi.unstubAllEnvs();
  });
  it("rejects cross-site CSRF before limiter or service mutation", async () => {
    const mutate = vi.fn();
    const limit = vi.fn();
    const { createAdminInviteHttpHandler } = await import("@/features/auth/server/adminInvites/adminInviteHttp");
    const handler = createAdminInviteHttpHandler("issue", {
      session: vi.fn().mockResolvedValue({ user: { id: "admin-1", role: "ADMIN", sessionVersion: 1 } }),
      csrfCookie: vi.fn().mockResolvedValue("csrf"), limit,
      service: { issue: mutate, revoke: vi.fn(), resend: vi.fn(), list: vi.fn() },
      expectedOrigin: "https://auth.example.com",
      clientIp: vi.fn().mockReturnValue("198.51.100.10"),
    });
    const request = new Request("https://auth.example.com/api/admin/invites/issue", {
      method: "POST", headers: { "content-type": "application/json", origin: "https://evil.example", "sec-fetch-site": "cross-site", "x-forwarded-for": "127.0.0.1" },
      body: JSON.stringify({ csrfToken: "csrf", email: "person@example.com", reason: "Support", requestId: "9da281d8-34b5-4be9-9274-46f04d9f6b06" }),
    });
    const response = await handler(request);
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ ok: false, message: "Unable to complete this request." });
    expect(limit).not.toHaveBeenCalled();
    expect(mutate).not.toHaveBeenCalled();
  });

  it.each(["issue", "revoke", "resend"] as const)("rejects invalid CSRF for %s before limiter or service", async (operation) => {
    const service = { issue: vi.fn(), revoke: vi.fn(), resend: vi.fn(), list: vi.fn() };
    const limit = vi.fn();
    const { createAdminInviteHttpHandler } = await import("@/features/auth/server/adminInvites/adminInviteHttp");
    const handler = createAdminInviteHttpHandler(operation, {
      session: vi.fn().mockResolvedValue({ user: { id: "admin-1", role: "ADMIN", sessionVersion: 1 } }),
      csrfCookie: vi.fn().mockResolvedValue("csrf"),
      limit,
      service,
      expectedOrigin: "https://auth.example.com",
      clientIp: vi.fn().mockReturnValue("198.51.100.10"),
    });
    const body = operation === "issue"
      ? { csrfToken: "wrong", email: "person@example.com", reason: "Support", requestId: "9da281d8-34b5-4be9-9274-46f04d9f6b06" }
      : { csrfToken: "wrong", inviteId: "invite-1", reason: "Support", requestId: "9da281d8-34b5-4be9-9274-46f04d9f6b06" };
    const response = await handler(new Request(`https://auth.example.com/api/admin/invites/${operation}`, {
      method: "POST", headers: { "content-type": "application/json", origin: "https://auth.example.com", "sec-fetch-site": "same-origin" },
      body: JSON.stringify(body),
    }));

    expect(response.status).toBe(403);
    expect(limit).not.toHaveBeenCalled();
    expect(service.issue).not.toHaveBeenCalled();
    expect(service.revoke).not.toHaveBeenCalled();
    expect(service.resend).not.toHaveBeenCalled();
  });

  it("enforces both actor and IP limits before invoking a valid issue", async () => {
    const issue = vi.fn().mockResolvedValue({ ok: true, inviteId: "hidden" });
    const limit = vi.fn().mockResolvedValue({ success: true });
    const { createAdminInviteHttpHandler } = await import("@/features/auth/server/adminInvites/adminInviteHttp");
    const handler = createAdminInviteHttpHandler("issue", {
      session: vi.fn().mockResolvedValue({ user: { id: "admin-1", role: "ADMIN", sessionVersion: 1 } }),
      csrfCookie: vi.fn().mockResolvedValue("csrf"), limit,
      service: { issue, revoke: vi.fn(), resend: vi.fn(), list: vi.fn() }, expectedOrigin: "https://auth.example.com",
      clientIp: vi.fn().mockReturnValue("198.51.100.10"),
    });
    const response = await handler(new Request("https://auth.example.com/api/admin/invites/issue", {
      method: "POST", headers: { "content-type": "application/json", origin: "https://auth.example.com", "sec-fetch-site": "same-origin", "x-forwarded-for": "127.0.0.1" },
      body: JSON.stringify({ csrfToken: "csrf", email: "person@example.com", reason: "Support", requestId: "9da281d8-34b5-4be9-9274-46f04d9f6b06" }),
    }));
    expect(response.status).toBe(200);
    expect(limit).toHaveBeenCalledTimes(2);
    expect(JSON.stringify(limit.mock.calls)).toContain("198.51.100.10");
    expect(JSON.stringify(limit.mock.calls)).not.toContain("127.0.0.1");
    expect(issue).toHaveBeenCalledOnce();
    await expect(response.json()).resolves.toEqual({ ok: true });
  });

  it.each(["admin", "ip"] as const)("denies when the shared %s limiter rejects", async (deniedScope) => {
    const issue = vi.fn();
    const limit = vi.fn(async (key: string) => ({ success: !key.includes(`:${deniedScope}:`) }));
    const { createAdminInviteHttpHandler } = await import("@/features/auth/server/adminInvites/adminInviteHttp");
    const handler = createAdminInviteHttpHandler("issue", {
      session: vi.fn().mockResolvedValue({ user: { id: "admin-1", role: "ADMIN", sessionVersion: 1 } }),
      csrfCookie: vi.fn().mockResolvedValue("csrf"), limit,
      service: { issue, revoke: vi.fn(), resend: vi.fn(), list: vi.fn() }, expectedOrigin: "https://auth.example.com",
      clientIp: vi.fn().mockReturnValue("198.51.100.10"),
    });
    const response = await handler(new Request("https://auth.example.com/api/admin/invites/issue", {
      method: "POST", headers: { "content-type": "application/json", origin: "https://auth.example.com", "sec-fetch-site": "same-origin", "x-forwarded-for": "127.0.0.1" },
      body: JSON.stringify({ csrfToken: "csrf", email: "person@example.com", reason: "Support", requestId: "9da281d8-34b5-4be9-9274-46f04d9f6b06" }),
    }));
    expect(response.status).toBe(403);
    expect(issue).not.toHaveBeenCalled();
  });

  it.each(["revoke", "resend"] as const)("applies both limiter buckets to %s", async (operation) => {
    const service = { issue: vi.fn(), revoke: vi.fn().mockResolvedValue({ ok: true }), resend: vi.fn().mockResolvedValue({ ok: true }), list: vi.fn() };
    const limit = vi.fn().mockResolvedValue({ success: true });
    const { createAdminInviteHttpHandler } = await import("@/features/auth/server/adminInvites/adminInviteHttp");
    const handler = createAdminInviteHttpHandler(operation, {
      session: vi.fn().mockResolvedValue({ user: { id: "admin-1", role: "ADMIN", sessionVersion: 1 } }),
      csrfCookie: vi.fn().mockResolvedValue("csrf"),
      limit,
      service,
      expectedOrigin: "https://auth.example.com",
      clientIp: vi.fn().mockReturnValue("198.51.100.10"),
    });
    const response = await handler(new Request(`https://auth.example.com/api/admin/invites/${operation}`, {
      method: "POST", headers: { "content-type": "application/json", origin: "https://auth.example.com", "sec-fetch-site": "same-origin" },
      body: JSON.stringify({ csrfToken: "csrf", inviteId: "invite-1", reason: "Support", requestId: "9da281d8-34b5-4be9-9274-46f04d9f6b06" }),
    }));

    expect(response.status).toBe(200);
    expect(limit).toHaveBeenCalledTimes(2);
    expect(service[operation]).toHaveBeenCalledOnce();
  });
});

describe("admin invite page boundary", () => {
  it("keeps server-side page authorization and never passes normalized emails", async () => {
    const source = await readFile("src/app/(auth)/admin/invites/page.tsx", "utf8");
    expect(source).toContain("getServerSession");
    expect(source).toContain("session.user.role !== \"ADMIN\"");
    expect(source).toContain("redirect(\"/\")");
    expect(source).toContain(".list(claim)");
    expect(source).not.toContain("normalizedEmail");
  });
});

describe("TASK-026 durable elevation denials", () => {
  it.each(["missing-session", "missing-factor", "stale"] as const)("persists a separate denial for %s elevation", async (scenario) => {
    vi.resetModules();
    const durableAudit = vi.fn().mockResolvedValue({ id: "denial" });
    const durableTransaction = vi.fn(async (callback) => callback({ auditEvent: { create: durableAudit } }));
    vi.doMock("@/lib/prisma", () => ({ prisma: { $transaction: durableTransaction } }));
    vi.doMock("@/lib/env", () => ({ env: { ADMIN_ELEVATION_MAX_AGE_SECONDS: 300 } }));
    const { authorizeAdminElevationForDomainMutation } = await import("@/features/auth/server/adminElevation/requireAdminElevation");
    const tx = elevationDelegates();
    const session = scenario === "missing-session" ? null : { userId: "admin-1", role: "ADMIN" as const, sessionVersion: 4 };
    tx.user.findUnique.mockResolvedValue({ role: "ADMIN", sessionVersion: 4, status: "ACTIVE", lastStrongAuthAt: scenario === "stale" ? new Date(NOW.getTime() - 301_000) : NOW });
    tx.adminMfaFactor.findFirst.mockResolvedValue(scenario === "missing-factor" ? null : { id: "factor" });
    tx.adminCapabilityGrant.findFirst.mockResolvedValue({ id: "grant" });
    await expect(authorizeAdminElevationForDomainMutation({ session, tx: { ...tx, auditEvent: { create: vi.fn() } } }, "admin:invite:issue", "admin.invite.issue.denied", NOW))
      .rejects.toMatchObject({ name: "GenericForbiddenError" });
    expect(durableTransaction).toHaveBeenCalledOnce();
    expect(durableAudit).toHaveBeenCalledOnce();
    expect(durableAudit).toHaveBeenCalledWith(expect.objectContaining({ data: expect.objectContaining({ action: "admin.invite.issue.denied", metadata: { capability: "admin:invite:issue", outcome: "DENIAL" } }) }));
    vi.doUnmock("@/lib/prisma");
    vi.doUnmock("@/lib/env");
  });
});
