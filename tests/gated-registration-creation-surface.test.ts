// Proves every account-creation/activation surface stays explicitly reviewed.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { analyzeCreationSources, assertCreationInventory } from "./helpers/creationSurfaceGuard";

process.env.SKIP_ENV_VALIDATION = "true";

const { auditCreate, requireElevation, sessionCreate, transaction, userCreate } = vi.hoisted(() => ({
  auditCreate: vi.fn(async () => ({ id: "audit-1" })),
  transaction: vi.fn(),
  requireElevation: vi.fn(),
  sessionCreate: vi.fn(),
  userCreate: vi.fn(async () => ({ id: "user-1", status: "INACTIVE" as const })),
}));

vi.mock("@/lib/prisma", () => ({ prisma: { $transaction: transaction } }));
vi.mock("@/features/auth/server/adminElevation", () => ({ requireAdminElevation: requireElevation }));

describe("trusted account creation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    transaction.mockImplementation(async (operation: (tx: unknown) => Promise<unknown>) => operation({
      user: { create: userCreate },
      session: { create: sessionCreate },
      auditEvent: { create: auditCreate },
    }));
    requireElevation.mockResolvedValue({
      actorId: "admin-1",
      capability: "admin:user:create",
      grantedAt: new Date("2026-07-12T12:00:00.000Z"),
    });
  });

  it("creates only INACTIVE users after same-transaction elevation and audit", async () => {
    const { trustedCreateUser } = await import("@/features/auth/server/registration/trustedCreateUser");
    const result = await trustedCreateUser({
      session: { userId: "admin-1", role: "ADMIN", sessionVersion: 4 },
      email: " New.User@Example.test ",
      name: "New User",
      reason: "approved support request",
    });

    expect(result).toEqual({ id: "user-1", status: "INACTIVE" });
    expect(requireElevation).toHaveBeenCalledWith(
      expect.objectContaining({ session: expect.objectContaining({ userId: "admin-1" }) }),
      "admin:user:create",
    );
    expect(userCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ email: "new.user@example.test", status: "INACTIVE" }),
    }));
    expect(auditCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        action: "admin.user.created",
        actorUserId: "admin-1",
        targetUserId: "user-1",
        metadata: expect.objectContaining({ outcome: "SUCCESS", status: "INACTIVE" }),
      }),
    }));
    expect(sessionCreate).not.toHaveBeenCalled();
  });

  it("cannot mint an auth token for the trusted-created INACTIVE identity", async () => {
    const { trustedCreateUser } = await import("@/features/auth/server/registration/trustedCreateUser");
    const { createSessionToken } = await import("@/features/auth/server/createSessionToken");
    const result = await trustedCreateUser({
      session: { userId: "admin-1", role: "ADMIN", sessionVersion: 4 },
      email: "new.user@example.test",
      name: null,
      reason: "approved support request",
    });

    await expect(createSessionToken({
      ...result,
      email: "new.user@example.test",
      name: null,
      role: "USER",
      sessionVersion: 0,
    })).rejects.toThrow("SESSION_USER_NOT_ACTIVE");
  });

  it("commits neither user nor success audit when elevation is denied", async () => {
    const forbidden = new Error("FORBIDDEN");
    requireElevation.mockRejectedValue(forbidden);
    const userCreate = vi.fn();
    const auditCreate = vi.fn();
    transaction.mockImplementation(async (operation: (tx: unknown) => Promise<unknown>) => operation({
      user: { create: userCreate },
      auditEvent: { create: auditCreate },
    }));
    const { trustedCreateUser } = await import("@/features/auth/server/registration/trustedCreateUser");

    await expect(trustedCreateUser({
      session: null,
      email: "new.user@example.test",
      name: null,
      reason: "approved support request",
    })).rejects.toBe(forbidden);
    expect(userCreate).not.toHaveBeenCalled();
    expect(auditCreate).not.toHaveBeenCalled();
  });
});

describe("bootstrap boundary", () => {
  afterEach(() => {
    vi.doUnmock("@/lib/env");
    vi.unstubAllEnvs();
  });

  it.each([
    [{ allowUserBootstrap: undefined, nodeEnv: "development" }, "unset"],
    [{ allowUserBootstrap: false, nodeEnv: "development" }, "disabled"],
    [{ allowUserBootstrap: true, nodeEnv: "production" }, "production"],
  ] as const)("fails closed when bootstrap is %s", async (runtime, _label) => {
    vi.resetModules();
    vi.stubEnv("NODE_ENV", runtime.nodeEnv);
    vi.doMock("@/lib/env", () => ({ env: { ALLOW_USER_BOOTSTRAP: runtime.allowUserBootstrap } }));
    const { bootstrapCreateActiveUser } = await import(
      "@/features/auth/server/registration/bootstrapCreateActiveUser"
    );
    const upsert = vi.fn();
    await expect(bootstrapCreateActiveUser({
      client: { user: { upsert } },
      email: "seed@example.test",
      name: "Seed",
      passwordHash: "hash",
    })).rejects.toThrow("USER_BOOTSTRAP_DISABLED");
    expect(upsert).not.toHaveBeenCalled();
  });

  it("creates an explicitly ACTIVE development seed user", async () => {
    vi.resetModules();
    vi.stubEnv("NODE_ENV", "development");
    vi.doMock("@/lib/env", () => ({ env: { ALLOW_USER_BOOTSTRAP: true } }));
    const { bootstrapCreateActiveUser } = await import(
      "@/features/auth/server/registration/bootstrapCreateActiveUser"
    );
    const upsert = vi.fn(async () => ({ id: "seed-1", status: "ACTIVE" as const }));
    await expect(bootstrapCreateActiveUser({
      client: { user: { upsert } },
      email: "seed@example.test",
      name: "Seed",
      passwordHash: "hash",
    })).resolves.toEqual({ id: "seed-1", status: "ACTIVE" });
    expect(upsert).toHaveBeenCalledWith(expect.objectContaining({
      create: expect.objectContaining({ status: "ACTIVE" }),
    }));
  });
});

describe("fail-closed creation-surface inventory", () => {
  const root = resolve(import.meta.dirname, "..");
  const allowlist = [
    "src/features/auth/server/registration/bootstrapCreateActiveUser.ts:45:user.upsert:ACTIVE",
    "src/features/auth/server/registration/registerWithInvite.ts:258:user.create:INACTIVE",
    "src/features/auth/server/registration/trustedCreateUser.ts:27:user.create:INACTIVE",
    "src/features/auth/server/social/gatedPrismaAdapter.ts:19:adapter.createUser:DENY",
    "src/features/auth/server/verify/consumeToken.ts:36:user.updateMany:ACTIVE",
  ];

  it("matches every current creation and activation call to the reviewed allowlist", () => {
    expect(() => assertCreationInventory(analyzeCreationSources(root), allowlist)).not.toThrow();
  });

  it("rejects an unallowlisted creation and a stale allowlist entry", () => {
    const fixture = analyzeCreationSources(root, {
      "src/fixture.ts": "async function x(tx: Db) { await tx.user.create({ data: { email: 'x' } }); }",
    });
    expect(() => assertCreationInventory(fixture, allowlist)).toThrow(/unreviewed/i);
    expect(() => assertCreationInventory(analyzeCreationSources(root), [...allowlist, "src/missing.ts:1:user.create:INACTIVE"]))
      .toThrow(/stale/i);
  });

  it("rejects a production trusted-creation fixture without elevation proof", () => {
    const fixture = analyzeCreationSources(root, {
      "src/features/auth/server/registration/fixture.ts":
        "export async function unsafe(tx: Db) { return tx.user.create({ data: { email: 'x', status: 'INACTIVE' } }); }",
    });
    expect(() => assertCreationInventory(fixture, [...allowlist, "src/features/auth/server/registration/fixture.ts:1:user.create:INACTIVE"]))
      .toThrow(/elevation/i);
  });

  it.each([
    ["elevation after create", [
      "const user = await tx.user.create({ data: { status: 'INACTIVE' } });",
      "const grant = await requireAdminElevation({ tx }, 'admin:user:create');",
      "await tx.auditEvent.create({ data: { action: 'admin.user.created', actorUserId: grant.actorId, targetId: user.id } });",
    ]],
    ["elevation on another client", [
      "const grant = await requireAdminElevation({ tx: otherTx }, 'admin:user:create');",
      "const user = await tx.user.create({ data: { status: 'INACTIVE' } });",
      "await tx.auditEvent.create({ data: { action: 'admin.user.created', actorUserId: grant.actorId, targetId: user.id } });",
    ]],
    ["missing associated audit", [
      "const grant = await requireAdminElevation({ tx }, 'admin:user:create');",
      "const user = await tx.user.create({ data: { status: 'INACTIVE' } });",
      "await tx.auditEvent.create({ data: { action: 'something.else', actorUserId: grant.actorId, targetId: user.id } });",
    ]],
  ] as const)("rejects structural proof bypass: %s", (_label, statements) => {
    const fixturePath = "src/features/admin/fixture.ts";
    const source = `export const x = (db: Db, otherTx: Db) => db.$transaction(async (tx: Db) => { ${statements.join(" ")} });`;
    const fixture = analyzeCreationSources(root, { [fixturePath]: source });
    const entry = fixture.entries.find(value => value.startsWith(`${fixturePath}:`) && value.includes(":user.create:"));
    expect(entry).toBeDefined();
    expect(() => assertCreationInventory(fixture, entry ? [...allowlist, entry] : allowlist))
      .toThrow(/elevation proof/i);
  });

  it("accepts structural proof only when elevation, creation, and associated audit share the transaction", () => {
    const fixturePath = "src/features/admin/fixture.ts";
    const source = [
      "export const x = (db: Db) => db.$transaction(async (tx: Db) => {",
      "const context = { tx };",
      "const grant = await requireAdminElevation(context, 'admin:user:create');",
      "const user = await tx.user.create({ data: { status: 'INACTIVE' } });",
      "await tx.auditEvent.create({ data: { action: 'admin.user.created', actorUserId: grant.actorId, targetId: user.id } });",
      "});",
    ].join("\n");
    const fixture = analyzeCreationSources(root, { [fixturePath]: source });
    const entry = fixture.entries.find(value => value.startsWith(`${fixturePath}:`) && value.includes(":user.create:"));
    expect(entry).toBeDefined();
    expect(() => assertCreationInventory(fixture, entry ? [...allowlist, entry] : allowlist)).not.toThrow();
  });

  it("detects ACTIVE mutation data through aliases", () => {
    const fixture = analyzeCreationSources(root, {
      "src/fixture.ts": [
        "const accountStatus = 'ACTIVE';",
        "const mutationData = { status: accountStatus };",
        "export const activate = (db: Db) => db.user.update({ where: { id: 'x' }, data: mutationData });",
      ].join("\n"),
    });
    expect(fixture.entries).toContain("src/fixture.ts:3:user.update:ACTIVE");
  });

  it("rejects destructured parameters that default status to ACTIVE", () => {
    const fixture = analyzeCreationSources(root, {
      "src/fixture.ts": "export function unsafe({ status = 'ACTIVE' }) { return status; }",
    });
    expect(() => assertCreationInventory(fixture, allowlist)).toThrow(/defaults status to ACTIVE/i);
  });

  it("detects ACTIVE mutation data inherited through object spread", () => {
    const fixture = analyzeCreationSources(root, {
      "src/fixture.ts": [
        "const active = { status: 'ACTIVE' };",
        "const data = { ...active, reason: 'activation' };",
        "export const run = (db: Db) => db.user.update({ where: { id: 'x' }, data });",
      ].join("\n"),
    });
    expect(fixture.entries).toContain("src/fixture.ts:3:user.update:ACTIVE");
  });

  it("detects enum/member aliases for ACTIVE", () => {
    const fixture = analyzeCreationSources(root, {
      "src/fixture.ts": [
        "enum Status { ACTIVE = 'ACTIVE' }",
        "export const run = (db: Db) => db.user.update({ where: { id: 'x' }, data: { status: Status.ACTIVE } });",
      ].join("\n"),
    });
    expect(fixture.entries).toContain("src/fixture.ts:2:user.update:ACTIVE");
  });

  it("detects calls through destructured user mutation methods", () => {
    const fixture = analyzeCreationSources(root, {
      "src/fixture.ts": [
        "export const run = (db: Db) => {",
        "const { update } = db.user;",
        "return update({ where: { id: 'x' }, data: { status: 'ACTIVE' } });",
        "};",
      ].join("\n"),
    });
    expect(fixture.entries).toContain("src/fixture.ts:3:user.update:ACTIVE");
  });

  it.each([
    ["elevation", [
      "const hidden = async () => requireAdminElevation({ tx }, 'admin:user:create');",
      "const grant = { actorId: 'admin' };",
      "const user = await tx.user.create({ data: { status: 'INACTIVE' } });",
      "await tx.auditEvent.create({ data: { action: 'admin.user.created', actorUserId: grant.actorId, targetId: user.id } });",
    ]],
    ["audit", [
      "const grant = await requireAdminElevation({ tx }, 'admin:user:create');",
      "const user = await tx.user.create({ data: { status: 'INACTIVE' } });",
      "const hidden = async () => tx.auditEvent.create({ data: { action: 'admin.user.created', actorUserId: grant.actorId, targetId: user.id } });",
    ]],
  ] as const)("does not accept %s proof from an uninvoked nested scope", (_label, statements) => {
    const path = "src/features/admin/nestedFixture.ts";
    const source = `export const run = (db: Db) => db.$transaction(async (tx: Db) => { ${statements.join(" ")} });`;
    const fixture = analyzeCreationSources(root, { [path]: source });
    const entry = fixture.entries.find(value => value.startsWith(`${path}:`) && value.includes(":user.create:"));
    expect(entry).toBeDefined();
    expect(() => assertCreationInventory(fixture, entry ? [...allowlist, entry] : allowlist))
      .toThrow(/elevation proof/i);
  });

  it.each([
    ["property", "export const adapter = { createUser: denyCreateUser };", "DENY"],
    ["method", "export const adapter = { createUser() { throw new Error('denied'); } };", "DENY"],
    ["shorthand", "function createUser() { throw new Error('denied'); } export const adapter = { createUser };", "DENY"],
    ["call", "export const x = (adapter: Adapter) => adapter.createUser({ email: 'x' });", "CALL"],
  ] as const)("inventories adapter createUser %s syntax", (_label, source, suffix) => {
    const fixture = analyzeCreationSources(root, { "src/fixture.ts": source });
    expect(fixture.entries.some(entry => entry.startsWith("src/fixture.ts:") && entry.endsWith(`adapter.createUser:${suffix}`)))
      .toBe(true);
  });

  it("requires elevation for creation outside the registration folder", () => {
    const fixtureEntry = "src/features/admin/createInactiveUser.ts:2:user.create:INACTIVE";
    const fixture = analyzeCreationSources(root, {
      "src/features/admin/createInactiveUser.ts": [
        "export async function unsafe(tx: Db) {",
        "  return tx.user.create({ data: { email: 'x', status: 'INACTIVE' } });",
        "}",
      ].join("\n"),
    });
    expect(() => assertCreationInventory(fixture, [...allowlist, fixtureEntry]))
      .toThrow(/elevation proof/i);
  });

  it("does not grant exemptions by spoofing a trusted filename", () => {
    const fixtureEntry = "src/features/unsafe/registerWithInvite.ts:1:user.create:INACTIVE";
    const fixture = analyzeCreationSources(root, {
      "src/features/unsafe/registerWithInvite.ts":
        "export const unsafe = (tx: Db) => tx.user.create({ data: { email: 'x', status: 'INACTIVE' } });",
    });
    expect(() => assertCreationInventory(fixture, [...allowlist, fixtureEntry]))
      .toThrow(/elevation proof/i);
  });

  it("rejects helpers that default status to ACTIVE", () => {
    const fixture = analyzeCreationSources(root, {
      "src/fixture.ts": "export function unsafe(status = 'ACTIVE') { return status; }",
    });
    expect(() => assertCreationInventory(fixture, allowlist)).toThrow(/defaults status to ACTIVE/i);
  });

  it("rejects an allowlisted ACTIVE creation outside the bootstrap exemption", () => {
    const fixtureEntry = "src/features/admin/createUser.ts:3:user.create:ACTIVE";
    const fixture = analyzeCreationSources(root, {
      "src/features/admin/createUser.ts": [
        "export async function unsafe(prisma: Db, context: Context) {",
        "  return prisma.$transaction(async (tx: Db) => {",
        "    await requireAdminElevation(context, 'admin:user:create'); return tx.user.create({ data: { email: 'x', status: 'ACTIVE' } });",
        "  });",
        "}",
      ].join("\n"),
    });
    expect(() => assertCreationInventory(fixture, [...allowlist, fixtureEntry]))
      .toThrow(/ACTIVE creation/i);
  });

  it("rejects bootstrap imports from top-level app routes", () => {
    const fixture = analyzeCreationSources(root, {
      "app/api/bootstrap/route.ts":
        "import { bootstrapCreateActiveUser } from '@/features/auth/server/registration/bootstrapCreateActiveUser';",
    });
    expect(() => assertCreationInventory(fixture, allowlist)).toThrow(/production bootstrap import/i);
  });

  it.each([
    "export async function x() { return import('@/features/auth/server/registration/bootstrapCreateActiveUser'); }",
    "const x = require('@/features/auth/server/registration/bootstrapCreateActiveUser');",
  ])("rejects dynamic production bootstrap loading: %s", (source) => {
    const fixture = analyzeCreationSources(root, { "src/fixture.js": source });
    expect(() => assertCreationInventory(fixture, allowlist)).toThrow(/production bootstrap import/i);
  });

  it("scans JSX creation surfaces", () => {
    const fixtureEntry = "src/fixture.jsx:1:user.create:INACTIVE";
    const fixture = analyzeCreationSources(root, {
      "src/fixture.jsx": "export const x = () => db.user.create({ data: { email: 'x', status: 'INACTIVE' } });",
    });
    expect(() => assertCreationInventory(fixture, [...allowlist, fixtureEntry])).toThrow(/elevation proof/i);
  });

  it("keeps bootstrap out of every production import graph", () => {
    const source = readFileSync(resolve(root, "prisma/seed.ts"), "utf8");
    expect(source).toContain("bootstrapCreateActiveUser");
    const productionImports = analyzeCreationSources(root).productionBootstrapImports;
    expect(productionImports).toEqual([]);
  });
});
