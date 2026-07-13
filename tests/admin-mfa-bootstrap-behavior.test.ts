// Exercises the imported admin bootstrap ceremony with deterministic dependencies and an in-memory Prisma boundary.
import { PrismaClient, type Prisma } from "@prisma/client";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  activate,
  prepare,
  type BootstrapDependencies,
} from "../scripts/admin-mfa-bootstrap";

const NOW = new Date("2026-07-12T18:00:00.000Z");

interface BootstrapUser {
  id: string;
  email: string;
  role: "USER" | "ADMIN";
  passwordHash: string | null;
  hasPasswordCredential: boolean;
  adminBootstrapCompletedAt: Date | null;
  adminMfaFactors: Array<{
    id: string;
    secretCipher?: string;
    keyVersion?: string;
    lastUsedStep?: bigint | null;
  }>;
}

function eligibleUser(overrides: Partial<BootstrapUser> = {}): BootstrapUser {
  return {
    id: "user-1",
    email: "admin@example.test",
    role: "USER",
    passwordHash: "stored-password-hash",
    hasPasswordCredential: true,
    adminBootstrapCompletedAt: null,
    adminMfaFactors: [],
    ...overrides,
  };
}

function dependencies(overrides: Partial<BootstrapDependencies> = {}): BootstrapDependencies {
  return {
    comparePassword: vi.fn().mockResolvedValue(true),
    decryptSecret: vi.fn().mockReturnValue("TOTP-SECRET"),
    encryptSecret: vi.fn().mockReturnValue({ cipher: "encrypted-secret", keyVersion: "v1" }),
    generateSecret: vi.fn().mockReturnValue("TOTP-SECRET"),
    matchingStep: vi.fn().mockReturnValue(1234),
    now: () => NOW,
    writeOutput: vi.fn(),
    ...overrides,
  };
}

function prismaProxy(overrides: Readonly<Record<string, unknown>>): PrismaClient {
  return new Proxy(new PrismaClient(), {
    get(target, property, receiver) {
      if (typeof property === "string" && property in overrides) return overrides[property];
      return Reflect.get(target, property, receiver);
    },
  });
}

function transactionHarness(user: BootstrapUser) {
  const calls = {
    factorCreate: vi.fn().mockResolvedValue({ id: "factor-1" }),
    factorUpdate: vi.fn().mockResolvedValue({ count: 1 }),
    grantCreate: vi.fn().mockResolvedValue({ count: 2 }),
    grantRevoke: vi.fn().mockResolvedValue({ count: 1 }),
    userFind: vi.fn().mockResolvedValue(user),
    userUpdate: vi.fn().mockResolvedValue({ count: 1 }),
    auditCreate: vi.fn().mockResolvedValue({ id: "audit-1" }),
    executeRaw: vi.fn().mockResolvedValue(1),
  };
  const tx = prismaProxy({
    adminMfaFactor: { create: calls.factorCreate, updateMany: calls.factorUpdate },
    adminCapabilityGrant: { createMany: calls.grantCreate, updateMany: calls.grantRevoke },
    user: { findUnique: calls.userFind, updateMany: calls.userUpdate },
    auditEvent: { create: calls.auditCreate },
    $executeRaw: calls.executeRaw,
  });
  const transaction = vi.fn(async (operation: (client: Prisma.TransactionClient) => Promise<unknown>) => operation(tx));
  const prisma = prismaProxy({
    user: { findUnique: vi.fn().mockResolvedValue(user) },
    $transaction: transaction,
  });
  return { calls, prisma, transaction };
}

beforeEach(() => vi.clearAllMocks());

describe("admin MFA bootstrap preparation", () => {
  it.each([
    ["missing identity", null],
    ["provider-only identity", eligibleUser({ hasPasswordCredential: false, passwordHash: null })],
    ["missing password hash", eligibleUser({ passwordHash: null })],
    ["completed bootstrap", eligibleUser({ adminBootstrapCompletedAt: NOW })],
    ["active or pending state", eligibleUser({ adminMfaFactors: [{ id: "factor-existing" }] })],
  ])("rejects unsafe %s before creating state", async (_label, user) => {
    const harness = transactionHarness(eligibleUser());
    const findUnique = vi.fn().mockResolvedValue(user);
    const prisma = prismaProxy({ user: { findUnique }, $transaction: harness.transaction });

    await expect(prepare(prisma, "admin@example.test", dependencies())).rejects.toThrow("Unsafe or ineligible bootstrap identity");
    expect(harness.transaction).not.toHaveBeenCalled();
  });

  it("allows a legacy ADMIN with only revoked history and commits factor plus audit together", async () => {
    const user = eligibleUser({ role: "ADMIN", adminMfaFactors: [] });
    const harness = transactionHarness(user);
    const deps = dependencies();

    await prepare(harness.prisma, user.email, deps);

    expect(harness.transaction).toHaveBeenCalledOnce();
    expect(harness.calls.factorCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ userId: user.id, status: "PENDING", secretCipher: "encrypted-secret" }),
    }));
    expect(harness.calls.auditCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ action: "admin.mfa.bootstrap.prepared", actorUserId: user.id }),
    }));
  });

  it("maps a unique pending-factor race to a generic safe failure and emits no proof", async () => {
    const transaction = vi.fn().mockRejectedValue(new Error("P2002 pending-factor-secret-detail"));
    const prisma = prismaProxy({
      user: { findUnique: vi.fn().mockResolvedValue(eligibleUser()) },
      $transaction: transaction,
    });
    const deps = dependencies();

    await expect(prepare(prisma, "admin@example.test", deps)).rejects.toThrow("Bootstrap preparation failed");
    expect(deps.writeOutput).not.toHaveBeenCalled();
  });
});

describe("admin MFA bootstrap activation", () => {
  function pendingUser(overrides: Partial<BootstrapUser> = {}): BootstrapUser {
    return eligibleUser({
      adminMfaFactors: [{ id: "factor-1", secretCipher: "encrypted-secret", keyVersion: "v1", lastUsedStep: null }],
      ...overrides,
    });
  }

  it("requires both password and TOTP proofs without leaking either proof", async () => {
    const passwordFailure = transactionHarness(pendingUser());
    const badPassword = dependencies({ comparePassword: vi.fn().mockResolvedValue(false) });
    await expect(activate(passwordFailure.prisma, "admin@example.test", "proof-password", "123456", ["admin:mfa:manage"], badPassword))
      .rejects.toThrow("Bootstrap assertion failed");
    expect(passwordFailure.calls.factorUpdate).not.toHaveBeenCalled();

    const totpFailure = transactionHarness(pendingUser());
    const badTotp = dependencies({ matchingStep: vi.fn().mockReturnValue(null) });
    await expect(activate(totpFailure.prisma, "admin@example.test", "proof-password", "654321", ["admin:mfa:manage"], badTotp))
      .rejects.toThrow("Bootstrap assertion failed");
    expect(totpFailure.calls.factorUpdate).not.toHaveBeenCalled();
    expect(JSON.stringify([...totpFailure.calls.auditCreate.mock.calls])).not.toContain("proof-password");
    expect(JSON.stringify([...totpFailure.calls.auditCreate.mock.calls])).not.toContain("654321");
  });

  it("permits revoked history but rejects active, absent, multiple-pending, and completed states", async () => {
    const rejected = [
      pendingUser({ adminMfaFactors: [] }),
      pendingUser({ adminMfaFactors: [{ id: "a" }, { id: "b" }] }),
      pendingUser({ adminBootstrapCompletedAt: NOW }),
    ];
    for (const user of rejected) {
      const harness = transactionHarness(user);
      await expect(activate(harness.prisma, user.email, "password", "123456", ["admin:mfa:manage"], dependencies()))
        .rejects.toThrow("Bootstrap assertion failed");
      expect(harness.calls.factorUpdate).not.toHaveBeenCalled();
    }
  });

  it("CAS-consumes a TOTP step so replay or a losing activation cannot mutate privilege", async () => {
    const harness = transactionHarness(pendingUser());
    harness.calls.factorUpdate.mockResolvedValue({ count: 0 });

    await expect(activate(harness.prisma, "admin@example.test", "password", "123456", ["admin:mfa:manage"], dependencies()))
      .rejects.toThrow("Bootstrap assertion failed");

    expect(harness.calls.factorUpdate).toHaveBeenCalledWith(expect.objectContaining({
      where: { id: "factor-1", status: "PENDING", lastUsedStep: null },
      data: expect.objectContaining({ lastUsedStep: BigInt(1234) }),
    }));
    expect(harness.calls.grantRevoke).not.toHaveBeenCalled();
    expect(harness.calls.auditCreate).not.toHaveBeenCalled();
  });

  it("runs the complete privilege transition as one serializable atomic command", async () => {
    const user = pendingUser({ role: "ADMIN" });
    const harness = transactionHarness(user);
    const selected = ["admin:invite:issue", "admin:mfa:manage"];

    await activate(harness.prisma, user.email, "password", "123456", selected, dependencies());

    expect(harness.transaction).toHaveBeenCalledWith(expect.any(Function), { isolationLevel: "Serializable" });
    expect(harness.calls.grantRevoke).toHaveBeenCalledWith({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: NOW } });
    expect(harness.calls.grantCreate).toHaveBeenCalledWith({ data: selected.map((capability) => ({ userId: user.id, capability })) });
    expect(harness.calls.userUpdate).toHaveBeenCalledWith({
      where: { id: user.id, adminBootstrapCompletedAt: null },
      data: {
        role: "ADMIN", mfaEnrolledAt: NOW, lastStrongAuthAt: NOW,
        adminBootstrapCompletedAt: NOW, sessionVersion: { increment: 1 },
      },
    });
    expect(harness.calls.executeRaw).toHaveBeenCalledTimes(2);
    expect(harness.calls.auditCreate).toHaveBeenCalledOnce();
    expect(harness.calls.auditCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        action: "admin.mfa.bootstrap.activated", actorUserId: user.id,
        targetUserId: user.id, metadata: { outcome: "SUCCESS", capabilities: selected },
      }),
    }));
  });

  it("rolls back conceptually and executes no later command after an intermediate failure", async () => {
    const harness = transactionHarness(pendingUser());
    harness.calls.grantCreate.mockRejectedValue(new Error("insert failed"));

    await expect(activate(harness.prisma, "admin@example.test", "password", "123456", ["admin:mfa:manage"], dependencies()))
      .rejects.toThrow("insert failed");

    expect(harness.calls.userUpdate).not.toHaveBeenCalled();
    expect(harness.calls.auditCreate).not.toHaveBeenCalled();
    expect(harness.calls.executeRaw).toHaveBeenCalledOnce();
  });

  it("rejects a lost promotion CAS without writing exemption deletion or success audit", async () => {
    const harness = transactionHarness(pendingUser());
    harness.calls.userUpdate.mockResolvedValue({ count: 0 });

    await expect(activate(harness.prisma, "admin@example.test", "password", "123456", ["admin:mfa:manage"], dependencies()))
      .rejects.toThrow("Bootstrap assertion failed");

    expect(harness.calls.executeRaw).toHaveBeenCalledOnce();
    expect(harness.calls.auditCreate).not.toHaveBeenCalled();
  });
});
