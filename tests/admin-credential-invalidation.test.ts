// Verifies credential changes invalidate every outstanding admin-elevation session.
import { beforeEach, describe, expect, it, vi } from "vitest";

const { prisma } = vi.hoisted(() => ({ prisma: {
  user: { findUnique: vi.fn(), update: vi.fn() },
  passwordResetToken: { findUnique: vi.fn(), deleteMany: vi.fn() },
  session: { deleteMany: vi.fn() },
  $transaction: vi.fn(),
} }));

vi.mock("@/lib/prisma", () => ({ prisma }));
vi.mock("@/features/auth/server/options", () => ({ authOptions: {} }));
vi.mock("next-auth", () => ({ getServerSession: vi.fn().mockResolvedValue({ user: { id: "user-1", email: "user@example.test" } }) }));
vi.mock("next/headers", () => ({ headers: vi.fn().mockResolvedValue(new Headers({ "x-real-ip": "127.0.0.1" })) }));
vi.mock("@/lib/rateLimit", () => ({
  buildRateLimitKey: vi.fn().mockReturnValue("test-key"),
  getClientIp: vi.fn().mockReturnValue("127.0.0.1"),
  rateLimit: vi.fn().mockResolvedValue({ success: true }),
}));
vi.mock("bcryptjs", () => ({
  default: { compare: vi.fn().mockResolvedValue(true), hash: vi.fn().mockResolvedValue("new-hash") },
}));

import { changePassword } from "@/features/account/server/actions/changePassword";
import { consumePasswordResetToken } from "@/features/auth/server/reset/consumeResetToken";

describe("credential-change elevation invalidation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    prisma.$transaction.mockImplementation(async (operations: readonly Promise<unknown>[]) => Promise.all(operations));
  });

  it("changes passwordHash and atomically invalidates strong auth and session version", async () => {
    prisma.user.findUnique.mockResolvedValue({ passwordHash: "old-hash" });
    const formData = new FormData();
    formData.set("currentPassword", "OldPassword123!");
    formData.set("newPassword", "NewPassword123!");
    formData.set("confirmPassword", "NewPassword123!");

    await expect(changePassword(formData)).resolves.toEqual({ ok: true });
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(prisma.user.update).toHaveBeenCalledWith({
      where: { id: "user-1" },
      data: { passwordHash: "new-hash", lastStrongAuthAt: null, sessionVersion: { increment: 1 } },
    });
  });

  it("resets passwordHash and invalidates strong auth and session version in the token transaction", async () => {
    prisma.passwordResetToken.findUnique.mockResolvedValue({ identifier: "user@example.test", expires: new Date("2099-01-01") });
    prisma.user.findUnique.mockResolvedValue({ id: "user-1" });

    await expect(consumePasswordResetToken("token", "NewPassword123!")).resolves.toEqual({ ok: true });
    expect(prisma.user.update).toHaveBeenCalledWith({
      where: { id: "user-1" },
      data: { passwordHash: "new-hash", lastStrongAuthAt: null, sessionVersion: { increment: 1 } },
    });
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
  });
});
