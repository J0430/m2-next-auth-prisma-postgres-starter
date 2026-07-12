// Verifies authenticated CSRF issuance uses a host-independent canonical cookie contract.
import { beforeEach, describe, expect, it, vi } from "vitest";

const { findUnique, getServerSession } = vi.hoisted(() => ({
  findUnique: vi.fn(),
  getServerSession: vi.fn(),
}));

vi.mock("next-auth", () => ({ getServerSession }));
vi.mock("@/features/auth/server/options", () => ({ authOptions: {} }));
vi.mock("@/lib/prisma", () => ({ prisma: { user: { findUnique } } }));
vi.mock("@/lib/env", () => ({ env: { AUTH_URL: "https://auth.example.test", NEXTAUTH_URL: "https://alias.example.test" } }));

import { handleAdminCsrfIssue } from "@/features/auth/server/adminMfa/adminCsrfHttp";

describe("admin CSRF HTTP issuance", () => {
  beforeEach(() => vi.clearAllMocks());

  it("issues a no-store Strict cookie for a current ACTIVE admin session", async () => {
    getServerSession.mockResolvedValue({ user: { id: "admin-1", sessionVersion: 4 } });
    findUnique.mockResolvedValue({ role: "ADMIN", status: "ACTIVE", sessionVersion: 4 });
    const result = await handleAdminCsrfIssue();
    const body: unknown = await result.json();
    expect(body).toEqual({ csrfToken: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u) });
    expect(result.headers.get("cache-control")).toBe("no-store");
    expect(result.headers.get("set-cookie")).toMatch(/^admin_csrf=.*; Path=\/api\/admin; Max-Age=300; HttpOnly; Secure; SameSite=Strict$/u);
  });

  it("fails generically without issuing a cookie for a stale session", async () => {
    getServerSession.mockResolvedValue({ user: { id: "admin-1", sessionVersion: 4 } });
    findUnique.mockResolvedValue({ role: "ADMIN", status: "ACTIVE", sessionVersion: 5 });
    const result = await handleAdminCsrfIssue();
    expect(result.status).toBe(403);
    expect(result.headers.get("set-cookie")).toBeNull();
  });
});
