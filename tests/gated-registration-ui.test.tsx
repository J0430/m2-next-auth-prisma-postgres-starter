// Verifies the invitation-only registration boundary and its leakage controls.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  exchangeInviteToken,
  type ExchangeInviteDeps,
} from "@/features/auth/server/registration/exchangeInviteToken";
import { buildRegistrationCsp } from "@/features/auth/server/registration/registrationSecurity";

describe("TASK-027 registration security profiles", () => {
  it("keeps the invite profile strict while allowing only Turnstile on register", () => {
    const invite = buildRegistrationCsp("invite", "invite-nonce");
    const register = buildRegistrationCsp("register", "register-nonce");

    expect(invite).toContain("script-src 'self' 'nonce-invite-nonce'");
    expect(invite).toContain("connect-src 'self'");
    expect(invite).not.toContain("challenges.cloudflare.com");
    expect(register).toContain(
      "script-src 'self' 'nonce-register-nonce' https://challenges.cloudflare.com",
    );
    expect(register).toContain("frame-src https://challenges.cloudflare.com");
    const registerScript = register.split("; ").find((value) => value.startsWith("script-src"));
    expect(registerScript).not.toContain("'unsafe-inline'");
    expect(registerScript).not.toContain("'unsafe-eval'");
  });
});

describe("TASK-027 opaque invitation exchange", () => {
  it("returns an opaque handle and stores only its digest without redeeming", async () => {
    const createSession = vi.fn(async () => undefined);
    const rawToken = "A".repeat(43);
    const result = await exchangeInviteToken(
      { rawToken, ip: "192.0.2.4" },
      {
        lookupInvite: vi.fn(async () => ({
          ok: true as const,
          invite: {
            id: "invite-1",
            tokenHash: Buffer.alloc(32, 7),
            normalizedEmail: "person@example.com",
            expiresAt: new Date(Date.now() + 60_000),
          },
        })),
        limitAll: vi.fn(async () => ({ success: true })),
        createSession,
        randomBytes: (size) => Buffer.alloc(size, 9),
        now: () => new Date("2026-07-12T20:00:00.000Z"),
      },
    );

    expect(result.handle).toBe(Buffer.alloc(32, 9).toString("base64url"));
    expect(result.handle).not.toContain(rawToken);
    expect(createSession).toHaveBeenCalledWith(expect.objectContaining({
      handleHash: createHash("sha256").update(result.handle).digest(),
      status: "PENDING",
      inviteId: "invite-1",
      normalizedEmail: "person@example.com",
    }));
  });

  it("preserves the same handle response while the global budget prevents row growth", async () => {
    const createSession = vi.fn(async () => undefined);
    const result = await exchangeInviteToken(
      { rawToken: "invalid", ip: "192.0.2.5" },
      {
        lookupInvite: vi.fn(async () => ({
          ok: false as const,
          status: 403 as const,
          body: { ok: false as const, message: "Unable to complete this request." as const },
        })),
        limitAll: vi.fn(async () => ({ success: false })),
        createSession,
        randomBytes: (size) => Buffer.alloc(size, 5),
        now: () => new Date("2026-07-12T20:00:00.000Z"),
      },
    );

    expect(result.handle).toHaveLength(43);
    expect(createSession).not.toHaveBeenCalled();
  });

  it("consumes independent IP, invite-hash, and global write budgets", async () => {
    const limitAll = vi.fn<ExchangeInviteDeps["limitAll"]>(async () => ({ success: true }));
    await exchangeInviteToken(
      { rawToken: "B".repeat(43), ip: "192.0.2.6" },
      {
        lookupInvite: vi.fn(async () => ({
          ok: false as const,
          status: 403 as const,
          body: { ok: false as const, message: "Unable to complete this request." as const },
        })),
        limitAll,
        createSession: vi.fn(async () => undefined),
        randomBytes: (size) => Buffer.alloc(size, 4),
        now: () => new Date("2026-07-12T20:00:00.000Z"),
      },
    );
    expect(limitAll.mock.calls[0]?.[0].map((check) => check.policy)).toEqual([
      "fragment-exchange-ip",
      "fragment-exchange-invite",
      "exchange-write-global",
    ]);
  });

  it("stops before invite, global, lookup, and row writes when the IP budget is exhausted", async () => {
    const lookupInvite = vi.fn<ExchangeInviteDeps["lookupInvite"]>();
    const createSession = vi.fn<ExchangeInviteDeps["createSession"]>();
    const limitAll = vi.fn<ExchangeInviteDeps["limitAll"]>(async () => ({ success: false }));
    await exchangeInviteToken(
      { rawToken: "E".repeat(43), ip: "192.0.2.8" },
      {
        lookupInvite,
        limitAll,
        createSession,
        randomBytes: (size) => Buffer.alloc(size, 6),
        now: () => new Date("2026-07-12T20:00:00.000Z"),
      },
    );

    expect(limitAll).toHaveBeenCalledOnce();
    expect(lookupInvite).not.toHaveBeenCalled();
    expect(createSession).not.toHaveBeenCalled();
  });

  it("does not consume the global write budget after the invite key is exhausted", async () => {
    const lookupInvite = vi.fn<ExchangeInviteDeps["lookupInvite"]>();
    const limitAll = vi.fn<ExchangeInviteDeps["limitAll"]>(async () => ({ success: false }));
    await exchangeInviteToken(
      { rawToken: "K".repeat(43), ip: "192.0.2.11" },
      {
        lookupInvite,
        limitAll,
        createSession: vi.fn(async () => undefined),
        randomBytes: (size) => Buffer.alloc(size, 8),
        now: () => new Date("2026-07-12T20:00:00.000Z"),
      },
    );

    expect(limitAll).toHaveBeenCalledOnce();
    expect(lookupInvite).not.toHaveBeenCalled();
  });
});

describe("TASK-027 invite-only action seam", () => {
  it("delegates an opaque invite session even while open self-service remains disabled", async () => {
    vi.resetModules();
    const registerWithInvite = vi.fn(async () => ({
      ok: false as const,
      status: 403,
      body: { ok: false as const, message: "Unable to complete this request.", supportId: "support" },
    }));
    vi.doMock("@/lib/env", () => ({
      env: {
        SELF_SERVICE_REGISTRATION_ENABLED: "false",
        AUTH_URL: "http://localhost",
        NEXTAUTH_URL: undefined,
        APP_URL: undefined,
      },
    }));
    vi.doMock("next/headers", () => ({
      headers: vi.fn(async () => new Headers({ origin: "http://localhost" })),
      cookies: vi.fn(async () => ({
        get: (name: string) => ({ value: name === "registration_session" ? "opaque" : "csrf" }),
        set: vi.fn(),
      })),
    }));
    vi.doMock("@/features/auth/server/registration/registerWithInvite", () => ({
      REGISTRATION_CSRF_COOKIE_NAME: "registration_csrf",
      REGISTRATION_SESSION_COOKIE_NAME: "registration_session",
      registerWithInvite,
    }));

    const { registerUser } = await import("@/features/auth/server/registration/registerAction");
    await registerUser(new FormData());
    expect(registerWithInvite).toHaveBeenCalledOnce();
  });
});

describe("TASK-027 browser and route contracts", () => {
  it("strips the fragment immediately after starting exchange and never persists it", () => {
    const source = readFileSync(resolve("src/features/auth/components/InviteAcceptance/useInviteAcceptance.ts"), "utf8");
    expect(source.indexOf("fetch(\"/api/invitations/exchange\"")).toBeLessThan(source.indexOf("history.replaceState"));
    expect(source.indexOf("history.replaceState")).toBeLessThan(source.indexOf("exchange.then"));
    expect(source).not.toMatch(/localStorage|sessionStorage|document\.cookie/u);
  });

  it("renders a non-leaking no-JS notice and no public signup entry", () => {
    const invitePage = readFileSync(resolve("src/app/invite/page.tsx"), "utf8");
    const publicPage = readFileSync(resolve("src/app/(public)/page.tsx"), "utf8");
    expect(invitePage).toContain("<noscript>");
    expect(invitePage).toContain("JavaScript is required to accept this invitation.");
    expect(invitePage).not.toContain("token=");
    expect(publicPage).not.toMatch(/SignupStep|Create an account|mode.*signup/u);
  });

  it("ships the deferred Playwright contract for fragment, CSP, keyboard, and responsive proof", () => {
    const spec = readFileSync(resolve("e2e/gated-registration.spec.mjs"), "utf8");
    expect(spec).toContain("history strips the invite fragment");
    expect(spec).toContain("Profile A");
    expect(spec).toContain("Profile B");
    expect(spec).toContain("keyboard");
    expect(spec).toContain("responsive");
    expect(spec).toContain("javaScriptEnabled: false");
  });

  it("keeps register GET independent of opaque-session validity and client token input", () => {
    const page = readFileSync(resolve("src/app/register/page.tsx"), "utf8");
    const form = readFileSync(resolve("src/features/auth/components/RegistrationForm/RegistrationForm.tsx"), "utf8");
    expect(page).not.toMatch(/cookies|RegistrationSession|normalizedEmail|prisma/u);
    expect(form).not.toMatch(/inviteToken|registration_session|type="hidden"/u);
  });

  it("sets the exact opaque cookie attributes and generic redirect", async () => {
    vi.resetModules();
    vi.doMock("@/lib/env", () => ({
      env: { AUTH_URL: "https://auth.example.com", NEXTAUTH_URL: undefined, APP_URL: undefined },
    }));
    vi.doMock("@/lib/rateLimit", () => ({ getClientIp: vi.fn(() => "192.0.2.7") }));
    vi.doMock("@/features/auth/server/registration/exchangeInviteToken", () => ({
      exchangeInviteToken: vi.fn(async () => ({ handle: "C".repeat(43) })),
    }));
    const { POST } = await import("@/app/api/invitations/exchange/route");
    const response = await POST(new Request("https://auth.example.com/api/invitations/exchange", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://auth.example.com",
        "sec-fetch-site": "same-origin",
        "x-registration-csrf": "csrf-token",
        "x-nonce": "route-nonce",
      },
      body: JSON.stringify({ token: "D".repeat(43), csrfToken: "csrf-token" }),
    }));
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/register");
    expect(response.headers.get("set-cookie")).toBe(
      `registration_session=${"C".repeat(43)}; HttpOnly; Secure; SameSite=Strict; Path=/register; Max-Age=600`,
    );
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("mints the same outward cookie for invalid CSRF without lookup, limits, or row writes", async () => {
    vi.resetModules();
    const exchangeInviteToken = vi.fn(async () => ({ handle: "V".repeat(43) }));
    const createOpaqueRegistrationHandle = vi.fn(() => "X".repeat(43));
    vi.doMock("@/lib/env", () => ({
      env: { AUTH_URL: "https://auth.example.com", NEXTAUTH_URL: undefined, APP_URL: undefined },
    }));
    vi.doMock("@/lib/rateLimit", () => ({ getClientIp: vi.fn(() => "192.0.2.9") }));
    vi.doMock("@/features/auth/server/registration/exchangeInviteToken", () => ({
      createOpaqueRegistrationHandle,
      exchangeInviteToken,
    }));
    const { POST } = await import("@/app/api/invitations/exchange/route");
    const response = await POST(new Request("https://auth.example.com/api/invitations/exchange", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://auth.example.com",
        "sec-fetch-site": "same-origin",
        "x-registration-csrf": "expected-csrf",
        "x-nonce": "csrf-nonce",
      },
      body: JSON.stringify({ token: "T".repeat(43), csrfToken: "wrong-csrf" }),
    }));
    const missingResponse = await POST(new Request("https://auth.example.com/api/invitations/exchange", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://auth.example.com",
        "sec-fetch-site": "same-origin",
        "x-registration-csrf": "expected-csrf",
        "x-nonce": "csrf-nonce",
      },
      body: JSON.stringify({ token: "T".repeat(43) }),
    }));

    expect(exchangeInviteToken).not.toHaveBeenCalled();
    expect(createOpaqueRegistrationHandle).toHaveBeenCalledTimes(2);
    expect(response.status).toBe(303);
    expect(missingResponse.status).toBe(response.status);
    expect(response.headers.get("location")).toBe("/register");
    expect(missingResponse.headers.get("location")).toBe(response.headers.get("location"));
    expect(response.headers.get("set-cookie")).toContain(`registration_session=${"X".repeat(43)}`);
  });

  it("keeps valid and decoy exchange responses identical outside opaque cookie bytes", async () => {
    vi.resetModules();
    const exchangeInviteToken = vi.fn()
      .mockResolvedValueOnce({ handle: "P".repeat(43) })
      .mockResolvedValueOnce({ handle: "D".repeat(43) });
    vi.doMock("@/lib/env", () => ({
      env: { AUTH_URL: "https://auth.example.com", NEXTAUTH_URL: undefined, APP_URL: undefined },
    }));
    vi.doMock("@/lib/rateLimit", () => ({ getClientIp: vi.fn(() => "192.0.2.10") }));
    vi.doMock("@/features/auth/server/registration/exchangeInviteToken", () => ({
      createOpaqueRegistrationHandle: vi.fn(() => "X".repeat(43)),
      exchangeInviteToken,
    }));
    const { POST } = await import("@/app/api/invitations/exchange/route");
    const request = (token: string) => new Request("https://auth.example.com/api/invitations/exchange", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://auth.example.com",
        "sec-fetch-site": "same-origin",
        "x-registration-csrf": "csrf-token",
        "x-nonce": "parity-nonce",
      },
      body: JSON.stringify({ token, csrfToken: "csrf-token" }),
    });
    const valid = await POST(request("V".repeat(43)));
    const decoy = await POST(request("invalid"));
    const normalizeCookie = (value: string | null) => value?.replace(/registration_session=[^;]+/u, "registration_session=<opaque>");

    expect(valid.status).toBe(decoy.status);
    expect(valid.headers.get("location")).toBe(decoy.headers.get("location"));
    expect(normalizeCookie(valid.headers.get("set-cookie"))).toBe(normalizeCookie(decoy.headers.get("set-cookie")));
    expect(await valid.text()).toBe(await decoy.text());
  });
});
