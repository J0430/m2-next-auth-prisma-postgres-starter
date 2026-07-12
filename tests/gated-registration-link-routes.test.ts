// Exercises the dedicated account-link HTTP routes through their public handlers.
import { beforeEach, describe, expect, it, vi } from "vitest";

const denialAudit = vi.fn(async () => undefined);
const rateLimit = vi.fn(async () => ({ success: true }));
const getServerSession = vi.fn<() => Promise<typeof session | null>>(async () => session);

const session = {
  user: { id: "user-1", email: "owner@example.com", sessionVersion: 4 },
  authProvider: "credentials",
  lastAuthAt: Date.now(),
};
const csrfToken = "csrf-value-that-is-at-least-32-characters";

vi.mock("next-auth", () => ({ getServerSession }));
vi.mock("@/features/auth/server/options", () => ({ authOptions: {} }));
vi.mock("@/lib/env", () => ({ env: { APP_URL: "https://app.example" } }));
vi.mock("@/features/auth/server/linking/audit", () => ({ recordLinkDenied: denialAudit }));
vi.mock("@/lib/rateLimit", () => ({
  buildRateLimitKey: vi.fn(() => "account-link:start"),
  getClientIp: vi.fn(() => "127.0.0.1"),
  rateLimit,
}));

describe("dedicated account-link start route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getServerSession.mockResolvedValue(session);
    rateLimit.mockResolvedValue({ success: true });
  });

  it("returns an opaque state and S256 PKCE provider authorization URL", async () => {
    const create = vi.fn(async () => ({
      ok: true,
      authorizationUrl: "https://github.com/login/oauth/authorize?state=opaque&code_challenge=challenge&code_challenge_method=S256",
    }));
    vi.doMock("@/features/auth/server/linking/startLinkFlow", () => ({ startAccountLinkFlow: create }));
    vi.doMock("next/headers", () => ({ cookies: vi.fn(async () => ({ get: () => ({ value: csrfToken }) })) }));
    const { POST } = await import("@/app/api/account/link/start/route");
    const response = await POST(new Request("https://app.example/api/account/link/start", {
      method: "POST",
      headers: { origin: "https://app.example", "content-type": "application/json" },
      body: JSON.stringify({ provider: "github", currentPassword: "password", csrfToken }),
    }));
    expect(response.status).toBe(200);
    const payload: unknown = await response.json();
    expect(payload).toEqual({ authorizationUrl: expect.stringContaining("code_challenge_method=S256") });
    expect(create).toHaveBeenCalledWith(expect.objectContaining({ userId: "user-1", sessionVersion: 4 }));
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("sets no-referrer on the CSRF response", async () => {
    vi.doMock("next/headers", () => ({ cookies: vi.fn(async () => ({ get: () => ({ value: csrfToken }) })) }));
    vi.resetModules();
    const { GET } = await import("@/app/api/account/link/csrf/route");
    const response = await GET();
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it.each([
    ["malformed request", "{", "malformed_request"],
    ["missing CSRF", JSON.stringify({ provider: "github", currentPassword: "password", csrfToken }), "csrf_failed"],
  ])("durably audits a redacted %s denial", async (_label, body, reason) => {
    vi.doMock("next/headers", () => ({ cookies: vi.fn(async () => ({ get: () => undefined })) }));
    vi.resetModules();
    const { POST } = await import("@/app/api/account/link/start/route");
    const response = await POST(new Request("https://app.example/api/account/link/start", {
      method: "POST", headers: { origin: "https://app.example", "content-type": "application/json" }, body,
    }));
    expect(response.status).toBe(400);
    expect(denialAudit).toHaveBeenCalledWith(reason === "malformed_request" ? "unknown" : "github", reason, "user-1");
    expect(JSON.stringify(denialAudit.mock.calls)).not.toContain(csrfToken);
  });

  it("audits origin and rate-limit denials without exposing their cause", async () => {
    vi.doMock("next/headers", () => ({ cookies: vi.fn(async () => ({ get: () => ({ value: csrfToken }) })) }));
    vi.resetModules();
    const { POST } = await import("@/app/api/account/link/start/route");
    await POST(new Request("https://app.example/api/account/link/start", {
      method: "POST", headers: { origin: "https://evil.example", "content-type": "application/json" },
      body: JSON.stringify({ provider: "github", currentPassword: "password", csrfToken }),
    }));
    expect(denialAudit).toHaveBeenLastCalledWith("github", "origin_failed", "user-1");

    rateLimit.mockResolvedValueOnce({ success: false });
    const response = await POST(new Request("https://app.example/api/account/link/start", {
      method: "POST", headers: { origin: "https://app.example", "content-type": "application/json" },
      body: JSON.stringify({ provider: "github", currentPassword: "password", csrfToken }),
    }));
    expect(response.status).toBe(400);
    expect(denialAudit).toHaveBeenLastCalledWith("github", "rate_limited", "user-1");
  });

  it("audits an unauthenticated start without retaining submitted credentials", async () => {
    getServerSession.mockResolvedValueOnce(null);
    vi.resetModules();
    const { POST } = await import("@/app/api/account/link/start/route");
    await POST(new Request("https://app.example/api/account/link/start", {
      method: "POST", headers: { origin: "https://app.example", "content-type": "application/json" },
      body: JSON.stringify({ provider: "github", currentPassword: "secret-password", csrfToken }),
    }));
    expect(denialAudit).toHaveBeenCalledWith("github", "authentication_required", null);
    expect(JSON.stringify(denialAudit.mock.calls)).not.toContain("secret-password");
  });

  it("exposes only the actionable stale-reauth denial to authenticated clients", async () => {
    vi.doMock("@/features/auth/server/linking/startLinkFlow", () => ({
      startAccountLinkFlow: vi.fn(async () => ({ ok: false, reason: "reauth_stale" })),
    }));
    vi.doMock("next/headers", () => ({ cookies: vi.fn(async () => ({ get: () => ({ value: csrfToken }) })) }));
    vi.resetModules();
    const { POST } = await import("@/app/api/account/link/start/route");
    const response = await POST(new Request("https://app.example/api/account/link/start", {
      method: "POST",
      headers: { origin: "https://app.example", "content-type": "application/json" },
      body: JSON.stringify({ provider: "github", currentPassword: null, csrfToken }),
    }));
    await expect(response.json()).resolves.toEqual({ error: "Account link failed", reason: "reauth_stale" });
  });
});

describe("social-only account-link reauthentication", () => {
  it("selects an existing linked provider and never the unlinked target", async () => {
    const { selectReauthProvider } = await import("@/features/account/components/ConnectedAccounts/ConnectedAccounts.helpers");
    expect(selectReauthProvider([{ provider: "google", providerAccountId: "subject" }])).toBe("google");
    expect(selectReauthProvider([{ provider: "unknown", providerAccountId: "subject" }])).toBeNull();
  });
});

describe("connected-account callback feedback", () => {
  it.each([
    ["success", { tone: "success", message: "Account connected successfully." }],
    ["failed", { tone: "error", message: "Account connection failed. Please try again." }],
  ] as const)("maps %s to explicit generic feedback", async (value, expected) => {
    const { parseLinkFeedback } = await import("@/features/account/components/ConnectedAccounts/ConnectedAccounts.helpers");
    expect(parseLinkFeedback(value)).toEqual(expected);
  });

  it("ignores unknown callback values", async () => {
    const { parseLinkFeedback } = await import("@/features/account/components/ConnectedAccounts/ConnectedAccounts.helpers");
    expect(parseLinkFeedback("secret-provider-error")).toBeNull();
  });

  it("navigates with an anchor that suppresses the settings referrer", async () => {
    const click = vi.fn();
    const anchor = { href: "", rel: "", referrerPolicy: "", click };
    vi.stubGlobal("document", { createElement: vi.fn(() => anchor) });
    const { navigateToProvider } = await import("@/features/account/components/ConnectedAccounts/ConnectedAccounts.helpers");
    navigateToProvider("https://github.example/authorize");
    expect(anchor).toMatchObject({
      href: "https://github.example/authorize", rel: "noreferrer", referrerPolicy: "no-referrer",
    });
    expect(click).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });
});

describe("dedicated account-link callback route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getServerSession.mockResolvedValue(session);
  });

  it.each([
    ["missing state", "?code=code"],
    ["malformed state", "?code=code&state=short"],
  ])("audits %s before redirecting generically", async (_label, query) => {
    vi.resetModules();
    const { GET } = await import("@/app/api/account/link/github/callback/route");
    const response = await GET(new Request(`https://app.example/api/account/link/github/callback${query}`));
    expect(response.headers.get("location")).toContain("link=failed");
    expect(denialAudit).toHaveBeenCalledWith("github", "malformed_callback", null);
  });
  it("audits an unauthenticated callback without retaining state or code", async () => {
    getServerSession.mockResolvedValueOnce(null);
    vi.resetModules();
    const { GET } = await import("@/app/api/account/link/github/callback/route");
    await GET(new Request("https://app.example/api/account/link/github/callback?code=secret-code&state=opaque-state-that-is-long-enough-123"));
    expect(denialAudit).toHaveBeenCalledWith("github", "authentication_required", null);
    expect(JSON.stringify(denialAudit.mock.calls)).not.toMatch(/secret-code|opaque-state/u);
  });
  it("does not commit a link when the replacement session cookie cannot be planned", async () => {
    const complete = vi.fn(async () => ({ ok: true }));
    vi.doMock("@/features/auth/server/linking/completeLink", () => ({ completeAccountLink: complete }));
    vi.doMock("@/features/auth/server/linking/linkSessionRotation", () => ({
      planLinkSessionRotation: vi.fn(async () => { throw new Error("encode failed"); }),
    }));
    vi.resetModules();
    const { GET } = await import("@/app/api/account/link/github/callback/route");
    const response = await GET(new Request("https://app.example/api/account/link/github/callback?code=code&state=opaque-state-that-is-long-enough-123"));
    expect(response.headers.get("location")).toContain("link=failed");
    expect(complete).not.toHaveBeenCalled();
    expect(denialAudit).toHaveBeenCalledWith("github", "session_rotation_failed", "user-1");
  });

  it("audits unexpected callback/exchange failure separately", async () => {
    vi.doMock("@/features/auth/server/linking/completeLink", () => ({ completeAccountLink: vi.fn(async () => { throw new Error("db unavailable"); }) }));
    vi.doMock("@/features/auth/server/linking/linkSessionRotation", () => ({
      planLinkSessionRotation: vi.fn(async () => ({ cookieHeader: "replacement" })),
    }));
    vi.resetModules();
    const { GET } = await import("@/app/api/account/link/github/callback/route");
    const response = await GET(new Request("https://app.example/api/account/link/github/callback?code=secret-code&state=opaque-state-that-is-long-enough-123"));
    expect(response.headers.get("location")).toContain("link=failed");
    expect(denialAudit).toHaveBeenCalledWith("github", "callback_failed", "user-1");
    expect(JSON.stringify(denialAudit.mock.calls)).not.toContain("secret-code");
  });

  it("passes the current session generation to completion and redirects generically", async () => {
    const complete = vi.fn(async () => ({ ok: true }));
    vi.doMock("@/features/auth/server/linking/completeLink", () => ({ completeAccountLink: complete }));
    vi.doMock("@/features/auth/server/linking/linkSessionRotation", () => ({
      planLinkSessionRotation: vi.fn(async () => ({ token: "new-token", cookieHeader: "next-auth.session-token=new-token; Path=/; HttpOnly; SameSite=Lax" })),
    }));
    vi.resetModules();
    const { GET } = await import("@/app/api/account/link/github/callback/route");
    const response = await GET(new Request("https://app.example/api/account/link/github/callback?code=code&state=opaque-state-that-is-long-enough-123"));
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("https://app.example/dashboard/settings/accounts?link=success");
    expect(complete).toHaveBeenCalledWith(expect.objectContaining({
      provider: "github", code: "code", session: { userId: "user-1", sessionVersion: 4 },
    }));
    expect(response.headers.get("set-cookie")).toContain("new-token");
  });

  it("handles provider cancellation without normal-signin fallback", async () => {
    const complete = vi.fn(async () => ({ ok: false, reason: "provider_error" }));
    vi.doMock("@/features/auth/server/linking/completeLink", () => ({ completeAccountLink: complete }));
    vi.resetModules();
    const { GET } = await import("@/app/api/account/link/google/callback/route");
    const response = await GET(new Request("https://app.example/api/account/link/google/callback?error=access_denied&state=opaque-state-that-is-long-enough-123"));
    expect(response.headers.get("location")).toContain("link=failed");
  });
});
