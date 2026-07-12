// Security-focused unit coverage for the dedicated account-link OAuth protocol.
import { decode, encode } from "next-auth/jwt";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

vi.mock("@/lib/env", () => ({ env: {
  NEXTAUTH_SECRET: "nextauth-secret-that-is-long-enough-for-tests",
  ACCOUNT_LINK_PKCE_SECRET: "account-link-pkce-secret-long-enough-tests",
  APP_URL: "https://app.example",
  GITHUB_CLIENT_ID: "github-client", GITHUB_CLIENT_SECRET: "github-secret",
  GITHUB_LINK_CLIENT_ID: "github-link-client", GITHUB_LINK_CLIENT_SECRET: "github-link-secret",
  GOOGLE_CLIENT_ID: "google-client", GOOGLE_CLIENT_SECRET: "google-secret",
} }));

vi.mock("@/lib/prisma", () => ({ prisma: {
  user: { findUnique: vi.fn(async () => ({ status: "ACTIVE", sessionVersion: 5, role: "USER" })) },
} }));

describe("account-link provider protocol", () => {
  beforeEach(() => vi.restoreAllMocks());

  it.each(["github", "google"] as const)("uses exact dedicated %s redirect and S256 PKCE", async (provider) => {
    const { buildAuthorizationUrl, createS256Challenge, deriveLinkVerifier } = await import("@/features/auth/server/linking");
    const state = "opaque-state-that-is-never-persisted-raw";
    const verifier = deriveLinkVerifier(state, provider);
    const url = new URL(buildAuthorizationUrl(provider, state, createS256Challenge(verifier)));
    expect(url.searchParams.get("redirect_uri")).toBe(`https://app.example/api/account/link/${provider}/callback`);
    expect(url.searchParams.get("state")).toBe(state);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).not.toBe(verifier);
    if (provider === "github") expect(url.searchParams.get("client_id")).toBe("github-link-client");
  });

  it("reads GitHub's stable id and discards token/email", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: "raw-token", scope: "read:user" })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 42, email: "ignored@example.com" })));
    const { fetchProviderSubject } = await import("@/features/auth/server/linking");
    await expect(fetchProviderSubject("github", "code", "verifier")).resolves.toBe("42");
    expect(String(fetchMock.mock.calls[0]?.[1]?.body)).toContain("redirect_uri=https%3A%2F%2Fapp.example%2Fapi%2Faccount%2Flink%2Fgithub%2Fcallback");
  });

  it("reads Google's sub and ignores email", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: "raw-token" })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ sub: "google-subject", email: "ignored@example.com" })));
    const { fetchProviderSubject } = await import("@/features/auth/server/linking");
    await expect(fetchProviderSubject("google", "code", "verifier")).resolves.toBe("google-subject");
    expect(String(fetchMock.mock.calls[0]?.[1]?.body)).toContain("grant_type=authorization_code");
  });
});

describe("post-link session rotation", () => {
  it("mints the incremented generation without extending authentication freshness", async () => {
    const { planLinkSessionRotation } = await import("@/features/auth/server/linking/linkSessionRotation");
    const lastAuthAt = Date.now() - 120_000;
    const rotation = await planLinkSessionRotation({
      user: { id: "user-1", email: "owner@example.com", name: "Owner", role: "USER", sessionVersion: 4 },
      authProvider: "credentials",
      lastAuthAt,
    });
    const payload = await decode({
      token: rotation.token,
      secret: "nextauth-secret-that-is-long-enough-for-tests",
      salt: "",
    });
    expect(payload).toMatchObject({ uid: "user-1", sessionVersion: 5, lastAuthAt, authProvider: "credentials" });
    expect(rotation.cookieHeader).toContain("next-auth.session-token=");
    expect(rotation.cookieHeader).toContain("HttpOnly");
    expect(rotation.cookieHeader).toContain("SameSite=Lax");
    expect(rotation.cookieHeader).toContain("Secure");
  });

  it("makes the old JWT invalid while the replacement JWT remains valid", async () => {
    const session = {
      user: { id: "user-1", email: "owner@example.com", name: "Owner", role: "USER" as const, sessionVersion: 4 },
      authProvider: "credentials",
      lastAuthAt: Date.now() - 60_000,
    };
    const oldToken = await encode({
      token: { uid: session.user.id, sessionVersion: 4, role: "USER" },
      secret: "nextauth-secret-that-is-long-enough-for-tests",
      salt: "",
    });
    const { planLinkSessionRotation } = await import("@/features/auth/server/linking/linkSessionRotation");
    const replacement = await planLinkSessionRotation(session);
    const oldPayload = await decode({ token: oldToken, secret: "nextauth-secret-that-is-long-enough-for-tests", salt: "" });
    const newPayload = await decode({ token: replacement.token, secret: "nextauth-secret-that-is-long-enough-for-tests", salt: "" });
    const { authOptions } = await import("@/features/auth/server/options");
    const jwtCallback = authOptions.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT_CALLBACK_MISSING");
    const JwtResultSchema = z.object({
      authRejected: z.boolean(),
      uid: z.string().optional(),
      sessionVersion: z.number().optional(),
    });
    const rejected = JwtResultSchema.parse(await Reflect.apply(jwtCallback, undefined, [{ token: oldPayload ?? {} }]));
    const accepted = JwtResultSchema.parse(await Reflect.apply(jwtCallback, undefined, [{ token: newPayload ?? {} }]));
    expect(rejected.authRejected).toBe(true);
    expect(rejected.uid).toBeUndefined();
    expect(accepted).toMatchObject({ authRejected: false, uid: "user-1", sessionVersion: 5 });
  });
});

describe("credential session modality", () => {
  it("marks generated credential sessions fresh and versioned", async () => {
    const { createSessionToken } = await import("@/features/auth/server/createSessionToken");
    const token = await createSessionToken({ id: "user-1", email: "a@example.com", name: null, role: "USER", status: "ACTIVE", sessionVersion: 7 });
    const payload = await decode({ token, secret: "nextauth-secret-that-is-long-enough-for-tests" });
    expect(payload?.authProvider).toBe("credentials");
    expect(payload?.sessionVersion).toBe(7);
    expect(typeof payload?.lastAuthAt).toBe("number");
  });
});
