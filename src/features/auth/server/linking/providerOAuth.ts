// Builds dedicated provider URLs and exchanges codes for provider subjects only.
import { z } from "zod";
import { env } from "@/lib/env";
import type { LinkableProvider } from "./linking.types";

const TokenSchema = z.object({ access_token: z.string().min(1) });
const GitHubSubjectSchema = z.object({ id: z.union([z.string(), z.number().int()]) });
const GoogleSubjectSchema = z.object({ sub: z.string().min(1) });

function config(provider: LinkableProvider) {
  const base = env.APP_URL ?? env.AUTH_URL ?? env.NEXTAUTH_URL;
  if (!base) throw new Error("ACCOUNT_LINK_URL_MISSING");
  const redirectUri = new URL(`/api/account/link/${provider}/callback`, base).toString();
  if (provider === "github") return {
    clientId: env.GITHUB_LINK_CLIENT_ID, clientSecret: env.GITHUB_LINK_CLIENT_SECRET, redirectUri,
    authorize: "https://github.com/login/oauth/authorize", token: "https://github.com/login/oauth/access_token",
  };
  return {
    clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET, redirectUri,
    authorize: "https://accounts.google.com/o/oauth2/v2/auth", token: "https://oauth2.googleapis.com/token",
  };
}

export function assertLinkProviderConfigured(provider: LinkableProvider): void {
  const value = config(provider);
  if (!value.clientId || !value.clientSecret) throw new Error("ACCOUNT_LINK_PROVIDER_DISABLED");
}

export function buildAuthorizationUrl(provider: LinkableProvider, state: string, challenge: string): string {
  const value = config(provider);
  if (!value.clientId || !value.clientSecret) throw new Error("ACCOUNT_LINK_PROVIDER_DISABLED");
  const url = new URL(value.authorize);
  url.searchParams.set("client_id", value.clientId);
  url.searchParams.set("redirect_uri", value.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("scope", provider === "github" ? "read:user" : "openid profile");
  return url.toString();
}

export async function fetchProviderSubject(provider: LinkableProvider, code: string, verifier: string): Promise<string> {
  const value = config(provider);
  if (!value.clientId || !value.clientSecret) throw new Error("ACCOUNT_LINK_PROVIDER_DISABLED");
  const response = await fetch(value.token, { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({
    client_id: value.clientId, client_secret: value.clientSecret, code, redirect_uri: value.redirectUri, code_verifier: verifier,
    ...(provider === "google" ? { grant_type: "authorization_code" } : {}),
  }) });
  if (!response.ok) throw new Error("ACCOUNT_LINK_TOKEN_FAILED");
  const token = TokenSchema.parse(await response.json());
  const subjectResponse = await fetch(provider === "github" ? "https://api.github.com/user" : "https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${token.access_token}`, Accept: "application/json" },
  });
  if (!subjectResponse.ok) throw new Error("ACCOUNT_LINK_SUBJECT_FAILED");
  const payload: unknown = await subjectResponse.json();
  return provider === "github" ? String(GitHubSubjectSchema.parse(payload).id) : GoogleSubjectSchema.parse(payload).sub;
}
