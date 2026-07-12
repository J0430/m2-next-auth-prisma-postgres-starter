// Derives a deterministic confidential PKCE verifier and its S256 challenge.
import crypto from "node:crypto";
import { env } from "@/lib/env";
import type { LinkableProvider } from "./linking.types";

export function deriveLinkVerifier(state: string, provider: LinkableProvider): string {
  const secret = env.ACCOUNT_LINK_PKCE_SECRET ?? env.NEXTAUTH_SECRET;
  return crypto.createHmac("sha256", secret).update(`account-link:${provider}:${state}`).digest("base64url");
}

export function createS256Challenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}
