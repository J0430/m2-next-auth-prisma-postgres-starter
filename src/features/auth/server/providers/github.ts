// Configures the optional GitHub OAuth provider for NextAuth.
import GitHubProvider from "next-auth/providers/github";

import { env } from "@/lib/env";

export function githubProvider() {
  const clientId = env.GITHUB_CLIENT_ID;
  const clientSecret = env.GITHUB_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;

  return GitHubProvider({
    clientId,
    clientSecret,
  });
}

/**
 * GitHub Developer Settings → OAuth Apps → New OAuth App
 *
 * Authorized redirect URIs:
 *   {APP_URL}/api/auth/callback/github
 *
 * Local:
 *   http://localhost:3000/api/auth/callback/github
 * Dedicated account-link callback (configure separately):
 *   {APP_URL}/api/account/link/github/callback
 */
