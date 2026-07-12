// Configures the optional Google OAuth provider for NextAuth.
import GoogleProvider from "next-auth/providers/google";

import { env } from "@/lib/env";

export function googleProvider() {
  const clientId = env.GOOGLE_CLIENT_ID;
  const clientSecret = env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;

  return GoogleProvider({
    clientId,
    clientSecret,
  });
}

/**
 * Google Console → APIs & Services → Credentials → OAuth 2.0 Client IDs
 *
 * Authorized redirect URIs:
 *   {APP_URL}/api/auth/callback/google
 *
 * Local:
 *   http://localhost:3000/api/auth/callback/google
 * Dedicated account-link callback (configure separately):
 *   {APP_URL}/api/account/link/google/callback
 */
