/**
 * NextAuth.js configuration for ManuMu Studio Authentication
 * 
 * Supports multiple authentication providers:
 * - Credentials (email/password) with email verification
 * - Google OAuth (conditional)
 * - GitHub OAuth (conditional)
 * 
 * Uses JWT strategy for stateless sessions that work with both
 * credentials and OAuth providers.
 * 
 * @module auth/server/options
 */

import type { NextAuthOptions } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { prisma } from "@/lib/prisma";
import { compare } from "bcryptjs";
import { z } from "zod";
import { googleProvider } from "@/features/auth/server/providers/google";
import { githubProvider } from "@/features/auth/server/providers/github";
import { env } from "@/lib/env";
import { buildAdmissionRateLimitChecks, getClientIp, rateLimit, type HeaderSource } from "@/lib/rateLimit";
import { allowSocialSignIn } from "@/features/auth/server/social/signInGate";
import { gatedPrismaAdapter } from "@/features/auth/server/social/gatedPrismaAdapter";
import { createGenericAdmissionFailure, monotonicNow, padAdmissionTiming } from "./admission";

const DUMMY_PASSWORD_HASH = "$2a$10$7EqJtq98hPqEX7fNZaFWoOhi.McZTpBdWnB7Rso8yX3i.Yx5x2m6e";

/**
 * Zod schema for validating credentials input
 */
const CredentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

async function consumeLoginLimiters(headers: HeaderSource, email: string): Promise<boolean> {
  const ip = getClientIp(headers);
  const checks = buildAdmissionRateLimitChecks({
    surface: "login",
    ip,
    accountIdentifier: email,
  });

  for (const check of checks) {
    const limitResult = await rateLimit(check.key, check.policy);
    if (!limitResult.success) return false;
  }

  return true;
}

function getSessionVersion(value: unknown): number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : 0;
}

function normalizeRole(role: string): "USER" | "ADMIN" {
  return role === "ADMIN" ? "ADMIN" : "USER";
}

/**
 * NextAuth.js configuration object
 * 
 * @type {NextAuthOptions}
 */
export const authOptions: NextAuthOptions = {
  adapter: gatedPrismaAdapter(prisma),

  // Use JWT strategy so credentials + OAuth both work without DB sessions
  session: { strategy: "jwt" },
  secret: env.NEXTAUTH_SECRET,

  // Route to custom branded sign-in page instead of NextAuth default
  pages: {
    signIn: "/",
  },

  providers: [
    Credentials({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      /**
       * Authorize function for credentials provider
       * 
       * Validates email/password credentials and enforces email verification.
       * 
       * @param {Object} credentials - User credentials (email, password)
       * @returns {Promise<Object|null>} User object if valid, null otherwise
       * @throws {Error} "EMAIL_NOT_VERIFIED" if email not verified
       */
      async authorize(credentials, req) {
        const startedAtMs = monotonicNow();
        const rejectWithParity = async () => {
          void createGenericAdmissionFailure(401);
          await padAdmissionTiming(startedAtMs);
          return null;
        };

        // Validate input format with Zod
        const parsed = CredentialsSchema.safeParse(credentials);
        if (!parsed.success) return rejectWithParity();

        const { email, password } = parsed.data;
        
        // Normalize email (lowercase, trimmed) and fetch user
        const normalizedEmail = email.trim().toLowerCase();

        const limitersPass = await consumeLoginLimiters(req?.headers ?? {}, normalizedEmail);
        if (!limitersPass) {
          throw new Error("RATE_LIMITED");
        }

        const user = await prisma.user.findUnique({
          where: { email: normalizedEmail },
          select: {
            id: true,
            name: true,
            email: true,
            passwordHash: true,
            hasPasswordCredential: true,
            role: true,
            emailVerified: true,
            origin: true,
            status: true,
            sessionVersion: true,
          },
        });
        
        const passwordHash = user?.passwordHash ?? DUMMY_PASSWORD_HASH;
        const passwordOk = await compare(password, passwordHash);
        const userCanAuthenticate =
          Boolean(user) &&
          user?.origin !== "PETSGRAM" &&
          user?.hasPasswordCredential === true &&
          user?.status === "ACTIVE" &&
          Boolean(user?.emailVerified) &&
          Boolean(user?.passwordHash) &&
          passwordOk;

        if (!userCanAuthenticate || !user) return rejectWithParity();

        return {
          id: user.id,
          name: user.name ?? undefined,
          email: user.email,
          role: normalizeRole(user.role),
          sessionVersion: user.sessionVersion,
        };
      },
    }),

    // Google OAuth provider (enabled only if env vars exist)
    ...(googleProvider() ? [googleProvider()!] : []),
    // GitHub OAuth provider (enabled only if env vars exist)
    ...(githubProvider() ? [githubProvider()!] : []),
  ],

  callbacks: {
    async signIn({ account }) {
      return allowSocialSignIn(account);
    },

    /**
     * JWT callback - called whenever a JWT is created or updated
     * 
     * Augments the JWT token with custom fields:
     * - uid: User ID (stored as 'uid' to avoid conflicts)
     * - role: User role (USER or ADMIN)
     * 
     * @param {Object} params - Callback parameters
     * @param {JWT} params.token - Current JWT token
     * @param {User} params.user - User object (only on initial sign-in)
     * @returns {Promise<JWT>} Augmented JWT token
     */
    async jwt({ token, user, account }) {
      // On initial sign-in, user object is provided
      if (user) {
        // Persist user ID and role in token for session hydration
        token.uid = user.id;
        token.role = user.role ?? "USER";
        token.name = user.name ?? token.name;
        token.email = user.email ?? token.email;
        token.sessionVersion = user.sessionVersion ?? 0;
        token.lastAuthAt = Date.now();
        token.authProvider = account?.provider;
      }
      if (token.uid) {
        const dbUser = await prisma.user.findUnique({
          where: { id: token.uid },
          select: { status: true, sessionVersion: true, role: true },
        });
        const tokenVersion = getSessionVersion(token.sessionVersion);
        if (!dbUser || dbUser.status !== "ACTIVE" || dbUser.sessionVersion !== tokenVersion) {
          token.authRejected = true;
          token.uid = undefined;
          token.role = undefined;
          token.sessionVersion = undefined;
          token.lastAuthAt = undefined;
          token.authProvider = undefined;
          return token;
        }
        token.authRejected = false;
        token.sessionVersion = dbUser.sessionVersion;
        token.role = normalizeRole(dbUser.role);
      }
      return token;
    },

    /**
     * Session callback - called whenever a session is accessed
     * 
     * Hydrates the session object with custom fields from the JWT token.
     * This makes user.id and user.role available in getServerSession() calls.
     * 
     * @param {Object} params - Callback parameters
     * @param {Session} params.session - Current session object
     * @param {JWT} params.token - JWT token with custom fields
     * @returns {Promise<Session>} Augmented session object
     */
    async session({ session, token }) {
      if (session.user) {
        if (token.authRejected || !token.uid) {
          session.user.id = "";
          session.user.role = undefined;
          session.user.sessionVersion = 0;
          session.lastAuthAt = undefined;
          session.authProvider = undefined;
          return session;
        }
        // Hydrate session with custom fields from JWT
        session.user.id = token.uid ?? "";
        session.user.role = token.role ?? "USER";
        session.user.sessionVersion = getSessionVersion(token.sessionVersion);
        session.lastAuthAt = typeof token.lastAuthAt === "number" ? token.lastAuthAt : undefined;
        session.authProvider = token.authProvider;
        session.user.name = token.name ?? session.user.name ?? undefined;
        session.user.email = token.email ?? session.user.email ?? undefined;
      }
      return session;
    },
  },
};
