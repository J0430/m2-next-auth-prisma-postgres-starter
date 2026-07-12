/**
 * NextAuth.js type augmentations for ManuMu Studio Authentication
 * 
 * Extends the default NextAuth Session and User types to include
 * custom fields: id and role.
 */

import "next-auth";
import "next-auth/jwt";

declare module "next-auth" {
  interface Session {
    lastAuthAt?: number;
    authProvider?: string;
    user: {
      id: string;
      role?: "USER" | "ADMIN";
      sessionVersion: number;
    } & DefaultSession["user"];
  }

  interface User {
    id: string;
    role?: "USER" | "ADMIN";
    sessionVersion?: number;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    uid?: string;
    role?: "USER" | "ADMIN";
    sessionVersion?: number;
    authRejected?: boolean;
    lastAuthAt?: number;
    authProvider?: string;
  }
}
