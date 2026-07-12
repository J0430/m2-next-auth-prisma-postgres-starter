// src/features/auth/server/registration/registerAction.ts
// Server-action adapter for the shared invite-gated registration service.
"use server";

import { cookies, headers } from "next/headers";

import { env } from "@/lib/env";
import type { ActionResult } from "@/features/auth/server/actions/types";
import {
  REGISTRATION_CSRF_COOKIE_NAME,
  REGISTRATION_SESSION_COOKIE_NAME,
  registerWithInvite,
} from "./registerWithInvite";

function toOrigin(value: string | undefined): string {
  if (!value) return "";
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}

function resolveExpectedOrigin(requestHeaders: Headers): string {
  return (
    toOrigin(env.AUTH_URL) ||
    toOrigin(env.NEXTAUTH_URL) ||
    toOrigin(env.APP_URL) ||
    toOrigin(requestHeaders.get("origin") ?? undefined)
  );
}

export async function registerUser(formData: FormData): Promise<ActionResult> {
  const requestHeaders = await headers();
  const cookieStore = await cookies();
  const result = await registerWithInvite({
    formData,
    headers: requestHeaders,
    expectedOrigin: resolveExpectedOrigin(requestHeaders),
    registrationHandle: cookieStore.get(REGISTRATION_SESSION_COOKIE_NAME)?.value ?? null,
    csrfSessionToken: cookieStore.get(REGISTRATION_CSRF_COOKIE_NAME)?.value ?? null,
  });
  cookieStore.set(REGISTRATION_SESSION_COOKIE_NAME, "", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/register",
    maxAge: 0,
  });

  if (result.ok) {
    return {
      ok: true,
      meta: { requiresEmailVerification: true, email: result.email },
    };
  }

  return {
    ok: false,
    errors: { formErrors: [result.body.message] },
  };
}
