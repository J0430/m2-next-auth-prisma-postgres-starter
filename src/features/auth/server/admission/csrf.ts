// src/features/auth/server/admission/csrf.ts
// Validates Origin, Sec-Fetch-Site, and per-session CSRF tokens for state-changing posts.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { AdmissionDecision, CsrfValidationInput } from "./admission.types";
import { createGenericAdmissionFailure } from "./enumerationParity";

const SAME_SITE_FETCH_VALUES = new Set(["same-origin", "same-site"]);
const MISSING_TOKEN_SENTINEL = "__missing_csrf_token__";

export function issueCsrfToken(): string {
  return randomBytes(32).toString("base64url");
}

const headerToString = (value: string | string[] | undefined) => {
  if (Array.isArray(value)) return value[0] ?? "";
  return value ?? "";
};

const getHeader = (headers: CsrfValidationInput["headers"], key: string) => {
  if (headers instanceof Headers) return headers.get(key) ?? undefined;
  return headers[key];
};

const normalizeOrigin = (value: string) => {
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
};

const tokenDigest = (token: string | null) =>
  createHash("sha256").update(token ?? MISSING_TOKEN_SENTINEL, "utf8").digest();

const tokensMatch = (sessionToken: string | null, submittedToken: string | null) => {
  const sessionDigest = tokenDigest(sessionToken);
  const submittedDigest = tokenDigest(submittedToken);
  return Boolean(sessionToken && submittedToken && timingSafeEqual(sessionDigest, submittedDigest));
};

export function validateCsrf(input: CsrfValidationInput): AdmissionDecision {
  const requestOrigin = normalizeOrigin(headerToString(getHeader(input.headers, "origin")));
  const expectedOrigin = normalizeOrigin(input.expectedOrigin);
  const secFetchSite = headerToString(getHeader(input.headers, "sec-fetch-site")).toLowerCase();

  if (!requestOrigin || !expectedOrigin || requestOrigin !== expectedOrigin) {
    return createGenericAdmissionFailure();
  }
  if (!SAME_SITE_FETCH_VALUES.has(secFetchSite)) {
    return createGenericAdmissionFailure();
  }
  if (!tokensMatch(input.sessionToken, input.submittedToken)) {
    return createGenericAdmissionFailure();
  }

  return { ok: true };
}
