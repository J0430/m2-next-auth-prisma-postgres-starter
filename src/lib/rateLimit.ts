// src/lib/rateLimit.ts
// Distributed rate limiting backed by Upstash Redis, with an in-memory fallback
// for development/test only. Provides per-policy limiter instances and extracts
// the trusted client IP from platform-injected Vercel headers only.
import { isIP } from "node:net";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { env } from "@/lib/env";
import { atomicMemoryLimit, atomicRedisLimit } from "./rateLimitAtomic";
import { hashRateLimitIdentifier, normalizeRateLimitIdentifier } from "./rateLimitIdentifiers";
export { buildAdmissionRateLimitChecks } from "./rateLimitAdmission";
export { hashRateLimitIdentifier } from "./rateLimitIdentifiers";
export type {
  AdmissionRateLimitCheck,
  AdmissionRateLimitInput,
  AdmissionRateLimitScope,
  AdmissionRateLimitSurface,
} from "./rateLimitAdmission";

// --- Types ---

export type HeaderValue = string | string[] | undefined;
export type HeaderSource = Headers | Record<string, HeaderValue>;

export type RateLimitResult = {
  success: boolean;
  limit: number;
  remaining: number;
  reset: number;
};

type RateLimitKeyInput = {
  scope: string;
  ip?: string | null;
  email?: string | null;
};

export type RateLimitPolicy =
  | "auth-sensitive"
  | "signup-ip"
  | "email-delivery"
  | "oauth-token-ip"
  | "oauth-token-client"
  | "oauth-userinfo-ip"
  | "oauth-userinfo-token"
  | "registration-ip"
  | "registration-account"
  | "registration-invite"
  | "invite-redemption-ip"
  | "invite-redemption-invite"
  | "login-ip"
  | "login-account"
  | "password-reset-ip"
  | "password-reset-account"
  | "otp-verify-ip"
  | "otp-verify-account"
  | "fragment-exchange-ip"
  | "fragment-exchange-invite"
  | "exchange-write-global"
  | "admin-operation-ip"
  | "admin-operation-admin";

type PolicyConfig = {
  readonly limit: number;
  readonly windowMinutes: number;
};

// --- Policy limits map ---

const POLICY_LIMITS = {
  "auth-sensitive": {
    limit: env.RATE_LIMIT_MAX,
    windowMinutes: env.RATE_LIMIT_WINDOW_MINUTES,
  },
  "signup-ip": { limit: 5, windowMinutes: 60 * 24 },
  "email-delivery": { limit: 5, windowMinutes: 60 },
  "oauth-token-ip": { limit: 60, windowMinutes: 1 },
  "oauth-token-client": { limit: 120, windowMinutes: 1 },
  "oauth-userinfo-ip": { limit: 300, windowMinutes: 1 },
  "oauth-userinfo-token": { limit: 120, windowMinutes: 1 },
  "registration-ip": { limit: 5, windowMinutes: 60 },
  "registration-account": { limit: 5, windowMinutes: 60 },
  "registration-invite": { limit: 5, windowMinutes: 60 },
  "invite-redemption-ip": { limit: 10, windowMinutes: 60 },
  "invite-redemption-invite": { limit: 10, windowMinutes: 60 },
  "login-ip": { limit: env.RATE_LIMIT_MAX, windowMinutes: env.RATE_LIMIT_WINDOW_MINUTES },
  "login-account": { limit: env.RATE_LIMIT_MAX, windowMinutes: env.RATE_LIMIT_WINDOW_MINUTES },
  "password-reset-ip": { limit: 3, windowMinutes: 60 },
  "password-reset-account": { limit: 3, windowMinutes: 60 },
  "otp-verify-ip": { limit: 3, windowMinutes: 60 },
  "otp-verify-account": { limit: 3, windowMinutes: 60 },
  "fragment-exchange-ip": { limit: 30, windowMinutes: 10 },
  "fragment-exchange-invite": { limit: 10, windowMinutes: 10 },
  "exchange-write-global": { limit: 300, windowMinutes: 10 },
  "admin-operation-ip": { limit: 30, windowMinutes: 10 },
  "admin-operation-admin": { limit: 20, windowMinutes: 10 },
} as const satisfies Record<RateLimitPolicy, PolicyConfig>;

// --- Upstash per-policy limiter cache ---

const useUpstash = Boolean(env.UPSTASH_REDIS_REST_URL && env.UPSTASH_REDIS_REST_TOKEN);

function buildUpstashLimiter(policy: RateLimitPolicy, signal?: AbortSignal): Ratelimit {
  const { limit, windowMinutes } = POLICY_LIMITS[policy];
  const redis = signal
    ? new Redis({
        url: env.UPSTASH_REDIS_REST_URL,
        token: env.UPSTASH_REDIS_REST_TOKEN,
        signal,
      })
    : Redis.fromEnv();
  return new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(limit, `${windowMinutes} m`),
    analytics: true,
    prefix: `rl:${policy}`,
  });
}

const upstashLimiters: Map<RateLimitPolicy, Ratelimit> = useUpstash
  ? new Map(
      (Object.keys(POLICY_LIMITS) as RateLimitPolicy[]).map((policy) => [
        policy,
        buildUpstashLimiter(policy),
      ])
    )
  : new Map();

// --- In-memory fallback (dev/test only) ---

export const memoryStore = new Map<string, number[]>();

export function memoryLimit(
  identifier: string,
  policy: RateLimitPolicy = "auth-sensitive"
): RateLimitResult {
  const { limit, windowMinutes } = POLICY_LIMITS[policy];
  const storeKey = `${policy}:${identifier}`;
  const windowMs = windowMinutes * 60 * 1000;
  const now = Date.now();
  const timestamps = memoryStore.get(storeKey) ?? [];
  const recent = timestamps.filter((ts) => now - ts < windowMs);
  recent.push(now);
  memoryStore.set(storeKey, recent);

  const remaining = Math.max(0, limit - recent.length);
  return {
    success: recent.length <= limit,
    limit,
    remaining,
    reset: now + windowMs,
  };
}

// --- Key builder ---

export function buildRateLimitKey({ scope, ip, email }: RateLimitKeyInput): string {
  const safeIp = (ip ?? "unknown").trim() || "unknown";
  const normalizedEmail = normalizeRateLimitIdentifier(email).toLowerCase();
  const safeEmail = normalizedEmail === "unknown" ? "unknown" : hashRateLimitIdentifier(normalizedEmail);
  return `${scope}:ip:${safeIp}:account:${safeEmail}`;
}

// --- Header helper ---

export function getHeader(headers: HeaderSource, key: string): HeaderValue {
  if (headers instanceof Headers) {
    return headers.get(key) ?? undefined;
  }
  return headers[key];
}

// --- Client IP extraction ---

/**
 * Returns the validated real client IP.
 *
 * Vercel mode (env.VERCEL === "1"):
 *   1. First valid address from x-vercel-forwarded-for (Vercel-controlled, not spoofable)
 *   2. First valid address from x-real-ip (Vercel canonical single-IP)
 *   3. First valid address from x-forwarded-for (Vercel overwrites this to prevent spoofing)
 *
 * Non-Vercel production: forwarded headers are untrusted — returns null.
 *
 * Development/test: first valid x-forwarded-for address (for deterministic local tests).
 *
 * Every candidate is validated with node:net isIP before being returned.
 */
export function getClientIp(headers: HeaderSource): string | null {
  const isVercel = env.VERCEL === "1";
  const isProduction = process.env.NODE_ENV === "production";

  if (isVercel) {
    // 1. x-vercel-forwarded-for — Vercel's platform-controlled header (first = real client)
    const vercelXff = getHeader(headers, "x-vercel-forwarded-for");
    if (vercelXff) {
      const raw = Array.isArray(vercelXff) ? vercelXff[0] : vercelXff;
      if (raw) {
        const candidate = raw.split(",")[0]?.trim() ?? "";
        if (isIP(candidate) !== 0) return candidate;
      }
    }

    // 2. x-real-ip — Vercel's canonical single-IP header
    const realIp = getHeader(headers, "x-real-ip");
    if (realIp) {
      const raw = Array.isArray(realIp) ? realIp[0] : realIp;
      const candidate = (raw ?? "").trim();
      if (isIP(candidate) !== 0) return candidate;
    }

    // 3. x-forwarded-for — Vercel overwrites this, so first entry is trusted
    const xff = getHeader(headers, "x-forwarded-for");
    if (xff) {
      const raw = Array.isArray(xff) ? xff[0] : xff;
      if (raw) {
        const candidate = raw.split(",")[0]?.trim() ?? "";
        if (isIP(candidate) !== 0) return candidate;
      }
    }

    return null;
  }

  // Non-Vercel production: do not trust any forwarded headers
  if (isProduction) {
    return null;
  }

  // Development/test: allow first valid x-forwarded-for address
  const xff = getHeader(headers, "x-forwarded-for");
  if (xff) {
    const raw = Array.isArray(xff) ? xff[0] : xff;
    if (raw) {
      const candidate = raw.split(",")[0]?.trim() ?? "";
      if (isIP(candidate) !== 0) return candidate;
    }
  }

  return null;
}

// --- Rate limiter ---

export async function rateLimit(
  identifier: string,
  policy: RateLimitPolicy = "auth-sensitive",
  signal?: AbortSignal,
): Promise<RateLimitResult> {
  if (signal?.aborted) throw new DOMException("Rate limit aborted", "AbortError");
  if (process.env.NODE_ENV === "production" && !useUpstash) {
    throw new Error(
      "rateLimit: Upstash is not configured. UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN must be set in production."
    );
  }

  const limiter = upstashLimiters.get(policy);
  if (limiter) {
    return signal
      ? buildUpstashLimiter(policy, signal).limit(identifier)
      : limiter.limit(identifier);
  }

  // In-memory fallback — development and test only
  return memoryLimit(identifier, policy);
}

export async function rateLimitAll(
  checks: readonly { key: string; policy: RateLimitPolicy }[],
  signal?: AbortSignal,
): Promise<{ success: boolean }> {
  if (signal?.aborted) throw new DOMException("Rate limit aborted", "AbortError");
  const atomicChecks = checks.map((check) => {
    const config = POLICY_LIMITS[check.policy];
    return {
      storeKey: `${check.policy}:${check.key}`,
      limit: config.limit,
      windowMs: config.windowMinutes * 60 * 1000,
    };
  });
  const upstashUrl = env.UPSTASH_REDIS_REST_URL;
  const upstashToken = env.UPSTASH_REDIS_REST_TOKEN;
  if (upstashUrl && upstashToken) {
    const success = await atomicRedisLimit({
      checks: atomicChecks,
      url: upstashUrl,
      token: upstashToken,
      ...(signal ? { signal } : {}),
    });
    return { success };
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "rateLimitAll: Upstash is not configured. UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN must be set in production.",
    );
  }
  return { success: atomicMemoryLimit(atomicChecks, memoryStore) };
}
