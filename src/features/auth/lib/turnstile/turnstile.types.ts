// src/features/auth/lib/turnstile/turnstile.types.ts
// Shared Turnstile verification types for server-side admission checks.
export type TurnstileFetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export type VerifyTurnstileTokenInput = {
  token: string;
  remoteIp?: string | null;
  fetcher?: TurnstileFetcher;
  now?: Date;
  maxAgeSeconds?: number;
  signal?: AbortSignal;
};

export type TurnstileVerificationResult =
  | { ok: true }
  | {
      ok: false;
      supportId: string;
    };
