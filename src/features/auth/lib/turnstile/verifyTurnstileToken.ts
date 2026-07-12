// src/features/auth/lib/turnstile/verifyTurnstileToken.ts
// Verifies Cloudflare Turnstile tokens server-side and fails closed on every anomaly.
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { env } from "@/lib/env";
import type { TurnstileVerificationResult, VerifyTurnstileTokenInput } from "./turnstile.types";

const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const DEFAULT_MAX_AGE_SECONDS = 300;

const SiteverifyResponseSchema = z.object({
  success: z.boolean(),
  challenge_ts: z.string().optional(),
  hostname: z.string().optional(),
  action: z.string().optional(),
  "error-codes": z.array(z.string()).optional(),
});

const failClosed = (): TurnstileVerificationResult => ({
  ok: false,
  supportId: `turnstile_${randomUUID()}`,
});

const isFreshChallenge = (challengeTimestamp: string | undefined, now: Date, maxAgeSeconds: number) => {
  if (!challengeTimestamp) return false;
  const issuedAt = new Date(challengeTimestamp).getTime();
  if (!Number.isFinite(issuedAt)) return false;
  const ageMs = now.getTime() - issuedAt;
  return ageMs >= 0 && ageMs <= maxAgeSeconds * 1000;
};

export async function verifyTurnstileToken(
  input: VerifyTurnstileTokenInput
): Promise<TurnstileVerificationResult> {
  const secret = env.TURNSTILE_SECRET_KEY;
  const expectedHostname = env.TURNSTILE_EXPECTED_HOSTNAME;
  const expectedAction = env.TURNSTILE_EXPECTED_ACTION;

  if (!secret || !expectedHostname || !expectedAction) return failClosed();

  const form = new URLSearchParams({
    secret,
    response: input.token,
  });
  if (input.remoteIp) form.set("remoteip", input.remoteIp);

  try {
    const fetcher = input.fetcher ?? fetch;
    const response = await fetcher(TURNSTILE_SITEVERIFY_URL, {
      method: "POST",
      body: form,
      signal: input.signal,
    });
    const payload: unknown = await response.json();
    const parsed = SiteverifyResponseSchema.safeParse(payload);
    if (!response.ok || !parsed.success) return failClosed();

    const data = parsed.data;
    if (!data.success) return failClosed();
    if (data.hostname !== expectedHostname) return failClosed();
    if (data.action !== expectedAction) return failClosed();
    if (!isFreshChallenge(data.challenge_ts, input.now ?? new Date(), input.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS)) {
      return failClosed();
    }

    return { ok: true };
  } catch {
    return failClosed();
  }
}
