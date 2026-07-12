// Shared contracts for the dedicated explicit OAuth account-link ceremony.
import { z } from "zod";

export const LINK_REAUTH_FRESHNESS_MS = 300_000;
export const LINK_INTENT_TTL_MS = LINK_REAUTH_FRESHNESS_MS;
export const LINK_CSRF_COOKIE = "account_link_csrf";
export const LinkableProviderSchema = z.enum(["google", "github"]);
export type LinkableProvider = z.infer<typeof LinkableProviderSchema>;

export const LinkStartBodySchema = z.object({
  provider: LinkableProviderSchema,
  currentPassword: z.string().min(1).max(128).nullable(),
  csrfToken: z.string().min(32).max(128),
});

export const LinkCallbackSchema = z.object({
  code: z.string().min(1).optional(),
  state: z.string().min(32).max(512),
  error: z.string().min(1).max(128).optional(),
});

export type LinkInitiationDenialReason =
  | "user_not_active" | "reauth_failed" | "reauth_stale"
  | "provider_already_connected" | "intent_persistence_failed"
  | "provider_unavailable" | "authorization_url_failed"
  | "malformed_request" | "authentication_required" | "csrf_failed"
  | "origin_failed" | "rate_limited";

export type CreateLinkIntentResult =
  | { ok: true; rawState: string; expiresAt: Date }
  | { ok: false; reason: LinkInitiationDenialReason };

export type LinkDenialReason =
  | "unknown_intent" | "expired_intent" | "replayed_intent"
  | "provider_mismatch" | "session_mismatch" | "intent_user_not_active"
  | "provider_already_linked" | "provider_error" | "link_transaction_failed"
  | "malformed_callback" | "authentication_required"
  | "session_rotation_failed" | "callback_failed";
