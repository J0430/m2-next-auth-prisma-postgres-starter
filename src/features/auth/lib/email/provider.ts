/**
 * Email provider for sending verification emails
 * 
 * Uses Resend for fail-closed email delivery.
 * 
 * @module auth/lib/email/provider
 */

import { z } from "zod";
import { getVerificationEmailSubject } from "@/features/auth/server/verify/templates/verifyEmail.subject";
import { getVerificationEmailText } from "@/features/auth/server/verify/templates/verifyEmail.text";
import { verifyEmailHtml } from "@/features/auth/server/verify/templates/verifyEmail.html";
import { env } from "@/lib/env";

// Resend API key (required by production environment validation)
const resendKey = env.RESEND_API_KEY;
// Sender email address (defaults to Resend onboarding address)
const from = env.RESEND_FROM || "Acme <onboarding@resend.dev>";
// Validate the direct Resend API response without exposing provider payloads.
const ResendResponseSchema = z.object({ id: z.string().min(1) });

type SendArgs = { to: string; code: string; name?: string; signal?: AbortSignal };

/**
 * Sends a verification email to the user
 * 
 * Sends both HTML and plain text versions of the verification email.
 * Fails closed when Resend is not configured.
 * 
 * @param {SendArgs} args - Email parameters
 * @param {string} args.to - Recipient email address
 * @param {string} args.code - 6-digit verification code
 * @param {string} [args.name] - Optional recipient name
 * @throws {Error} "EMAIL_SEND_FAILED" if Resend returns an error
 * 
 * @example
 * ```ts
 * await sendVerificationEmail({
 *   to: "user@example.com",
 *   code: "123456",
 *   name: "John Doe"
 * });
 * ```
 */
export async function sendVerificationEmail({ to, code, name, signal }: SendArgs) {
  // Generate email content (subject, plain text, HTML)
  const subject = getVerificationEmailSubject();
  const text = getVerificationEmailText({ name, code });
  const html = verifyEmailHtml({ name, code });

  // Environment-aware logging (only in development)
  const isDevelopment = process.env.NODE_ENV === 'development';
  const log = isDevelopment ? console.log : () => {};
  const logError = isDevelopment ? console.error : () => {};

  // Production: Send via Resend if configured
  if (resendKey) {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST", signal,
      headers: { Authorization: `Bearer ${resendKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to: [to], subject, text, html }),
    });
    const parsed = ResendResponseSchema.safeParse(await response.json().catch(() => null));
    if (!response.ok || !parsed.success) {
      logError("EMAIL_SEND_FAILED");
      throw new Error("EMAIL_SEND_FAILED");
    }
    log("[Resend] sent id:", parsed.data.id);
    return;
  }

  throw new Error("EMAIL_PROVIDER_NOT_CONFIGURED");
}
