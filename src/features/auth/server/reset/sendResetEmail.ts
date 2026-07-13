/**
 * Email sender for password reset flow
 *
 * Uses Resend for email delivery in production, with a redacted simulated
 * delivery event in development when Resend is not configured.
 *
 * @module auth/server/reset/sendResetEmail
 */

import { Resend } from "resend";
import { getPasswordResetEmailSubject } from "./templates/resetEmail.subject";
import { getPasswordResetEmailText } from "./templates/resetEmail.text";
import { resetEmailHtml } from "./templates/resetEmail.html";
import { env } from "@/lib/env";

// Resend client setup (mirrors verification email provider)
const resendKey = env.RESEND_API_KEY;
const from = env.RESEND_FROM || "Acme <onboarding@resend.dev>";
const resend = resendKey ? new Resend(resendKey) : null;

/**
 * Sends a password reset email to the user
 *
 * @param to - Recipient email address
 * @param resetUrl - Password reset link URL
 * @param name - Optional recipient name for greeting
 * @throws "EMAIL_SEND_FAILED" if Resend returns an error
 */
export async function sendPasswordResetEmail({
  to,
  resetUrl,
  name,
  ttlMinutes,
}: {
  to: string;
  resetUrl: string;
  name?: string;
  ttlMinutes: number;
}) {
  const subject = getPasswordResetEmailSubject();
  const text = getPasswordResetEmailText({ name, resetUrl, ttlMinutes });
  const html = resetEmailHtml({ name, resetUrl, ttlMinutes });

  // Development diagnostics contain stable event codes only.
  const isDevelopment = process.env.NODE_ENV === "development";
  const log = isDevelopment ? console.log : () => {};

  // Production: send via Resend
  if (resend) {
    const { error } = await resend.emails.send({
      from,
      to: Array.isArray(to) ? to : [to],
      subject,
      text,
      html,
    });

    if (error) {
      console.error("auth.password_reset_delivery_failed", {
        code: "EMAIL_SEND_FAILED",
      });
      throw new Error("EMAIL_SEND_FAILED");
    }

    log("auth.password_reset_delivery_succeeded", {
      code: "PASSWORD_RESET_EMAIL_SENT",
    });
    return;
  }

  // Development fallback preserves simulated delivery without exposing content.
  log("auth.password_reset_delivery_simulated", {
    code: "PASSWORD_RESET_EMAIL_SIMULATED",
  });
}
