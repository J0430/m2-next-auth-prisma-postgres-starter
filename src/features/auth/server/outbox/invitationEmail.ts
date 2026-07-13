// Invitation email delivery for Packet 02 outbox events.
import { z } from "zod";
import { env } from "@/lib/env";

const resendKey = env.RESEND_API_KEY;
const from = env.RESEND_FROM || "Acme <onboarding@resend.dev>";
const ResendResponseSchema = z.object({ id: z.string().min(1) });

export type SendInvitationEmailArgs = {
  to: string;
  inviteUrl: string;
  name?: string;
  signal?: AbortSignal;
};

function buildInvitationText(args: SendInvitationEmailArgs): string {
  const greeting = args.name ? `Hi ${args.name},` : "Hi,";
  return `${greeting}\n\nYou've been invited to create your account.\n\nAccept invitation: ${args.inviteUrl}\n\nIf you were not expecting this, you can ignore this email.`;
}

function buildInvitationHtml(args: SendInvitationEmailArgs): string {
  const greeting = args.name ? `Hi ${args.name},` : "Hi,";
  return `<p>${greeting}</p><p>You've been invited to create your account.</p><p><a href="${args.inviteUrl}">Accept invitation</a></p><p>If you were not expecting this, you can ignore this email.</p>`;
}

export async function sendInvitationEmail(args: SendInvitationEmailArgs): Promise<void> {
  if (!resendKey) {
    throw new Error("EMAIL_PROVIDER_NOT_CONFIGURED");
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST", signal: args.signal,
    headers: { Authorization: `Bearer ${resendKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from, to: [args.to], subject: "You're invited to ManuMu Studio",
      text: buildInvitationText(args), html: buildInvitationHtml(args),
    }),
  });
  const parsed = ResendResponseSchema.safeParse(await response.json().catch(() => null));
  if (!response.ok || !parsed.success) throw new Error("EMAIL_SEND_FAILED");
}
