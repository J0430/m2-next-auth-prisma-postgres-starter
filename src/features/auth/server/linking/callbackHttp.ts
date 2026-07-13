// Handles dedicated provider callbacks and never falls back to normal sign-in.
import { getServerSession } from "next-auth";
import { authOptions } from "@/features/auth/server/options";
import { env } from "@/lib/env";
import { completeAccountLink } from "./completeLink";
import { planLinkSessionRotation } from "./linkSessionRotation";
import { LinkCallbackSchema, type LinkableProvider } from "./linking.types";
import { recordLinkDenied } from "./audit";

function destination(success: boolean, cookieHeader?: string): Response {
  const base = env.APP_URL ?? env.AUTH_URL ?? env.NEXTAUTH_URL ?? "http://localhost:3000";
  const url = new URL("/dashboard/settings/accounts", base);
  url.searchParams.set("link", success ? "success" : "failed");
  const headers = new Headers({ Location: url.toString(), "Referrer-Policy": "no-referrer" });
  if (cookieHeader) headers.set("set-cookie", cookieHeader);
  return new Response(null, { status: 303, headers });
}

export async function handleLinkCallback(request: Request, provider: LinkableProvider): Promise<Response> {
  const parsed = LinkCallbackSchema.safeParse(Object.fromEntries(new URL(request.url).searchParams));
  if (!parsed.success) {
    await recordLinkDenied(provider, "malformed_callback", null);
    return destination(false);
  }
  const session = await getServerSession(authOptions);
  if (!session?.user.id) {
    await recordLinkDenied(provider, "authentication_required", null);
    return destination(false);
  }
  const current = session?.user.id ? { userId: session.user.id, sessionVersion: session.user.sessionVersion } : null;
  let rotation: Awaited<ReturnType<typeof planLinkSessionRotation>> | null = null;
  if (session?.user.id) {
    try { rotation = await planLinkSessionRotation(session); }
    catch {
      await recordLinkDenied(provider, "session_rotation_failed", session.user.id);
      return destination(false);
    }
  }
  let outcome: { ok: boolean };
  try {
    outcome = await completeAccountLink({
      provider, state: parsed.data.state, code: parsed.data.code ?? null,
      providerError: parsed.data.error !== undefined, session: current,
    });
  } catch {
    await recordLinkDenied(provider, "callback_failed", session.user.id);
    outcome = { ok: false };
  }
  return destination(outcome.ok, outcome.ok ? rotation?.cookieHeader : undefined);
}
