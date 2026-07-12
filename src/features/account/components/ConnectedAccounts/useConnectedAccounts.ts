// Coordinates explicit provider linking and safe provider disconnection.
"use client";

import { useEffect, useMemo, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { signIn } from "next-auth/react";
import { z } from "zod";
import { disconnectProvider } from "@/features/account/server/actions/disconnectProvider";
import type { ConnectedAccountsProps, LinkableProvider, LinkFeedback } from "./ConnectedAccounts.types";
import { navigateToProvider, parseLinkFeedback, selectReauthProvider } from "./ConnectedAccounts.helpers";

const CsrfResponseSchema = z.object({ csrfToken: z.string().min(32) });
const LinkStartResponseSchema = z.union([
  z.object({ authorizationUrl: z.string().url() }),
  z.object({ error: z.string(), reason: z.literal("reauth_stale").optional() }),
]);

export function useConnectedAccounts(providers: ConnectedAccountsProps["providers"]) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [activeProvider, setActiveProvider] = useState<LinkableProvider | null>(null);
  const [reauthProvider, setReauthProvider] = useState<LinkableProvider | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [feedback, setFeedback] = useState<LinkFeedback | null>(null);
  const connectedProviders = useMemo(() => new Set(providers.map(({ provider }) => provider)), [providers]);

  useEffect(() => {
    const url = new URL(window.location.href);
    const callbackFeedback = parseLinkFeedback(url.searchParams.get("link"));
    if (!callbackFeedback) return;
    setFeedback(callbackFeedback);
    url.searchParams.delete("link");
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }, []);

  const run = (provider: LinkableProvider, action: () => Promise<void>) => {
    setError(null);
    setActiveProvider(provider);
    startTransition(async () => {
      try { await action(); } finally { setActiveProvider(null); }
    });
  };

  const disconnect = (provider: LinkableProvider) => run(provider, async () => {
    const data = new FormData();
    data.set("provider", provider);
    const result = await disconnectProvider(data);
    if (!result.ok) setError(result.errors.formErrors?.[0] ?? "Request failed.");
    else router.refresh();
  });

  const link = (provider: LinkableProvider) => run(provider, async () => {
    setReauthProvider(null);
    const csrfResponse = await fetch("/api/account/link/csrf", { credentials: "same-origin" });
    const csrfPayload = CsrfResponseSchema.safeParse(await csrfResponse.json());
    if (!csrfResponse.ok || !csrfPayload.success) {
      setError("Verification failed.");
      return;
    }
    const response = await fetch("/api/account/link/start", {
      method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, currentPassword: currentPassword || null, csrfToken: csrfPayload.data.csrfToken }),
    });
    const payload = LinkStartResponseSchema.safeParse(await response.json());
    if (!payload.success || !response.ok || !("authorizationUrl" in payload.data)) {
      const linkedProvider = payload.success && "reason" in payload.data && payload.data.reason === "reauth_stale"
        ? selectReauthProvider(providers) : null;
      setReauthProvider(linkedProvider);
      setError(linkedProvider ? "Reauthenticate with your connected provider before linking another account." : "Verification failed.");
      return;
    }
    navigateToProvider(payload.data.authorizationUrl);
  });

  const reauthenticate = async () => {
    if (!reauthProvider) return;
    await signIn(reauthProvider, { callbackUrl: "/dashboard/settings/accounts" });
  };

  return { activeProvider, connectedProviders, currentPassword, disconnect, error, feedback, isPending, link,
    reauthenticate, reauthProvider, setCurrentPassword };
}
