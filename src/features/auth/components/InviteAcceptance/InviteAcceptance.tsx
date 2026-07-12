// Renders the enumeration-safe invitation exchange progress state.
"use client";

import type { InviteAcceptanceProps } from "./InviteAcceptance.types";
import { useInviteAcceptance } from "./useInviteAcceptance";

export function InviteAcceptance({ csrfToken }: InviteAcceptanceProps) {
  const status = useInviteAcceptance(csrfToken);
  return (
    <main aria-live="polite" aria-busy="true" className="mx-auto max-w-lg p-8 text-center">
      <h1 className="text-2xl font-semibold">Preparing registration</h1>
      <p className="mt-3 text-gray-600">
        {status === "exchanging" ? "Checking your invitation…" : "Opening registration…"}
      </p>
    </main>
  );
}
