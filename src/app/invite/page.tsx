// Side-effect-free invitation landing page; the browser exchanges its fragment.
import { headers } from "next/headers";

import { InviteAcceptance } from "@/features/auth/components/InviteAcceptance";

export const dynamic = "force-dynamic";

export default async function InvitePage() {
  const requestHeaders = await headers();
  const csrfToken = requestHeaders.get("x-registration-csrf") ?? "";
  return (
    <>
      <InviteAcceptance csrfToken={csrfToken} />
      <noscript>
        <main className="mx-auto max-w-lg p-8 text-center">
          <h1 className="text-2xl font-semibold">JavaScript required</h1>
          <p className="mt-3">JavaScript is required to accept this invitation.</p>
        </main>
      </noscript>
    </>
  );
}
