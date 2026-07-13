// Handles CSRF acquisition and opaque admin invitation mutations.
"use client";
import { useCallback, useState } from "react";
import { z } from "zod";
import type { AdminInviteAction } from "./AdminInvites.types";

const CsrfSchema = z.object({ csrfToken: z.string().min(1) });
const MutationSchema = z.object({ ok: z.literal(true) });

export function useAdminInvites() {
  const [pending, setPending] = useState<AdminInviteAction | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const mutate = useCallback(async (action: AdminInviteAction, body: Record<string, string>) => {
    setPending(action); setMessage(null);
    try {
      const csrfResponse = await fetch("/api/admin/csrf", { credentials: "same-origin", cache: "no-store" });
      const csrf = CsrfSchema.parse(await csrfResponse.json());
      const response = await fetch(`/api/admin/invites/${action}`, {
        method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...body, csrfToken: csrf.csrfToken, requestId: crypto.randomUUID() }),
      });
      if (!response.ok) throw new Error("ADMIN_INVITE_FAILED");
      MutationSchema.parse(await response.json());
      setMessage("Request completed.");
      window.location.reload();
    } catch { setMessage("Unable to complete this request."); }
    finally { setPending(null); }
  }, []);
  return { pending, message, mutate };
}
