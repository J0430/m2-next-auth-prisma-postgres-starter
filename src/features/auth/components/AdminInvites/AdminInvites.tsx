// Renders the least-privilege invitation issue/list/revoke/resend console.
"use client";
import { useState } from "react";
import type { AdminInvitesProps } from "./AdminInvites.types";
import { useAdminInvites } from "./useAdminInvites";

export default function AdminInvites({ invites }: AdminInvitesProps) {
  const [email, setEmail] = useState("");
  const [reason, setReason] = useState("");
  const { pending, message, mutate } = useAdminInvites();
  return (
    <div className="mx-auto max-w-4xl space-y-8 p-6">
      <section className="rounded-lg border bg-white p-6 shadow-sm">
        <h1 className="text-2xl font-semibold">Invitation administration</h1>
        <p className="mt-2 text-sm text-gray-600">Every action requires a recent authenticator assertion and is audited.</p>
        <form className="mt-6 grid gap-4" onSubmit={(event) => { event.preventDefault(); void mutate("issue", { email, reason }); }}>
          <label className="grid gap-1 text-sm">Invitee email
            <input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} className="rounded border p-2" />
          </label>
          <label className="grid gap-1 text-sm">Reason
            <textarea required minLength={3} maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} className="rounded border p-2" />
          </label>
          <button disabled={pending !== null} className="w-fit rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-50">Issue invitation</button>
        </form>
        {message ? <p role="status" className="mt-4 text-sm">{message}</p> : null}
      </section>
      <section className="rounded-lg border bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold">Recent invitations</h2>
        <ul className="mt-4 divide-y">
          {invites.map((invite) => (
            <li key={invite.id} className="flex flex-wrap items-center justify-between gap-4 py-4">
              <div><p className="font-medium">{invite.maskedEmail ?? "Unbound"}</p><p className="text-xs text-gray-500">{invite.status} · expires {invite.expiresAt.toLocaleDateString()}</p></div>
              <div className="flex gap-2">
                <button disabled={pending !== null || invite.status !== "ISSUED"} onClick={() => void mutate("resend", { inviteId: invite.id, reason: "Administrator requested redelivery" })} className="rounded border px-3 py-1 text-sm disabled:opacity-50">Resend</button>
                <button disabled={pending !== null || invite.status !== "ISSUED"} onClick={() => void mutate("revoke", { inviteId: invite.id, reason: "Administrator revoked access" })} className="rounded border border-red-300 px-3 py-1 text-sm text-red-700 disabled:opacity-50">Revoke</button>
              </div>
            </li>
          ))}
          {invites.length === 0 ? <li className="py-6 text-sm text-gray-500">No invitations found.</li> : null}
        </ul>
      </section>
    </div>
  );
}
