// Server-authorized admin invitation console; service rechecks elevation and capability.
import { getServerSession } from "next-auth";
import { redirect } from "next/navigation";
import { AdminInvites } from "@/features/auth/components/AdminInvites";
import { createDefaultAdminInviteService } from "@/features/auth/server/adminInvites";
import { authOptions } from "@/features/auth/server/options";

export default async function AdminInvitesPage() {
  const session = await getServerSession(authOptions);
  if (!session?.user.id || session.user.role !== "ADMIN") redirect("/");
  const claim = { userId: session.user.id, role: session.user.role, sessionVersion: session.user.sessionVersion } as const;
  let invites;
  try { invites = await createDefaultAdminInviteService().list(claim); }
  catch { redirect("/"); }
  return <AdminInvites invites={invites} />;
}
