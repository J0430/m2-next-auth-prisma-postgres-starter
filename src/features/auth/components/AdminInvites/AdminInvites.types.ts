// Props and action types for the admin invitation console.
import type { AdminInviteListItem } from "../../server/adminInvites";

export interface AdminInvitesProps {
  invites: AdminInviteListItem[];
}

export type AdminInviteAction = "issue" | "revoke" | "resend";
