// Rotates invitations through the CSRF/rate/elevation protected boundary.
import { createDefaultAdminInviteHttpHandler } from "@/features/auth/server/adminInvites";
export function POST(request: Request): Promise<Response> {
  return createDefaultAdminInviteHttpHandler("resend")(request);
}
