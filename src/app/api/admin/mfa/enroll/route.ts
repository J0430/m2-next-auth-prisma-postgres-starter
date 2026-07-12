// POST endpoint for provisioning a PENDING admin TOTP factor.
import { handleAdminMfaEnroll } from "@/features/auth/server/adminMfa/adminMfaHttp";
export const POST = handleAdminMfaEnroll;

