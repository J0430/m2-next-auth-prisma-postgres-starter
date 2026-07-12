// POST endpoint for activating/asserting an owned admin TOTP factor.
import { handleAdminMfaVerify } from "@/features/auth/server/adminMfa/adminMfaHttp";
export const POST = handleAdminMfaVerify;

