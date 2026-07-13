// POST endpoint for refreshing elevation through a real MFA assertion.
import { handleAdminElevationRefresh } from "@/features/auth/server/adminMfa/adminMfaHttp";
export const POST = handleAdminElevationRefresh;
