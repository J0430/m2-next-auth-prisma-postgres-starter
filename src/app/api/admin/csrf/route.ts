// Authenticated endpoint for issuing the admin mutation CSRF token.
import { handleAdminCsrfIssue } from "@/features/auth/server/adminMfa/adminCsrfHttp";

export const GET = handleAdminCsrfIssue;
