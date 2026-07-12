// Issues the authenticated double-submit token for account-link initiation.
import { issueLinkCsrf } from "@/features/auth/server/linking/linkHttp";
export const GET = issueLinkCsrf;
