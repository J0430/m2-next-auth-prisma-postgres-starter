// Starts a dedicated OAuth account-link ceremony without invoking normal sign-in.
import { startLink } from "@/features/auth/server/linking/linkHttp";
export const POST = startLink;
