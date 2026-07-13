// Receives the dedicated Google account-link callback.
import { handleLinkCallback } from "@/features/auth/server/linking/callbackHttp";
export const GET = (request: Request) => handleLinkCallback(request, "google");
