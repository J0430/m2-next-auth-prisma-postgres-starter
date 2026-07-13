// Receives the dedicated GitHub account-link callback.
import { handleLinkCallback } from "@/features/auth/server/linking/callbackHttp";
export const GET = (request: Request) => handleLinkCallback(request, "github");
