// Selects a trusted, already-linked provider for social-only reauthentication.
import type { ConnectedAccountsProps, LinkableProvider, LinkFeedback } from "./ConnectedAccounts.types";

export function parseLinkFeedback(value: string | null): LinkFeedback | null {
  if (value === "success") return { tone: "success", message: "Account connected successfully." };
  if (value === "failed") return { tone: "error", message: "Account connection failed. Please try again." };
  return null;
}

export function navigateToProvider(authorizationUrl: string): void {
  const anchor = document.createElement("a");
  anchor.href = authorizationUrl;
  anchor.rel = "noreferrer";
  anchor.referrerPolicy = "no-referrer";
  anchor.click();
}

export function selectReauthProvider(
  providers: ConnectedAccountsProps["providers"],
): LinkableProvider | null {
  const match = providers.find(({ provider }) => provider === "google" || provider === "github");
  return match?.provider === "google" || match?.provider === "github" ? match.provider : null;
}
