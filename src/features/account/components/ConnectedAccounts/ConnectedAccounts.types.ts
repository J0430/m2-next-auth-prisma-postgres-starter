// Type definitions for the connected-account management component.

export type LinkableProvider = "google" | "github";
export type LinkFeedback = { tone: "success" | "error"; message: string };

export interface ConnectedAccountsProps {
  providers: Array<{ provider: string; providerAccountId: string }>;
  hasPassword: boolean;
}
