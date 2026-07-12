// Renders explicit connect/disconnect controls for supported OAuth providers.
"use client";

import type { ConnectedAccountsProps, LinkableProvider } from "./ConnectedAccounts.types";
import { useConnectedAccounts } from "./useConnectedAccounts";

const PROVIDERS = ["google", "github"] satisfies LinkableProvider[];
const LABELS = { google: "Google", github: "GitHub" } satisfies Record<LinkableProvider, string>;

export default function ConnectedAccounts({ providers, hasPassword }: ConnectedAccountsProps) {
  const state = useConnectedAccounts(providers);

  return (
    <div className="space-y-3">
      {state.feedback ? (
        <div role={state.feedback.tone === "error" ? "alert" : "status"} aria-live="polite"
          className={`p-3 rounded-lg text-sm ${state.feedback.tone === "error" ? "bg-red-50 text-red-600" : "bg-green-50 text-green-700"}`}>
          {state.feedback.message}
        </div>
      ) : null}
      {state.error ? (
        <div role="alert" className="p-3 rounded-lg bg-red-50 text-red-600 text-sm">
          <p>{state.error}</p>
          {state.reauthProvider ? (
            <button type="button" onClick={state.reauthenticate} className="mt-2 font-medium underline">
              Reauthenticate with {LABELS[state.reauthProvider]}
            </button>
          ) : null}
        </div>
      ) : null}
      {PROVIDERS.map((provider) => {
        const connected = state.connectedProviders.has(provider);
        const canDisconnect = hasPassword || providers.length > 1;
        return (
          <div key={provider} className="flex items-center justify-between p-4 rounded-lg border">
            <div>
              <p className="text-sm font-medium">{LABELS[provider]}</p>
              <p className="text-xs text-gray-500">{connected ? "Connected" : "Not connected"}</p>
            </div>
            {connected ? (
              <button type="button" disabled={!canDisconnect || state.isPending}
                onClick={() => state.disconnect(provider)} className="text-sm text-red-600 disabled:opacity-50">
                {state.activeProvider === provider ? "Disconnecting…" : "Disconnect"}
              </button>
            ) : (
              <button type="button" disabled={state.isPending}
                onClick={() => state.link(provider)} className="text-sm text-blue-600 disabled:opacity-50">
                {state.activeProvider === provider ? "Connecting…" : `Connect ${LABELS[provider]}`}
              </button>
            )}
          </div>
        );
      })}
      {hasPassword ? (
        <label className="block text-sm">
          Confirm current password before connecting
          <input type="password" autoComplete="current-password" value={state.currentPassword}
            onChange={(event) => state.setCurrentPassword(event.target.value)} className="mt-1 block w-full rounded border p-2" />
        </label>
      ) : null}
    </div>
  );
}
