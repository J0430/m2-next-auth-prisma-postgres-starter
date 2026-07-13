// Drives the one-time fragment exchange without client persistence.
"use client";

import { useEffect, useState } from "react";

export function useInviteAcceptance(csrfToken: string): "exchanging" | "redirecting" {
  const [status, setStatus] = useState<"exchanging" | "redirecting">("exchanging");

  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.slice(1));
    const token = params.get("token") ?? "";
    const exchange = fetch("/api/invitations/exchange", {
      method: "POST",
      credentials: "same-origin",
      redirect: "manual",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, csrfToken }),
    });

    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
    const redirect = () => {
      setStatus("redirecting");
      window.location.replace("/register");
    };
    void exchange.then(redirect, redirect);
  }, [csrfToken]);

  return status;
}
