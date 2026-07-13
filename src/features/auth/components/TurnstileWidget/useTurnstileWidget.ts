// Mounts and resets a Turnstile widget while keeping its token in React state only.
"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { TurnstileApi, TurnstileWidgetProps } from "./TurnstileWidget.types";

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

export function useTurnstileWidget(props: TurnstileWidgetProps) {
  const { onToken, resetKey, siteKey } = props;
  const containerRef = useRef<HTMLDivElement>(null);
  const widgetIdRef = useRef<string | null>(null);
  const [scriptReady, setScriptReady] = useState(false);

  const mount = useCallback(() => {
    if (!scriptReady || !containerRef.current || !window.turnstile || widgetIdRef.current) return;
    widgetIdRef.current = window.turnstile.render(containerRef.current, {
      sitekey: siteKey,
      action: "gated-registration",
      callback: onToken,
      "expired-callback": () => onToken(""),
      "error-callback": () => onToken(""),
    });
  }, [onToken, scriptReady, siteKey]);

  useEffect(mount, [mount]);
  useEffect(() => {
    if (widgetIdRef.current && window.turnstile) {
      window.turnstile.reset(widgetIdRef.current);
      onToken("");
    }
  }, [onToken, resetKey]);

  return { containerRef, markScriptReady: () => setScriptReady(true) };
}
