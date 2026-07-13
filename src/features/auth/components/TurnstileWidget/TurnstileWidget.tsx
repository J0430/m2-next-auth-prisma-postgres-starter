// Cloudflare Turnstile widget used only after the invite fragment is stripped.
"use client";

import Script from "next/script";
import type { TurnstileWidgetProps } from "./TurnstileWidget.types";
import { useTurnstileWidget } from "./useTurnstileWidget";

export function TurnstileWidget(props: TurnstileWidgetProps) {
  const { containerRef, markScriptReady } = useTurnstileWidget(props);
  return (
    <>
      <Script
        id="turnstile-api"
        src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
        nonce={props.nonce}
        strategy="afterInteractive"
        onLoad={markScriptReady}
      />
      <div ref={containerRef} aria-label="Security verification" />
    </>
  );
}
