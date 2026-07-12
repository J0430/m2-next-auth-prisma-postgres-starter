// Public types for the Cloudflare Turnstile registration widget.
export interface TurnstileWidgetProps {
  siteKey: string;
  nonce: string;
  resetKey: number;
  onToken(token: string): void;
}

export interface TurnstileApi {
  render(container: HTMLElement, options: {
    sitekey: string;
    action: string;
    callback(token: string): void;
    "expired-callback"(): void;
    "error-callback"(): void;
  }): string;
  reset(widgetId: string): void;
}
