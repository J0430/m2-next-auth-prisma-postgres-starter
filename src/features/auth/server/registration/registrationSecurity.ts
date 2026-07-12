// Builds route-specific CSPs and defense-in-depth headers for registration.
export type RegistrationSecurityProfile = "invite" | "register";

const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";

export function buildRegistrationCsp(
  profile: RegistrationSecurityProfile,
  nonce: string,
): string {
  const directives = [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "img-src 'self' data:",
    "style-src 'self' 'unsafe-inline'",
  ];

  if (profile === "invite") {
    directives.push(`script-src 'self' 'nonce-${nonce}'`, "connect-src 'self'");
  } else {
    directives.push(
      `script-src 'self' 'nonce-${nonce}' ${TURNSTILE_ORIGIN}`,
      `frame-src ${TURNSTILE_ORIGIN}`,
      `connect-src 'self' ${TURNSTILE_ORIGIN}`,
    );
  }
  return directives.join("; ");
}

export function applyRegistrationSecurityHeaders(
  headers: Headers,
  profile: RegistrationSecurityProfile,
  nonce: string,
): void {
  headers.set("Content-Security-Policy", buildRegistrationCsp(profile, nonce));
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Cache-Control", "no-store");
}
