// Verifies the shared admin CSRF token is issuable and consumable fail-closed.
import { describe, expect, it } from "vitest";

import { issueCsrfToken, validateCsrf } from "@/features/auth/server/admission";

describe("admin CSRF issuance", () => {
  it("issues a high-entropy token accepted only with the configured canonical origin", () => {
    const token = issueCsrfToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(validateCsrf({
      headers: new Headers({ origin: "https://auth.example.test", "sec-fetch-site": "same-origin" }),
      expectedOrigin: "https://auth.example.test",
      sessionToken: token,
      submittedToken: token,
    })).toEqual({ ok: true });
  });

  it.each([
    [null, "token", "https://auth.example.test", "same-origin"],
    ["token", "other", "https://auth.example.test", "same-origin"],
    ["token", "token", "https://evil.example", "same-origin"],
    ["token", "token", "https://auth.example.test", "cross-site"],
  ])("fails closed for missing, mismatch, or cross-site inputs", (sessionToken, submittedToken, origin, site) => {
    expect(validateCsrf({
      headers: new Headers({ origin, "sec-fetch-site": site }),
      expectedOrigin: "https://auth.example.test",
      sessionToken,
      submittedToken,
    }).ok).toBe(false);
  });
});
