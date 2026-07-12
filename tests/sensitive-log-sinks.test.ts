// Prevents credential, reset-token, recipient, and provider-error data from reaching console sinks.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();

const sources = {
  adminBootstrap: readFileSync(resolve(ROOT, "scripts/admin-mfa-bootstrap.ts"), "utf8"),
  jwks: readFileSync(resolve(ROOT, "src/app/jwks.json/route.ts"), "utf8"),
  redirectUpdater: readFileSync(resolve(ROOT, "scripts/update-lsa-redirect-uris.ts"), "utf8"),
  resendSmokeTest: readFileSync(resolve(ROOT, "scripts/resend-test.ts"), "utf8"),
  seedClient: readFileSync(resolve(ROOT, "scripts/seed-lsa-client.ts"), "utf8"),
  resetRequest: readFileSync(
    resolve(ROOT, "src/features/auth/server/actions/requestPasswordReset.ts"),
    "utf8",
  ),
  resetDelivery: readFileSync(
    resolve(ROOT, "src/features/auth/server/reset/sendResetEmail.ts"),
    "utf8",
  ),
};

describe("P034 sensitive console-sink inventory", () => {
  it("never writes the OAuth client secret to a console sink", () => {
    expect(sources.seedClient).not.toMatch(/console\.(?:log|error)[^\n]*(?:clientSecret|AUTH_CLIENT_SECRET)/);
    expect(sources.seedClient).not.toContain("randomBytes(32)");
    expect(sources.seedClient).toContain("LSA_CLIENT_SECRET");
  });

  it.each([
    ["seed client", sources.seedClient],
    ["password-reset request", sources.resetRequest],
    ["password-reset delivery", sources.resetDelivery],
    ["redirect updater", sources.redirectUpdater],
    ["JWKS route", sources.jwks],
  ])("does not pass caught error objects to the %s console sink", (_label, source) => {
    expect(source).not.toMatch(/console\.error\([^\n]*,\s*error\s*\)/);
  });

  it("does not emit provider result objects or unbounded error details", () => {
    expect(sources.resendSmokeTest).not.toMatch(/console\.(?:log|error)\(\s*\{[^}]*(?:data|error)/);
    expect(sources.adminBootstrap).not.toMatch(/console\.error\([^\n]*(?:error\.message|error\.stack)/);
  });

  it("does not write password-reset recipient, URL, message content, or provider ids", () => {
    expect(sources.resetDelivery).not.toMatch(
      /console\.(?:log|error)[^\n]*(?:\bto\b|resetUrl|\btext\b|\bhtml\b|data\?\.id|error)/,
    );
    expect(sources.resetDelivery).not.toContain("[DEV EMAIL]");
  });

  it("uses bounded stable-code metadata for reset failures", () => {
    expect(sources.resetRequest).toContain('code: "PASSWORD_RESET_PROCESSING_FAILED"');
    expect(sources.resetDelivery).toContain('code: "EMAIL_SEND_FAILED"');
  });
});
