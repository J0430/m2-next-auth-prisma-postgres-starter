// Verifies bootstrap target binding and secret transport through side-effect-free imports.
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalTarget, parseBootstrapArgs } from "../scripts/admin-mfa-bootstrap";

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

const loopback = canonicalTarget("postgresql://operator:secret@localhost:5432/auth_ci").url;

describe("admin MFA bootstrap target contract", () => {
  it("accepts an exact canonical loopback target with password and TOTP outside argv", () => {
    const parsed = parseBootstrapArgs([
      "activate", "--database-url", loopback, "--target-sha256", digest(loopback),
      "--email", "admin@example.test", "--capability", "admin:mfa:manage",
    ], { ADMIN_BOOTSTRAP_PASSWORD: "password", ADMIN_BOOTSTRAP_TOTP_CODE: "123456" });
    expect(parsed).toMatchObject({ databaseUrl: loopback, password: "password", code: "123456" });
  });

  it("rejects an inexact SHA binding", () => {
    expect(() => parseBootstrapArgs([
      "inventory", "--database-url", loopback, "--target-sha256", "0".repeat(64),
    ], {})).toThrow("Exact database target SHA-256 mismatch");
  });

  it.each([
    "postgresql://localhost/auth_ci?host=remote.example",
    "postgresql://localhost/auth_ci#remote",
  ])("rejects query or fragment routing in %s", (target) => {
    expect(() => canonicalTarget(target)).toThrow("canonical PostgreSQL URL");
  });

  it("rejects remote targets without explicit approval proof", () => {
    const remote = canonicalTarget("postgresql://operator:secret@db.example.test/auth").url;
    expect(() => parseBootstrapArgs([
      "inventory", "--database-url", remote, "--target-sha256", digest(remote),
    ], {})).toThrow("Remote bootstrap requires allow flag");
  });

  it("rejects a wrong remote approval challenge", () => {
    const remote = canonicalTarget("postgresql://operator:secret@db.example.test/auth").url;
    expect(() => parseBootstrapArgs([
      "inventory", "--database-url", remote, "--target-sha256", digest(remote),
      "--allow-remote-bootstrap", "--approval-challenge", "0".repeat(64),
    ], { ADMIN_BOOTSTRAP_APPROVAL_SECRET: "a".repeat(32) })).toThrow("approval challenge mismatch");
  });
});
