// Verifies production startup invokes stored-key readiness without importing a database.
import { describe, expect, it, vi } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { runAdminMfaStartupReadiness } from "@/startup/adminMfaReadiness";
import { registerAdminMfaInstrumentation } from "@/instrumentation-node";

const SOURCE_ROOT = resolve(import.meta.dirname, "../src");

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return /\.(?:ts|tsx)$/.test(entry.name) ? [path] : [];
  });
}

describe("admin MFA startup readiness", () => {
  it("loads the Node startup implementation only from the Node instrumentation runtime", () => {
    const source = readFileSync(resolve(SOURCE_ROOT, "instrumentation.ts"), "utf8");
    const nodeSource = readFileSync(resolve(SOURCE_ROOT, "instrumentation-node.ts"), "utf8");
    expect(source).toContain('process.env.NEXT_RUNTIME === "nodejs"');
    expect(source).toContain('import("./instrumentation-node")');
    expect(source).not.toContain("secretCrypto");
    expect(source).not.toContain("@/lib/prisma");
    expect(nodeSource).toContain('import("@/features/auth/server/adminMfa/secretCrypto")');
    expect(nodeSource).toContain('import("@/lib/prisma")');
  });

  it("keeps secret cryptography out of client entry points", () => {
    const clientSources = sourceFiles(SOURCE_ROOT)
      .map((path) => readFileSync(path, "utf8"))
      .filter((source) => /^\s*["']use client["'];/m.test(source));
    expect(clientSources.some((source) => source.includes("secretCrypto"))).toBe(false);
    expect(clientSources.some((source) => source.includes("instrumentation-node"))).toBe(false);
  });

  it("loads and invokes database readiness only for production Node registration", async () => {
    const validate = vi.fn();
    const loader = vi.fn().mockResolvedValue(validate);
    await registerAdminMfaInstrumentation("nodejs", "production", loader);
    expect(loader).toHaveBeenCalledOnce();
    expect(validate).toHaveBeenCalledOnce();
  });

  it.each([["edge", "production"], ["nodejs", "test"]])(
    "does not load database modules for %s/%s registration",
    async (runtime, nodeEnv) => {
      const loader = vi.fn();
      await registerAdminMfaInstrumentation(runtime, nodeEnv, loader);
      expect(loader).not.toHaveBeenCalled();
    },
  );
  it("fails closed by awaiting validation in the production Node runtime", async () => {
    const validate = vi.fn().mockRejectedValue(new Error("unknown stored key"));
    await expect(runAdminMfaStartupReadiness({ runtime: "nodejs", nodeEnv: "production", validate }))
      .rejects.toThrow("unknown stored key");
    expect(validate).toHaveBeenCalledOnce();
  });

  it.each([
    ["edge", "production"],
    ["nodejs", "test"],
  ])("does not touch the database for runtime %s in %s", async (runtime, nodeEnv) => {
    const validate = vi.fn();
    await runAdminMfaStartupReadiness({ runtime, nodeEnv, validate });
    expect(validate).not.toHaveBeenCalled();
  });
});
