// Verifies TASK-028 cross-cutting security contracts that span task documents and test infrastructure.
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import ts from "typescript";

import { beforeEach, describe, expect, it, vi } from "vitest";

import { exchangeInviteToken } from "@/features/auth/server/registration/exchangeInviteToken";

const ROOT = process.cwd();

const DECISION_ONE_FILES = [
  "docs/build-packets/PACKET-02-gated-registration.md",
  "docs/research/PACKET-02-STAGE-0-CONTEXT/source/PACKET-02-gated-registration.md",
  "docs/research/PACKET-02-STAGE-0-CONTEXT/source/CP-012-packet02-redline-apply-and-build.md",
  "docs/research/PACKET-02-STAGE-0-CONTEXT/source/TASK-027-invitation-registration-ux.md",
] as const;

function read(relativePath: string): string {
  return readFileSync(resolve(ROOT, relativePath), "utf8");
}

function sourceFiles(relativeDirectory: string): string[] {
  return readdirSync(resolve(ROOT, relativeDirectory), { withFileTypes: true }).flatMap((entry) => {
    const relativePath = `${relativeDirectory}/${entry.name}`;
    if (entry.isDirectory()) return sourceFiles(relativePath);
    return /\.(?:ts|tsx)$/u.test(entry.name) ? [relativePath] : [];
  });
}

function unsafeConsoleArguments(relativePath: string): string[] {
  const source = read(relativePath);
  const tree = ts.createSourceFile(relativePath, source, ts.ScriptTarget.Latest, true);
  const findings: string[] = [];
  const sensitiveName = /(rawToken|inviteToken|otp|password|secret|ciphertext|authorization|headers|body)/iu;
  const inspectArgument = (node: ts.Node, safeErrorNameOnly: boolean): void => {
    if (ts.isIdentifier(node)) {
      const parent = node.parent;
      const allowedErrorName = node.text === "error"
        && ts.isPropertyAccessExpression(parent)
        && parent.expression === node
        && parent.name.text === "name";
      if ((!safeErrorNameOnly && !allowedErrorName && node.text === "error") || sensitiveName.test(node.text)) {
        findings.push(`${relativePath}:${tree.getLineAndCharacterOfPosition(node.getStart()).line + 1}:${node.text}`);
      }
    }
    ts.forEachChild(node, (child) => inspectArgument(child, safeErrorNameOnly));
  };
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)
      && ts.isPropertyAccessExpression(node.expression)
      && ts.isIdentifier(node.expression.expression)
      && node.expression.expression.text === "console") {
      node.arguments.forEach((argument) => {
        const argumentText = argument.getText(tree);
        const safeErrorNameOnly = argumentText.includes("error instanceof Error")
          && argumentText.includes("error.name")
          && !argumentText.includes("error.message")
          && !argumentText.includes("error.stack");
        inspectArgument(argument, safeErrorNameOnly);
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(tree);
  return findings;
}

describe("TASK-028 locked decision and evidence contracts", () => {
  it.each(DECISION_ONE_FILES)("keeps %s on fragment/hybrid, off-GET, hash-only transport", (path) => {
    const source = read(path);

    expect(source).toMatch(/FRAGMENT\/HYBRID|fragment\/hybrid/u);
    expect(source).toMatch(/#fragment/u);
    expect(source).toMatch(/hash-only|stores only `?sha256\(token\)`?/u);
    expect(source).toMatch(/off-GET|never (?:sent|on) (?:on|to )?(?:a |the )?GET|never on any GET/u);
    expect(source).not.toMatch(/raw (?:invite )?token[^\n]{0,80}(?:cookie|registration[_ -]session)/iu);
  });

  it("keeps fake timers restricted globally and never widens them per test", () => {
    const config = read("vitest.config.ts");
    const allTests = [
        "tests/gated-registration-admission.test.ts",
        "tests/gated-registration-credentials.test.ts",
        "tests/gated-registration-invites.test.ts",
        "tests/gated-registration-outbox.test.ts",
      ].map(read)
      .join("\n");

    expect(config).toContain("toFake: ['Date', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval']");
    expect(config).not.toMatch(/toFake:[^\]]*(?:queueMicrotask|nextTick|performance|setImmediate)/u);
    expect(allTests).not.toMatch(/useFakeTimers\s*\(\s*\{[^}]*toFake/u);
  });

  it("retains executable real-PostgreSQL concurrency and audit mutation rejection", () => {
    const runner = read("scripts/gated-registration-db-integration.ts");

    expect(runner).toContain("Promise.all(Array.from({ length: 8 }");
    expect(runner).toMatch(/UPDATE "public"\."audit_events"/u);
    expect(runner).toMatch(/DELETE FROM "public"\."audit_events"/u);
    expect(runner).toContain("immutable AuditEvent must remain unchanged");
  });

  it("keeps source and operator console sinks free of sensitive values and broad errors", () => {
    const findings = [...sourceFiles("src"), ...sourceFiles("scripts")].flatMap(unsafeConsoleArguments);
    expect(findings).toEqual([]);
  });
});

describe("TASK-028 four keyed limiter dimensions", () => {
  beforeEach(() => {
    vi.resetModules();
    process.env.SKIP_ENV_VALIDATION = "true";
  });

  it.each([
    ["ip", "account"], ["ip", "invite"], ["ip", "admin"],
    ["account", "ip"], ["account", "invite"], ["account", "admin"],
    ["invite", "ip"], ["invite", "account"], ["invite", "admin"],
    ["admin", "ip"], ["admin", "account"], ["admin", "invite"],
  ] as const)("exhausting %s leaves %s untouched", async (exhausted, untouched) => {
    const { memoryLimit, memoryStore } = await import("@/lib/rateLimit");
    memoryStore.clear();
    const dimensions = {
      ip: { key: "task028:ip", policy: "registration-ip" as const },
      account: { key: "task028:account", policy: "registration-account" as const },
      invite: { key: "task028:invite", policy: "registration-invite" as const },
      admin: { key: "task028:admin", policy: "admin-operation-admin" as const },
    };
    const source = dimensions[exhausted];
    const destination = dimensions[untouched];
    let result = memoryLimit(source.key, source.policy);
    for (let attempt = 1; attempt < result.limit; attempt += 1) {
      result = memoryLimit(source.key, source.policy);
    }
    expect(memoryLimit(source.key, source.policy).success).toBe(false);

    const untouchedResult = memoryLimit(destination.key, destination.policy);
    expect(untouchedResult.success).toBe(true);
    expect(untouchedResult.remaining).toBe(untouchedResult.limit - 1);
  });
});

describe("TASK-028 invalid-fragment storage amplification", () => {
  it("caps a flood before the SLO and cleanup restores the steady-state ceiling", async () => {
    const steadyStateSlo = 8;
    const rows: Array<{ handleHash: Buffer; expiresAt: Date }> = [];
    let writesRemaining = steadyStateSlo;
    let randomByte = 0;
    const shapes: string[] = [];

    const results = await Promise.all(Array.from({ length: 100 }, async (_, request) =>
      exchangeInviteToken(
        { rawToken: `malformed-${request}`, ip: "192.0.2.80" },
        {
          lookupInvite: vi.fn(async () => ({
            ok: false as const,
            status: 403 as const,
            body: { ok: false as const, message: "Unable to complete this request." as const },
          })),
          limitAll: vi.fn(async () => ({ success: writesRemaining-- > 0 })),
          createSession: vi.fn(async (row) => { rows.push(row); }),
          randomBytes: (size) => Buffer.alloc(size, (randomByte += 1) % 255),
          now: () => new Date("2026-07-12T20:00:00.000Z"),
        },
      )));
    for (const result of results) {
      shapes.push(JSON.stringify({
        status: 303,
        location: "/register",
        cookie: result.handle.replace(/[A-Za-z0-9_-]/gu, "x"),
      }));
    }

    expect(rows).toHaveLength(steadyStateSlo);
    expect(rows.length).toBeLessThanOrEqual(steadyStateSlo);
    expect(new Set(shapes)).toEqual(new Set([
      JSON.stringify({ status: 303, location: "/register", cookie: "x".repeat(43) }),
    ]));
    rows.splice(0, rows.length, ...rows.filter(({ expiresAt }) =>
      expiresAt > new Date("2026-07-12T20:10:01.000Z")));
    expect(rows.length).toBeLessThanOrEqual(steadyStateSlo);
    expect(rows).toHaveLength(0);
  });
});
