// Credential-backed, target-bound, one-time administrator bootstrap ceremony.
import "dotenv/config";
import { createHash, timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";
import { PrismaClient } from "@prisma/client";
import { compare } from "bcryptjs";
import { z } from "zod";
import { decryptTotpSecret, encryptTotpSecret } from "../src/features/auth/server/adminMfa/secretCrypto";
import { buildOtpauthUri, generateTotpSecret, matchingTotpStep } from "../src/features/auth/server/adminMfa/totp";

export interface BootstrapDependencies {
  comparePassword: typeof compare;
  decryptSecret: typeof decryptTotpSecret;
  encryptSecret: typeof encryptTotpSecret;
  generateSecret: typeof generateTotpSecret;
  matchingStep: typeof matchingTotpStep;
  now: () => Date;
  writeOutput: (value: string) => void;
}

const defaultDependencies: BootstrapDependencies = {
  comparePassword: compare,
  decryptSecret: decryptTotpSecret,
  encryptSecret: encryptTotpSecret,
  generateSecret: generateTotpSecret,
  matchingStep: matchingTotpStep,
  now: () => new Date(),
  writeOutput: console.log,
};

const CapabilitySchema = z.enum(["admin:invite:issue", "admin:invite:revoke", "admin:user:create", "admin:mfa:manage"]);
const ArgsSchema = z.object({
  mode: z.enum(["inventory", "prepare", "activate"]),
  email: z.string().email().optional(),
  code: z.string().regex(/^\d{6}$/u).optional(),
  password: z.string().min(1).optional(),
  databaseUrl: z.string().url(),
  targetSha256: z.string().regex(/^[a-f0-9]{64}$/u),
  allowRemote: z.boolean(),
  approvalSecret: z.string().min(32).optional(),
  approvalChallenge: z.string().regex(/^[a-f0-9]{64}$/u).optional(),
  capabilities: z.array(CapabilitySchema).min(1).optional(),
});

function flag(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  return index < 0 ? undefined : argv[index + 1];
}

function repeatedFlags(argv: readonly string[], name: string): string[] {
  return argv.flatMap((value, index) => value === name && argv[index + 1] ? [argv[index + 1] ?? ""] : []);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function equalHex(left: string, right: string): boolean {
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

export function canonicalTarget(raw: string): { url: string; loopback: boolean } {
  const parsed = new URL(raw);
  if (!/^postgres(?:ql)?:$/u.test(parsed.protocol) || parsed.search || parsed.hash || !parsed.pathname.slice(1)) {
    throw new Error("Bootstrap target must be a named canonical PostgreSQL URL without query or fragment routing");
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(parsed.hostname);
  return { url: parsed.toString(), loopback };
}

type BootstrapEnvironment = Readonly<Partial<Record<
  "ADMIN_BOOTSTRAP_TOTP_CODE" | "ADMIN_BOOTSTRAP_PASSWORD" | "ADMIN_BOOTSTRAP_APPROVAL_SECRET" | "NODE_ENV",
  string
>>>;

export function parseBootstrapArgs(argv: readonly string[], environment: BootstrapEnvironment) {
  const raw = flag(argv, "--database-url");
  const target = raw ? canonicalTarget(raw) : null;
  if (!target) throw new Error("Bootstrap requires --database-url");
  const capabilities = repeatedFlags(argv, "--capability");
  const args = ArgsSchema.parse({
    mode: argv[0], email: flag(argv, "--email"), code: environment.ADMIN_BOOTSTRAP_TOTP_CODE, password: environment.ADMIN_BOOTSTRAP_PASSWORD,
    databaseUrl: target.url, targetSha256: flag(argv, "--target-sha256"), allowRemote: argv.includes("--allow-remote-bootstrap"),
    approvalSecret: environment.ADMIN_BOOTSTRAP_APPROVAL_SECRET, approvalChallenge: flag(argv, "--approval-challenge"),
    capabilities: capabilities.length > 0 ? capabilities : undefined,
  });
  if (!equalHex(sha256(args.databaseUrl), args.targetSha256)) throw new Error("Exact database target SHA-256 mismatch");
  if (!target.loopback || environment.NODE_ENV === "production") {
    if (!args.allowRemote || !args.approvalSecret || !args.approvalChallenge) throw new Error("Remote bootstrap requires allow flag and separate approval proof");
    const expected = sha256(`${args.approvalSecret}\0${args.databaseUrl}`);
    if (!equalHex(expected, args.approvalChallenge)) throw new Error("Remote bootstrap approval challenge mismatch");
  }
  return args;
}

async function inventory(prisma: PrismaClient): Promise<void> {
  const admins = await prisma.user.findMany({
    where: { role: "ADMIN" },
    select: { id: true, email: true, mfaEnrolledAt: true, adminBootstrapCompletedAt: true,
      adminCapabilityGrants: { where: { revokedAt: null }, select: { capability: true } },
      adminMfaFactors: { where: { status: "ACTIVE" }, select: { id: true, keyVersion: true } } },
  });
  console.log(JSON.stringify({ adminCount: admins.length, admins }, null, 2));
}

export async function prepare(
  prisma: PrismaClient,
  email: string,
  dependencies: BootstrapDependencies = defaultDependencies,
): Promise<void> {
  const user = await prisma.user.findUnique({ where: { email }, select: { id: true, email: true, role: true, passwordHash: true, hasPasswordCredential: true, adminBootstrapCompletedAt: true,
    adminMfaFactors: { where: { status: { in: ["ACTIVE", "PENDING"] } }, select: { id: true } } } });
  if (!user || !user.hasPasswordCredential || !user.passwordHash || user.adminBootstrapCompletedAt || user.adminMfaFactors.length > 0 || !["USER", "ADMIN"].includes(user.role)) throw new Error("Unsafe or ineligible bootstrap identity");
  const secret = dependencies.generateSecret();
  const encrypted = dependencies.encryptSecret(secret);
  try {
    const factor = await prisma.$transaction(async (tx) => {
      const created = await tx.adminMfaFactor.create({ data: { userId: user.id, kind: "TOTP", status: "PENDING", secretCipher: encrypted.cipher, keyVersion: encrypted.keyVersion }, select: { id: true } });
      await tx.auditEvent.create({ data: { actorUserId: user.id, action: "admin.mfa.bootstrap.prepared", targetType: "AdminMfaFactor", targetId: created.id, metadata: { outcome: "SUCCESS" } } });
      return created;
    });
    dependencies.writeOutput(JSON.stringify({ factorId: factor.id, provisioningUri: buildOtpauthUri({ secretBase32: secret, accountName: user.email, issuer: process.env.MFA_ISSUER ?? "ManuMu Studio" }) }));
  } catch {
    throw new Error("Bootstrap preparation failed");
  }
}

export async function activate(
  prisma: PrismaClient,
  email: string,
  password: string,
  code: string,
  capabilities: string[],
  dependencies: BootstrapDependencies = defaultDependencies,
): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT 1 FROM "public"."users" WHERE "email" = ${email} FOR UPDATE`;
    const user = await tx.user.findUnique({ where: { email }, select: { id: true, role: true, passwordHash: true, hasPasswordCredential: true, adminBootstrapCompletedAt: true,
      adminMfaFactors: { where: { status: "PENDING", kind: "TOTP" }, select: { id: true, secretCipher: true, keyVersion: true, lastUsedStep: true } } } });
    if (!user || !user.hasPasswordCredential || !user.passwordHash || user.adminBootstrapCompletedAt || user.adminMfaFactors.length !== 1 || !(await dependencies.comparePassword(password, user.passwordHash))) throw new Error("Bootstrap assertion failed");
    const factor = user.adminMfaFactors[0];
    if (!factor) throw new Error("Bootstrap assertion failed");
    const now = dependencies.now();
    const step = dependencies.matchingStep(code, dependencies.decryptSecret(factor.secretCipher, factor.keyVersion), { atMs: now.getTime() });
    if (step === null) throw new Error("Bootstrap assertion failed");
    const activated = await tx.adminMfaFactor.updateMany({ where: { id: factor.id, status: "PENDING", lastUsedStep: null }, data: { status: "ACTIVE", activatedAt: now, lastUsedAt: now, lastUsedStep: BigInt(step) } });
    if (activated.count !== 1) throw new Error("Bootstrap assertion failed");
    await tx.adminCapabilityGrant.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: now } });
    await tx.adminCapabilityGrant.createMany({ data: capabilities.map((capability) => ({ userId: user.id, capability })) });
    const promoted = await tx.user.updateMany({ where: { id: user.id, adminBootstrapCompletedAt: null }, data: { role: "ADMIN", mfaEnrolledAt: now, lastStrongAuthAt: now, adminBootstrapCompletedAt: now, sessionVersion: { increment: 1 } } });
    if (promoted.count !== 1) throw new Error("Bootstrap assertion failed");
    await tx.$executeRaw`DELETE FROM "public"."admin_mfa_legacy_exemptions" WHERE "userId" = ${user.id}`;
    await tx.auditEvent.create({ data: { actorUserId: user.id, action: "admin.mfa.bootstrap.activated", targetType: "User", targetId: user.id, targetUserId: user.id, metadata: { outcome: "SUCCESS", capabilities } } });
  }, { isolationLevel: "Serializable" });
}

async function main(): Promise<void> {
  const args = parseBootstrapArgs(process.argv.slice(2), process.env);
  const prisma = new PrismaClient({ datasources: { db: { url: args.databaseUrl } } });
  try {
    if (args.mode === "inventory") await inventory(prisma);
    else if (args.mode === "prepare") {
      if (!args.email) throw new Error("prepare requires --email");
      await prepare(prisma, args.email);
    } else {
      if (!args.email || !args.password || !args.code || !args.capabilities) throw new Error("activate requires email, password, code, and capabilities");
      await activate(prisma, args.email, args.password, args.code, args.capabilities);
    }
  } finally { await prisma.$disconnect(); }
}

const entryPath = process.argv[1];
if (entryPath !== undefined && import.meta.url === pathToFileURL(entryPath).href) {
  main().catch(() => {
    console.error("admin_mfa_bootstrap_failed", { code: "ADMIN_MFA_BOOTSTRAP_FAILED" });
    process.exitCode = 1;
  });
}
