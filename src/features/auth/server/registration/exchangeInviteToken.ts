// Exchanges a fragment invite token for a server-bound opaque registration handle.
import { createHash, randomBytes } from "node:crypto";

import { lookupInviteByToken } from "@/features/auth/server/invites";
import { prisma } from "@/lib/prisma";
import {
  buildAdmissionRateLimitChecks,
  rateLimitAll,
  type AdmissionRateLimitCheck,
} from "@/lib/rateLimit";

const HANDLE_BYTES = 32;
const SESSION_TTL_MS = 10 * 60 * 1_000;
const EXCHANGE_TIMING_TARGET_MS = 250;
const defaultMonotonicNow = () => performance.now();
const defaultSleep = (milliseconds: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

type LookupResult = Awaited<ReturnType<typeof lookupInviteByToken>>;

type SessionRow = {
  handleHash: Buffer;
  inviteTokenHash: Buffer | null;
  inviteId: string | null;
  normalizedEmail: string | null;
  nonce: Buffer;
  status: "PENDING" | "DECOY";
  expiresAt: Date;
};

export type ExchangeInviteInput = {
  rawToken: string;
  ip: string | null;
};

export type ExchangeInviteDeps = {
  lookupInvite(rawToken: string): Promise<LookupResult>;
  limitAll(checks: readonly AdmissionRateLimitCheck[]): Promise<{ success: boolean }>;
  createSession(row: SessionRow): Promise<void>;
  randomBytes(size: number): Buffer;
  now(): Date;
  monotonicNow?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
};

const DEFAULT_DEPS: ExchangeInviteDeps = {
  lookupInvite: (rawToken) => lookupInviteByToken(rawToken, null),
  limitAll: (checks) => rateLimitAll(checks),
  createSession: async (data) => {
    await prisma.registrationSession.create({ data });
  },
  randomBytes,
  now: () => new Date(),
  monotonicNow: defaultMonotonicNow,
  sleep: defaultSleep,
};

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

export function createOpaqueRegistrationHandle(): string {
  return randomBytes(HANDLE_BYTES).toString("base64url");
}

async function pad(startedAt: number, deps: ExchangeInviteDeps): Promise<void> {
  const elapsed = (deps.monotonicNow ?? defaultMonotonicNow)() - startedAt;
  const remaining = EXCHANGE_TIMING_TARGET_MS - elapsed;
  if (remaining > 0) await (deps.sleep ?? defaultSleep)(remaining);
}

export async function exchangeInviteToken(
  input: ExchangeInviteInput,
  deps: ExchangeInviteDeps = DEFAULT_DEPS,
): Promise<{ handle: string }> {
  const startedAt = (deps.monotonicNow ?? defaultMonotonicNow)();
  const handle = deps.randomBytes(HANDLE_BYTES).toString("base64url");
  const tokenHash = digest(input.rawToken);
  const checks = buildAdmissionRateLimitChecks({
    surface: "fragment-exchange",
    ip: input.ip,
    inviteTokenHash: tokenHash.toString("hex"),
  });

  let limitsPassed = true;
  try {
    limitsPassed = (await deps.limitAll(checks)).success;
  } catch {
    limitsPassed = false;
  }

  if (limitsPassed) {
    let lookup: LookupResult | null = null;
    try {
      lookup = await deps.lookupInvite(input.rawToken);
    } catch {
      lookup = null;
    }
    const now = deps.now();
    const knownInvite = lookup?.ok === true ? lookup.invite : null;
    await deps.createSession({
      handleHash: digest(handle),
      inviteTokenHash: knownInvite ? Buffer.from(knownInvite.tokenHash) : null,
      inviteId: knownInvite?.id ?? null,
      normalizedEmail: knownInvite?.normalizedEmail ?? null,
      nonce: deps.randomBytes(HANDLE_BYTES),
      status: knownInvite ? "PENDING" : "DECOY",
      expiresAt: new Date(now.getTime() + SESSION_TTL_MS),
    }).catch(() => undefined);
  }

  await pad(startedAt, deps);
  return { handle };
}
