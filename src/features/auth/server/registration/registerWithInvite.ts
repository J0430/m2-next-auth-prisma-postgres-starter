// src/features/auth/server/registration/registerWithInvite.ts
// Atomically redeems an invite, creates an inactive credential account, and queues OTP email.
import { createHash } from "node:crypto";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { z } from "zod";

import { verifyTurnstileToken, type TurnstileFetcher } from "@/features/auth/lib/turnstile";
import {
  createGenericAdmissionFailure,
  padAdmissionTiming,
  monotonicNow,
  remainingDeadlineMs,
  type MonotonicClock,
  validateCsrf,
  withinDeadline,
} from "@/features/auth/server/admission";
import { recordInviteReuseEvidence, redeemInviteInTx } from "@/features/auth/server/invites";
import type { ResolvedInvite } from "@/features/auth/server/invites/invite.types";
import { publishConfiguredOutboxEmail } from "@/features/auth/server/outbox";
import { prisma } from "@/lib/prisma";
import { buildAdmissionRateLimitChecks, getClientIp, rateLimitAll, type HeaderSource } from "@/lib/rateLimit";
import { isValidCountryCode } from "@/lib/data/countries";
import {
  createInviteTransactionClient,
} from "./inviteTransaction";

export const REGISTRATION_SESSION_COOKIE_NAME = "registration_session";
export const REGISTRATION_CSRF_COOKIE_NAME = "registration_csrf";

const RegisterWithInviteFormSchema = z.object({
  firstname: z.string().trim().optional(),
  lastname: z.string().trim().optional(),
  email: z.string().email(),
  country: z
    .string()
    .length(2, "Country is required")
    .refine((value) => isValidCountryCode(value), "Invalid country"),
  city: z.string().min(2).max(120).optional(),
  address: z.string().min(3).max(500).optional(),
  csrfToken: z.string().min(1),
  turnstileToken: z.string().min(1),
});

const RegistrationSessionSchema = z.object({
  id: z.string(),
  handleHash: z.instanceof(Uint8Array),
  inviteTokenHash: z.instanceof(Uint8Array).nullable(),
  inviteId: z.string().nullable(),
  normalizedEmail: z.string().nullable(),
  status: z.string(),
  expiresAt: z.date(),
  consumedAt: z.date().nullable(),
});

const PUBLIC_TIMING_TARGET_MS = 250;
const PRE_MUTATION_DEADLINE_MS = 75;
const MIN_MUTATION_BUDGET_MS = 155;
const TRANSACTION_MAX_WAIT_MS = 50;
const TRANSACTION_TIMEOUT_MS = 150;

class InviteReuseSignal extends Error {
  constructor(readonly inviteId: string) {
    super("REGISTRATION_ADMISSION_DENIED");
  }
}

export type RegisterWithInviteInput = {
  formData: FormData;
  headers: HeaderSource;
  expectedOrigin: string;
  registrationHandle: string | null;
  csrfSessionToken: string | null;
  now?: Date;
  fetcher?: TurnstileFetcher;
  monotonicClock?: MonotonicClock;
};

export type RegistrationResult =
  | {
      ok: true;
      email: string;
      userId: string;
    }
  | {
      ok: false;
      status: number;
      body: {
        ok: false;
        message: string;
        supportId: string;
      };
    };

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function handleHash(handle: string): Buffer {
  return createHash("sha256").update(handle, "utf8").digest();
}

function hashForRateLimit(value: Buffer | Uint8Array | null): string | null {
  if (!value) return null;
  return Buffer.from(value).toString("hex");
}

function toResolvedInvite(row: { inviteTokenHash: Buffer | Uint8Array | null; inviteId: string | null }): ResolvedInvite | null {
  if (row.inviteTokenHash) return { tokenHash: Buffer.from(row.inviteTokenHash) };
  if (row.inviteId) return { inviteId: row.inviteId };
  return null;
}

function genericFailure(): RegistrationResult {
  const failure = createGenericAdmissionFailure();
  return {
    ok: false,
    status: failure.status,
    body: failure.body,
  };
}

function isUniqueConstraintError(error: unknown): boolean {
  return error instanceof PrismaClientKnownRequestError && error.code === "P2002";
}

async function runAdmissionLimiters(input: {
  ip: string | null;
  email: string;
  inviteTokenHash: Buffer | Uint8Array | null;
  deadlineAtMs: number;
  clock: MonotonicClock;
}): Promise<boolean> {
  const checks = buildAdmissionRateLimitChecks({
    surface: "registration",
    ip: input.ip,
    accountIdentifier: input.email,
    inviteTokenHash: hashForRateLimit(input.inviteTokenHash),
  });

  const result = await withinDeadline(
    (signal) => rateLimitAll(checks, signal),
    input.deadlineAtMs,
    input.clock,
  );
  return result.success;
}

export async function registerWithInvite(input: RegisterWithInviteInput): Promise<RegistrationResult> {
  const clock = input.monotonicClock ?? monotonicNow;
  const startedAtMs = clock();
  const finish = async (result: RegistrationResult): Promise<RegistrationResult> => {
    const elapsedMs = clock() - startedAtMs;
    if (elapsedMs > PUBLIC_TIMING_TARGET_MS) {
      console.error("security.registration_timing_parity_breach", {
        targetMs: PUBLIC_TIMING_TARGET_MS,
        elapsedMs,
      });
      return result.ok ? result : genericFailure();
    }
    await padAdmissionTiming(startedAtMs, PUBLIC_TIMING_TARGET_MS, clock);
    return result;
  };
  const fail = () => finish(genericFailure());

  const parsed = RegisterWithInviteFormSchema.safeParse({
    firstname: input.formData.get("firstname")?.toString(),
    lastname: input.formData.get("lastname")?.toString(),
    email: input.formData.get("email")?.toString(),
    country: input.formData.get("country")?.toString(),
    city: input.formData.get("city")?.toString(),
    address: input.formData.get("address")?.toString(),
    csrfToken: input.formData.get("csrfToken")?.toString(),
    turnstileToken: input.formData.get("turnstileToken")?.toString(),
  });
  if (!parsed.success) return fail();

  const csrf = validateCsrf({
    headers: input.headers,
    expectedOrigin: input.expectedOrigin,
    sessionToken: input.csrfSessionToken,
    submittedToken: parsed.data.csrfToken,
  });
  if (!csrf.ok) return fail();

  const ip = getClientIp(input.headers);
  if (!input.registrationHandle) return fail();

  const normalizedEmail = normalizeEmail(parsed.data.email);
  const refHash = handleHash(input.registrationHandle);
  const admissionDeadlineAtMs = startedAtMs + PRE_MUTATION_DEADLINE_MS;
  let turnstile: Awaited<ReturnType<typeof verifyTurnstileToken>>;
  let sessionResult: unknown;
  try {
    [turnstile, sessionResult] = await Promise.all([
      withinDeadline((signal) => verifyTurnstileToken({
        token: parsed.data.turnstileToken,
        remoteIp: ip,
        fetcher: input.fetcher,
        now: input.now,
        signal,
      }), admissionDeadlineAtMs, clock),
      withinDeadline(() => prisma.$transaction(
        (tx) => tx.registrationSession.findUnique({
          where: { handleHash: refHash },
          select: {
            id: true, handleHash: true, inviteTokenHash: true, inviteId: true,
            normalizedEmail: true, status: true, expiresAt: true, consumedAt: true,
          },
        }),
        { maxWait: 20, timeout: 50 },
      ), admissionDeadlineAtMs, clock),
    ]);
  } catch {
    return fail();
  }
  if (!turnstile.ok) return fail();
  const parsedSession = RegistrationSessionSchema.safeParse(sessionResult);
  if (!parsedSession.success) return fail();
  const session = parsedSession.data;
  try {
    if (!(await runAdmissionLimiters({
      ip, email: normalizedEmail, inviteTokenHash: session.inviteTokenHash,
      deadlineAtMs: admissionDeadlineAtMs, clock,
    }))) return fail();
  } catch {
    return fail();
  }

  const resolvedInvite = toResolvedInvite(session);
  if (
    !resolvedInvite ||
    (session.normalizedEmail !== null && normalizeEmail(session.normalizedEmail) !== normalizedEmail)
  ) {
    return fail();
  }

  const now = input.now ?? new Date();
  const fullName = [parsed.data.firstname, parsed.data.lastname].filter(Boolean).join(" ").trim() || null;
  const mutationBudgetMs = remainingDeadlineMs(startedAtMs + PUBLIC_TIMING_TARGET_MS, clock);
  if (mutationBudgetMs < MIN_MUTATION_BUDGET_MS) return fail();

  try {
    const created = await prisma.$transaction(async (tx) => {
      const consumed = await tx.registrationSession.updateMany({
        where: {
          handleHash: refHash,
          status: "PENDING",
          expiresAt: { gt: now },
          consumedAt: null,
        },
        data: {
          status: "CONSUMED",
          consumedAt: now,
        },
      });
      if (consumed.count !== 1) throw new Error("REGISTRATION_ADMISSION_DENIED");

      const user = await tx.user.create({
        data: {
          email: normalizedEmail,
          name: fullName,
          password: null,
          passwordHash: null,
          hasPasswordCredential: true,
          emailVerified: null,
          status: "INACTIVE",
          origin: "FIRST_PARTY",
          profile: {
            create: {
              country: parsed.data.country.toUpperCase(),
              city: parsed.data.city?.trim(),
              address: parsed.data.address?.trim(),
            },
          },
        },
        select: { id: true },
      });

      const redeemed = await redeemInviteInTx(
        createInviteTransactionClient(tx, user.id, (inviteId) => {
          throw new InviteReuseSignal(inviteId);
        }),
        resolvedInvite,
        session.normalizedEmail
      );
      if (!redeemed.ok) {
        throw new Error("REGISTRATION_ADMISSION_DENIED");
      }

      const outbox = await tx.outboxEmail.create({
        data: {
          eventType: "EMAIL_VERIFICATION",
          aggregateId: user.id,
          recipientUserId: user.id,
          dedupId: `email-verification:${user.id}`,
          status: "PENDING",
          availableAt: now,
        }, select: { id: true, dedupId: true },
      });

      return { user, outbox };
    }, {
      maxWait: Math.min(TRANSACTION_MAX_WAIT_MS, mutationBudgetMs - TRANSACTION_TIMEOUT_MS),
      timeout: Math.min(TRANSACTION_TIMEOUT_MS, mutationBudgetMs - TRANSACTION_MAX_WAIT_MS),
    });

    await publishConfiguredOutboxEmail(created.outbox).catch(() => undefined);
    return finish({ ok: true, email: normalizedEmail, userId: created.user.id });
  } catch (error) {
    if (error instanceof InviteReuseSignal) {
      await recordInviteReuseEvidence(error.inviteId);
      return fail();
    }
    if (isUniqueConstraintError(error) || error instanceof Error) {
      return fail();
    }
    return fail();
  }
}
