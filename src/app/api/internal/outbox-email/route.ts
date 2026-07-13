// Internal transactional email outbox worker endpoint.
import { timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import {
  processOutboxEmailMessage,
  drainDueOutboxEmails,
  runRegistrationSessionCleanup,
  OutboxWorkerMessageSchema,
} from "@/features/auth/server/outbox";
import { env } from "@/lib/env";
import { buildAdmissionRateLimitChecks, getClientIp, rateLimit } from "@/lib/rateLimit";

const WORKER_ACTOR_ID = "internal-outbox-email-worker";

function unauthorizedResponse(): NextResponse {
  return NextResponse.json({ ok: false }, { status: 401 });
}

function badRequestResponse(): NextResponse {
  return NextResponse.json({ ok: false }, { status: 400 });
}

function extractBearerSecret(headers: Headers): string | null {
  const header = headers.get("authorization") ?? "";
  const prefix = "Bearer ";
  if (!header.startsWith(prefix)) return null;
  const token = header.slice(prefix.length).trim();
  return token.length > 0 ? token : null;
}

function timingSafeSecretEquals(candidate: string | null, expected: string | undefined): boolean {
  if (!candidate || !expected) return false;

  const candidateBytes = Buffer.from(candidate);
  const expectedBytes = Buffer.from(expected);
  if (candidateBytes.length !== expectedBytes.length) {
    const paddedCandidate = Buffer.alloc(expectedBytes.length);
    candidateBytes.copy(paddedCandidate, 0, 0, Math.min(candidateBytes.length, expectedBytes.length));
    timingSafeEqual(paddedCandidate, expectedBytes);
    return false;
  }

  return timingSafeEqual(candidateBytes, expectedBytes);
}

async function passesWorkerRateLimit(req: Request): Promise<boolean> {
  const ip = getClientIp(req.headers);
  const checks = buildAdmissionRateLimitChecks({
    surface: "admin-operation",
    ip,
    adminActorId: WORKER_ACTOR_ID,
  });

  for (const check of checks) {
    const result = await rateLimit(check.key, check.policy);
    if (!result.success) return false;
  }

  return true;
}

export async function POST(req: Request): Promise<NextResponse> {
  const workerSecret = extractBearerSecret(req.headers);
  if (!timingSafeSecretEquals(workerSecret, env.INTERNAL_WORKER_AUTH_SECRET)) {
    return unauthorizedResponse();
  }

  const body: unknown = await req.json().catch(() => null);
  const parsed = OutboxWorkerMessageSchema.safeParse(body);
  if (!parsed.success) return badRequestResponse();

  if (!(await passesWorkerRateLimit(req))) return unauthorizedResponse();

  await processOutboxEmailMessage(parsed.data);
  await runRegistrationSessionCleanup();
  return NextResponse.json({ ok: true });
}

export async function GET(req: Request): Promise<NextResponse> {
  const workerSecret = extractBearerSecret(req.headers);
  if (!timingSafeSecretEquals(workerSecret, env.INTERNAL_WORKER_AUTH_SECRET)) {
    return unauthorizedResponse();
  }
  if (!(await passesWorkerRateLimit(req))) return unauthorizedResponse();

  const [delivery, deleted] = await Promise.all([
    drainDueOutboxEmails(),
    runRegistrationSessionCleanup(),
  ]);
  if (delivery.batchFull) console.warn("OUTBOX_CRON_BATCH_FULL");
  return NextResponse.json({
    ok: true, deleted, processed: delivery.processed,
    batchFull: delivery.batchFull, deadlineExceeded: delivery.deadlineExceeded,
  });
}
