// Bounded serverless cron fallback for due transactional outbox work.
import { prisma } from "@/lib/prisma";
import { processOutboxEmailMessage } from "./processor";
import { publishConfiguredOutboxEmail } from "./qstash";

export const OUTBOX_CRON_DELIVERY_CAPACITY = 60;
export const OUTBOX_CRON_CONCURRENCY = 4;
export const OUTBOX_CRON_DEADLINE_MS = 20_000;

type DueRow = { id: string; dedupId: string };
type Publish = typeof publishConfiguredOutboxEmail;
type Process = typeof processOutboxEmailMessage;
type CronDrainDeps = {
  monotonicNow(): number;
  findDueRows(now: Date, take: number): Promise<DueRow[]>;
  deliver(row: DueRow, signal: AbortSignal): Promise<void>;
};

export type OutboxCronDrainResult = {
  processed: number;
  batchFull: boolean;
  deadlineExceeded: boolean;
};

export async function deliverOutboxRowWithFallback(
  row: DueRow,
  signal: AbortSignal,
  publish: Publish = publishConfiguredOutboxEmail,
  process: Process = processOutboxEmailMessage,
): Promise<void> {
  signal.throwIfAborted();
  try {
    await publish(row, fetch, signal);
  } catch {
    signal.throwIfAborted();
    await process({ id: row.id }, undefined, signal);
  }
}

const defaultDeps: CronDrainDeps = {
  monotonicNow: () => performance.now(),
  findDueRows: (now, take) => prisma.outboxEmail.findMany({
    where: {
      status: "PENDING", availableAt: { lte: now },
      OR: [{ nextAttemptAt: null }, { nextAttemptAt: { lte: now } }],
    },
    orderBy: [{ availableAt: "asc" }, { id: "asc" }],
    take,
    select: { id: true, dedupId: true },
  }),
  deliver: deliverOutboxRowWithFallback,
};

export async function drainDueOutboxEmails(
  now = new Date(),
  deps: CronDrainDeps = defaultDeps,
): Promise<OutboxCronDrainResult> {
  const startedAt = deps.monotonicNow();
  const rows = await deps.findDueRows(now, OUTBOX_CRON_DELIVERY_CAPACITY + 1);
  const queue = rows.slice(0, OUTBOX_CRON_DELIVERY_CAPACITY);
  const controller = new AbortController();
  let deadlineExceeded = false;
  const deadlineTimer = setTimeout(() => {
    deadlineExceeded = true;
    controller.abort(new Error("OUTBOX_CRON_DEADLINE"));
  }, OUTBOX_CRON_DEADLINE_MS);
  let nextIndex = 0;
  let processed = 0;

  const worker = async (): Promise<void> => {
    while (nextIndex < queue.length) {
      if (deps.monotonicNow() - startedAt >= OUTBOX_CRON_DEADLINE_MS) {
        deadlineExceeded = true;
        controller.abort(new Error("OUTBOX_CRON_DEADLINE"));
        return;
      }
      const row = queue[nextIndex];
      nextIndex += 1;
      if (!row) return;
      await deps.deliver(row, controller.signal).catch(() => undefined);
      processed += 1;
    }
  };

  try {
    await Promise.all(Array.from(
      { length: Math.min(OUTBOX_CRON_CONCURRENCY, queue.length) },
      worker,
    ));
  } finally {
    clearTimeout(deadlineTimer);
  }
  const batchFull = rows.length > OUTBOX_CRON_DELIVERY_CAPACITY ||
    processed < queue.length || deadlineExceeded;
  return { processed, batchFull, deadlineExceeded };
}
