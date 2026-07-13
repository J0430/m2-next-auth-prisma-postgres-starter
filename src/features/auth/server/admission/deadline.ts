// Bounds admission dependencies against one absolute monotonic request deadline.
import { monotonicNow, type MonotonicClock } from "./monotonicClock";

export class AdmissionDeadlineExceeded extends Error {
  constructor() {
    super("ADMISSION_DEADLINE_EXCEEDED");
  }
}

export function remainingDeadlineMs(
  deadlineAtMs: number,
  clock: MonotonicClock = monotonicNow,
): number {
  return Math.max(0, deadlineAtMs - clock());
}

export async function withinDeadline<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  deadlineAtMs: number,
  clock: MonotonicClock = monotonicNow,
): Promise<T> {
  const remainingMs = remainingDeadlineMs(deadlineAtMs, clock);
  if (remainingMs <= 0) throw new AdmissionDeadlineExceeded();

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new AdmissionDeadlineExceeded());
    }, remainingMs);
  });

  try {
    return await Promise.race([operation(controller.signal), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
