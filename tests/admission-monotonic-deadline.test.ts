// Verifies admission budgets use an injectable monotonic clock, independent of wall-clock jumps.
import { describe, expect, it, vi } from "vitest";

import {
  AdmissionDeadlineExceeded,
  remainingDeadlineMs,
  withinDeadline,
} from "@/features/auth/server/admission";

describe("monotonic admission deadlines", () => {
  it("computes an exact remaining budget from an injected monotonic clock", () => {
    const clock = vi.fn(() => 125.5);

    expect(remainingDeadlineMs(200, clock)).toBe(74.5);
    expect(clock).toHaveBeenCalledOnce();
  });

  it.each([
    ["backward", -3_600_000],
    ["forward", 3_600_000],
  ])("does not let a %s Date.now jump alter the timeout", async (_direction, jumpMs) => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-12T12:00:00.000Z"));
    const clock = vi.fn(() => 1_000);
    let outcome: "pending" | "rejected" = "pending";
    const pending = withinDeadline(() => new Promise<never>(() => undefined), 1_075, clock)
      .catch<unknown>((error: unknown) => {
        outcome = "rejected";
        return error;
      });

    vi.setSystemTime(new Date(Date.now() + jumpMs));
    await vi.advanceTimersByTimeAsync(74);
    await Promise.resolve();
    expect(outcome).toBe("pending");

    await vi.advanceTimersByTimeAsync(1);
    await expect(pending).resolves.toBeInstanceOf(AdmissionDeadlineExceeded);
    vi.useRealTimers();
  });
});
