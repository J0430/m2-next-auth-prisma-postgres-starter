// Provides injectable monotonic elapsed-time readings for admission budgets.
export type MonotonicClock = () => number;

export const monotonicNow: MonotonicClock = () => performance.now();
