// Performs all-or-none consumption for heterogeneous sliding-window rate limits.
import { randomBytes } from "node:crypto";
import { Redis } from "@upstash/redis";
import { z } from "zod";

export type AtomicLimitCheck = {
  storeKey: string;
  limit: number;
  windowMs: number;
};

const AtomicRedisResultSchema = z
  .union([z.literal(0), z.literal(1), z.literal("0"), z.literal("1")])
  .transform((value) => value === 1 || value === "1");

const ATOMIC_SLIDING_WINDOW_SCRIPT = `
local now = redis.call("TIME")
local now_ms = (now[1] * 1000) + math.floor(now[2] / 1000)

for index, key in ipairs(KEYS) do
  local offset = ((index - 1) * 2)
  local limit = tonumber(ARGV[offset + 1])
  local window_ms = tonumber(ARGV[offset + 2])
  redis.call("ZREMRANGEBYSCORE", key, 0, now_ms - window_ms)
  if redis.call("ZCARD", key) >= limit then
    return 0
  end
end

local member = tostring(now_ms) .. ":" .. ARGV[#ARGV]
for index, key in ipairs(KEYS) do
  local offset = ((index - 1) * 2)
  local window_ms = tonumber(ARGV[offset + 2])
  redis.call("ZADD", key, now_ms, member)
  redis.call("PEXPIRE", key, window_ms)
end
return 1
`;

export function atomicMemoryLimit(
  checks: readonly AtomicLimitCheck[],
  store: Map<string, number[]>,
  now = Date.now(),
): boolean {
  const prepared = checks.map((check) => {
    const timestamps = store.get(check.storeKey) ?? [];
    return {
      check,
      recent: timestamps.filter((timestamp) => now - timestamp < check.windowMs),
    };
  });
  if (prepared.some(({ check, recent }) => recent.length >= check.limit)) {
    return false;
  }
  prepared.forEach(({ check, recent }) => {
    store.set(check.storeKey, [...recent, now]);
  });
  return true;
}

export async function atomicRedisLimit(input: {
  checks: readonly AtomicLimitCheck[];
  url: string;
  token: string;
  signal?: AbortSignal;
}): Promise<boolean> {
  const redis = new Redis({ url: input.url, token: input.token, signal: input.signal });
  const keys = input.checks.map((check) => `rl:atomic:${check.storeKey}`);
  const args = input.checks.flatMap((check) => [String(check.limit), String(check.windowMs)]);
  args.push(randomBytes(16).toString("hex"));
  const result = await redis.eval<string[], unknown>(ATOMIC_SLIDING_WINDOW_SCRIPT, keys, args);
  return AtomicRedisResultSchema.parse(result);
}
