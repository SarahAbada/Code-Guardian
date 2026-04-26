const WINDOW_MS = 60 * 60 * 1000;
const MAX_REQUESTS = 60;

const buckets = new Map<string, number[]>();

export type RateLimitResult = {
  allowed: boolean;
  remaining: number;
  resetAtMs: number;
  limit: number;
  retryAfterSec: number;
};

export function checkRateLimit(key: string, now = Date.now()): RateLimitResult {
  const windowStart = now - WINDOW_MS;
  const previous = buckets.get(key) ?? [];
  const fresh = previous.filter((ts) => ts > windowStart);

  if (fresh.length >= MAX_REQUESTS) {
    const oldest = fresh[0] ?? now;
    const resetAtMs = oldest + WINDOW_MS;
    buckets.set(key, fresh);
    return {
      allowed: false,
      remaining: 0,
      resetAtMs,
      limit: MAX_REQUESTS,
      retryAfterSec: Math.max(1, Math.ceil((resetAtMs - now) / 1000)),
    };
  }

  fresh.push(now);
  buckets.set(key, fresh);
  return {
    allowed: true,
    remaining: MAX_REQUESTS - fresh.length,
    resetAtMs: now + WINDOW_MS,
    limit: MAX_REQUESTS,
    retryAfterSec: 0,
  };
}

setInterval(() => {
  const cutoff = Date.now() - WINDOW_MS;
  for (const [key, timestamps] of buckets) {
    const fresh = timestamps.filter((ts) => ts > cutoff);
    if (fresh.length === 0) buckets.delete(key);
    else buckets.set(key, fresh);
  }
}, 5 * 60 * 1000).unref?.();
