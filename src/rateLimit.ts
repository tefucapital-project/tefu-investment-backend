import type { NextFunction, Request, Response } from "express";
import { env } from "./config.ts";
import { ApiError } from "./http.ts";

type Bucket = { hits: number[] };

const buckets = new Map<string, Bucket>();

function prune(hits: number[], windowMs: number, now: number) {
  const floor = now - windowMs;
  let index = 0;
  while (index < hits.length && hits[index]! < floor) index += 1;
  if (index > 0) hits.splice(0, index);
}

function subjectKey(req: Request) {
  if (req.user?.id) return `user:${req.user.id}`;
  const forwarded = req.header("x-forwarded-for")?.split(",")[0]?.trim();
  return `ip:${forwarded || req.ip || "unknown"}`;
}

export function consumeRateLimit(key: string, max: number, windowMs: number) {
  const now = Date.now();
  const bucket = buckets.get(key) ?? { hits: [] };
  prune(bucket.hits, windowMs, now);
  if (bucket.hits.length >= max) {
    const retryAfterMs = Math.max(1_000, (bucket.hits[0] ?? now) + windowMs - now);
    buckets.set(key, bucket);
    return { allowed: false as const, retryAfterSec: Math.ceil(retryAfterMs / 1_000), remaining: 0 };
  }
  bucket.hits.push(now);
  buckets.set(key, bucket);
  return { allowed: true as const, retryAfterSec: 0, remaining: Math.max(0, max - bucket.hits.length) };
}

/** Clear in-memory counters (tests only). */
export function resetRateLimits() {
  buckets.clear();
}

export type RateLimitOptions = {
  bucket: string;
  max?: number;
  windowMs?: number;
};

/**
 * Per-authenticated-user rate limit. Falls back to client IP before auth.
 * Attach after `requireUser` for money-moving routes.
 */
export function rateLimitPerUser(options: RateLimitOptions) {
  const max = options.max ?? env.rateLimitPerUser;
  const windowMs = options.windowMs ?? env.rateLimitWindowMs;
  return (req: Request, res: Response, next: NextFunction) => {
    if (!env.rateLimitEnabled) return next();
    const key = `${options.bucket}:${subjectKey(req)}`;
    const result = consumeRateLimit(key, max, windowMs);
    res.setHeader("X-RateLimit-Limit", String(max));
    res.setHeader("X-RateLimit-Remaining", String(result.remaining));
    if (!result.allowed) {
      res.setHeader("Retry-After", String(result.retryAfterSec));
      return next(
        new ApiError(429, "RATE_LIMITED", `Too many ${options.bucket} requests. Try again in ${result.retryAfterSec}s.`),
      );
    }
    next();
  };
}
