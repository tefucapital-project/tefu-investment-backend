import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ApiError } from "./http.ts";
import { consumeRateLimit, resetRateLimits } from "./rateLimit.ts";
import { idempotencyKeySchema, nairaAmountSchema, readIdempotencyKey } from "./validation.ts";

describe("validation", () => {
  it("accepts a valid idempotency key", () => {
    assert.equal(readIdempotencyKey("credit-abc-12345"), "credit-abc-12345");
  });

  it("rejects a short idempotency key", () => {
    assert.throws(() => readIdempotencyKey("short"), (error: unknown) => error instanceof ApiError && error.code === "IDEMPOTENCY_KEY_REQUIRED");
  });

  it("rejects invalid idempotency characters", () => {
    assert.equal(idempotencyKeySchema.safeParse("bad key!!").success, false);
  });

  it("accepts amounts with at most 2 decimal places", () => {
    assert.equal(nairaAmountSchema.parse(1_250.5), 1_250.5);
  });

  it("rejects amounts with too many decimal places", () => {
    assert.equal(nairaAmountSchema.safeParse(10.123).success, false);
  });

  it("rejects non-positive amounts", () => {
    assert.equal(nairaAmountSchema.safeParse(0).success, false);
    assert.equal(nairaAmountSchema.safeParse(-5).success, false);
  });
});

describe("rateLimit", () => {
  it("enforces a per-key window", () => {
    resetRateLimits();
    assert.equal(consumeRateLimit("test:user-1", 2, 60_000).allowed, true);
    assert.equal(consumeRateLimit("test:user-1", 2, 60_000).allowed, true);
    const blocked = consumeRateLimit("test:user-1", 2, 60_000);
    assert.equal(blocked.allowed, false);
    assert.ok(blocked.retryAfterSec >= 1);
    assert.equal(consumeRateLimit("test:user-2", 2, 60_000).allowed, true);
  });
});
