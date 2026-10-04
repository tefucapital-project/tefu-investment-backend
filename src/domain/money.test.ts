import assert from "node:assert/strict";
import test from "node:test";
import { arrangementFee, splitDistribution, withdrawalAllowed } from "./money.ts";

test("Mudarabah arrangement fee is half a percent and Ijarah has none", () => {
  assert.equal(arrangementFee("MUDARABAH", 5_000_000), 25_000);
  assert.equal(arrangementFee("IJARAH", 5_000_000), 0);
});

test("withdrawal rules reject inactive accounts and over-balance requests", () => {
  assert.equal(
    withdrawalAllowed({
      accountActive: false,
      kycApproved: true,
      bankVerified: true,
      amountKobo: 100_000,
      availableKobo: 1_000_000,
    }),
    "ACCOUNT_INACTIVE",
  );
  assert.equal(
    withdrawalAllowed({
      accountActive: true,
      kycApproved: true,
      bankVerified: true,
      amountKobo: 1_000_000,
      availableKobo: 1_000_000,
    }),
    "INSUFFICIENT_BALANCE",
  );
  assert.equal(
    withdrawalAllowed({
      accountActive: true,
      kycApproved: true,
      bankVerified: true,
      amountKobo: 100_000,
      availableKobo: 1_000_000,
    }),
    null,
  );
});

test("distribution uses recorded performance and gives rounding to the last line", () => {
  assert.deepEqual(
    splitDistribution({ kind: "MUDARABAH", performanceKobo: 1_000_000, investorShare: 70, capitals: [50, 50] }),
    [350_000, 350_000],
  );
  assert.deepEqual(
    splitDistribution({ kind: "IJARAH", performanceKobo: 100, investorShare: 100, capitals: [1, 1, 1] }),
    [33, 33, 34],
  );
});
