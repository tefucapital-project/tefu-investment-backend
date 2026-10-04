import assert from "node:assert/strict";
import test from "node:test";
import { kycCompletion, kycReadyForApproval } from "./kyc.ts";

const complete = {
  personal: "COMPLETE" as const,
  nin: "VERIFIED" as const,
  bvn: "VERIFIED" as const,
  bank: "VERIFIED" as const,
  document: "VERIFIED" as const,
  identity: "VERIFIED" as const,
};

test("KYC completion is calculated on the server", () => {
  assert.equal(kycCompletion({ ...complete, identity: "NOT_STARTED" }), 90);
  assert.equal(kycCompletion(complete), 100);
});

test("approval requires every component and a successful onboarding fee", () => {
  assert.equal(kycReadyForApproval(complete, false), false);
  assert.equal(kycReadyForApproval({ ...complete, bvn: "FAILED" }, true), false);
  assert.equal(kycReadyForApproval(complete, true), true);
});
