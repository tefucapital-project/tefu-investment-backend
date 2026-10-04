import assert from "node:assert/strict";
import test from "node:test";
import { bankCodeFor, interpretMatch, readIdentityResult } from "./otobill.ts";

test("exact identity match is verified and a partial name needs an update", () => {
  assert.equal(interpretMatch({ nameMatchRlt: "Exact Match", birthdayMatchRlt: "Exact Match" }), "VERIFIED");
  assert.equal(interpretMatch({ nameMatchRlt: "Partial Match" }), "REQUIRES_UPDATE");
  assert.equal(interpretMatch({ nameMatchRlt: "Exact Match", phoneNumberMatchRlt: "No Match" }), "REQUIRES_UPDATE");
  assert.equal(interpretMatch({ nameMatchRlt: "No Match" }), "FAILED");
});

test("a successful HTTP body with a failed nested check is not verified", () => {
  const result = readIdentityResult({ success: true, data: { success: false, message: "Record not found" } }, "match");
  assert.equal(result.status, "FAILED");
});

test("bank names map to NIP codes", () => {
  assert.equal(bankCodeFor("Guaranty Trust Bank"), "058");
  assert.equal(bankCodeFor("GTBank"), "058");
  assert.equal(bankCodeFor("United Bank for Africa"), "033");
});
