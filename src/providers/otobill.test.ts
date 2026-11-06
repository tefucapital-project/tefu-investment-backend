import assert from "node:assert/strict";
import test from "node:test";
import { bankCodeFor, interpretMatch, readIdentityResult, readNinEnquiry } from "./otobill.ts";

test("exact identity match is verified and a partial name needs an update", () => {
  assert.equal(interpretMatch({ nameMatchRlt: "Exact Match", birthdayMatchRlt: "Exact Match" }), "VERIFIED");
  assert.equal(interpretMatch({ nameMatchRlt: "Partial Match" }), "REQUIRES_UPDATE");
  // Phone match is ignored — only the typed NIN/BVN plus name/DOB/gender decide the result.
  assert.equal(interpretMatch({ nameMatchRlt: "Exact Match", birthdayMatchRlt: "Exact Match", phoneNumberMatchRlt: "No Match" }), "VERIFIED");
  assert.equal(interpretMatch({ nameMatchRlt: "No Match" }), "FAILED");
});

test("a successful HTTP body with a failed nested check is not verified", () => {
  const result = readIdentityResult({ success: true, data: { success: false, message: "Record not found" } }, "match");
  assert.equal(result.status, "FAILED");
});

test("a failed NIN lookup keeps Otobill's message", () => {
  const result = readNinEnquiry({
    success: true,
    message: "NIN verification completed",
    data: { success: false, message: "Record not found", transactionId: "txn-1" },
  });
  assert.equal(result.status, "FAILED");
  assert.equal(result.message, "Record not found");
  assert.equal(result.profile, null);
});

test("a confirmed NIN slip returns the legal name and date of birth", () => {
  const result = readNinEnquiry({
    success: true,
    message: "NIN verification completed successfully",
    data: {
      success: true,
      transactionId: "txn-2",
      data: {
        firstName: "JOHN",
        middleName: "JOSEPH",
        lastName: "DOE",
        birthday: "15-01-1990",
      },
    },
  });
  assert.equal(result.status, "VERIFIED");
  assert.deepEqual(result.profile, {
    firstName: "JOHN",
    middleName: "JOSEPH",
    lastName: "DOE",
    birthday: "1990-01-15",
  });
});

test("bank names map to NIP codes", () => {
  assert.equal(bankCodeFor("Guaranty Trust Bank"), "058");
  assert.equal(bankCodeFor("GTBank"), "058");
  assert.equal(bankCodeFor("United Bank for Africa"), "033");
});
