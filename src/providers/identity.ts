import { codesMatch } from "../auth.ts";
import { env } from "../config.ts";
import { ApiError } from "../http.ts";
import { bankCodeFor, matchBankAccount, matchBvn, matchNin, type IdentityStatus } from "./otobill.ts";
import { verifyBank, verifyBvn, verifyNin } from "../services.ts";

export type IdentityCheck = { status: IdentityStatus; reference: string | null; provider: "otobill" | "demo" };

function provider() {
  return env.identityMode === "otobill" ? "otobill" : "demo";
}

function localPhone(phone: string | null) {
  if (!phone) return undefined;
  const digits = phone.replace(/\D/g, "");
  if (digits.startsWith("234") && digits.length === 13) return `0${digits.slice(3)}`;
  if (digits.length === 11 && digits.startsWith("0")) return digits;
  return undefined;
}

function gender(value: string | null) {
  const normal = value?.trim().toLowerCase();
  if (normal === "male" || normal === "m") return "male";
  if (normal === "female" || normal === "f") return "female";
  return undefined;
}

function birthday(value: string | null) {
  if (!value) return undefined;
  const match = value.match(/^(\d{4}-\d{2}-\d{2})/);
  return match?.[1];
}

export async function checkNin(input: {
  nin: string;
  firstName: string;
  lastName: string;
  middleName: string;
  gender: string | null;
  birthday: string | null;
  phone: string | null;
  consent: boolean;
}): Promise<IdentityCheck> {
  if (!/^\d{11}$/.test(input.nin)) throw new ApiError(422, "INVALID_NIN", "Enter the 11-digit NIN.");
  if (provider() === "demo") return { status: verifyNin(input.nin), reference: null, provider: "demo" };
  if (!input.consent) throw new ApiError(422, "CONSENT_REQUIRED", "Confirm that this person consented to the NIN check.");
  const result = await matchNin({
    nin: input.nin,
    firstName: input.firstName,
    lastName: input.lastName,
    middleName: input.middleName || undefined,
    gender: gender(input.gender),
    birthday: birthday(input.birthday),
    phoneNumber: localPhone(input.phone),
  });
  return { ...result, provider: "otobill" };
}

export async function checkBvn(input: {
  bvn: string;
  firstName: string;
  lastName: string;
  middleName: string;
  gender: string | null;
  birthday: string | null;
  phone: string | null;
  consent: boolean;
}): Promise<IdentityCheck> {
  if (!/^\d{11}$/.test(input.bvn)) throw new ApiError(422, "INVALID_BVN", "Enter the 11-digit BVN.");
  if (provider() === "demo") return { status: verifyBvn(input.bvn), reference: null, provider: "demo" };
  if (!input.consent) throw new ApiError(422, "CONSENT_REQUIRED", "Confirm that this person consented to the BVN check.");
  const result = await matchBvn({
    bvn: input.bvn,
    firstName: input.firstName,
    lastName: input.lastName,
    middleName: input.middleName || undefined,
    gender: gender(input.gender),
    birthday: birthday(input.birthday),
    phoneNumber: localPhone(input.phone),
  });
  return { ...result, provider: "otobill" };
}

export async function checkBank(input: {
  bankName: string;
  bankCode?: string;
  accountNumber: string;
  accountName: string;
  firstName: string;
  lastName: string;
  bvn?: string;
  bvnHash: string | null;
}): Promise<IdentityCheck> {
  if (!/^\d{10}$/.test(input.accountNumber)) throw new ApiError(422, "INVALID_ACCOUNT", "Enter the 10-digit account number.");
  if (provider() === "demo") {
    return { status: verifyBank(input.accountNumber, input.accountName, input.firstName, input.lastName), reference: null, provider: "demo" };
  }
  if (!input.bvn || !input.bvnHash || !codesMatch(input.bvn, input.bvnHash)) {
    throw new ApiError(422, "BVN_REQUIRED", "Enter the same BVN that was verified on this account.");
  }
  const bankCode = input.bankCode || bankCodeFor(input.bankName);
  if (!bankCode) throw new ApiError(422, "UNKNOWN_BANK", "Select a supported Nigerian bank.");
  const result = await matchBankAccount({ bvn: input.bvn, bankCode, bankAccount: input.accountNumber });
  return { ...result, provider: "otobill" };
}
