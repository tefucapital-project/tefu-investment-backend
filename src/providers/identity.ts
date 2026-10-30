import { codesMatch } from "../auth.ts";
import { env } from "../config.ts";
import { ApiError } from "../http.ts";
import { bankCodeFor, matchBankAccount, matchBvn, matchNin, type IdentityStatus } from "./otobill.ts";
import { paystackConfigured, resolvePaystackAccount } from "./paystack.ts";
import { verifyBank, verifyBvn, verifyNin } from "../services.ts";

export type IdentityCheck = {
  status: IdentityStatus;
  reference: string | null;
  provider: "otobill" | "demo" | "paystack";
  accountName?: string;
};

export { bankCodeFor };

function provider() {
  return env.identityMode === "otobill" ? "otobill" : "demo";
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
  consent: boolean;
}): Promise<IdentityCheck> {
  const nin = input.nin.replace(/\D/g, "");
  if (!/^\d{11}$/.test(nin)) throw new ApiError(422, "INVALID_NIN", "Enter the 11-digit NIN yourself. Phone number cannot be used.");
  if (provider() === "demo") return { status: verifyNin(nin), reference: null, provider: "demo" };
  if (!input.consent) throw new ApiError(422, "CONSENT_REQUIRED", "Confirm that this person consented to the NIN check.");
  const result = await matchNin({
    nin,
    firstName: input.firstName,
    lastName: input.lastName,
    middleName: input.middleName || undefined,
    gender: gender(input.gender),
    birthday: birthday(input.birthday),
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
  consent: boolean;
}): Promise<IdentityCheck> {
  const bvn = input.bvn.replace(/\D/g, "");
  if (!/^\d{11}$/.test(bvn)) throw new ApiError(422, "INVALID_BVN", "Enter the 11-digit BVN yourself. Phone number cannot be used.");
  if (provider() === "demo") return { status: verifyBvn(bvn), reference: null, provider: "demo" };
  if (!input.consent) throw new ApiError(422, "CONSENT_REQUIRED", "Confirm that this person consented to the BVN check.");
  const result = await matchBvn({
    bvn,
    firstName: input.firstName,
    lastName: input.lastName,
    middleName: input.middleName || undefined,
    gender: gender(input.gender),
    birthday: birthday(input.birthday),
  });
  return { ...result, provider: "otobill" };
}

function nameMatchesAccount(accountName: string, firstName: string, lastName: string) {
  const name = accountName.toLowerCase();
  return name.includes(firstName.trim().toLowerCase()) && name.includes(lastName.trim().toLowerCase());
}

/** Pull the registered account name for a bank + 10-digit NUBAN (does not save KYC yet). */
export async function resolveBankName(input: { bankName: string; bankCode?: string; accountNumber: string }) {
  const accountNumber = input.accountNumber.replace(/\D/g, "");
  if (!/^\d{10}$/.test(accountNumber)) {
    throw new ApiError(422, "INVALID_ACCOUNT", "Enter the 10-digit account number.");
  }
  const bankCode = input.bankCode || bankCodeFor(input.bankName);
  if (!bankCode) throw new ApiError(422, "UNKNOWN_BANK", "Select a supported Nigerian bank.");

  if (provider() === "demo" || !paystackConfigured()) {
    return {
      accountNumber,
      accountName: `${input.bankName} Account ${accountNumber.slice(-4)}`,
      bankCode,
      provider: "demo" as const,
    };
  }

  const resolved = await resolvePaystackAccount(accountNumber, bankCode);
  return { ...resolved, provider: "paystack" as const };
}

export async function checkBank(input: {
  bankName: string;
  bankCode?: string;
  accountNumber: string;
  accountName?: string;
  firstName: string;
  lastName: string;
  bvn?: string;
  bvnHash: string | null;
}): Promise<IdentityCheck> {
  const accountNumber = input.accountNumber.replace(/\D/g, "");
  if (!/^\d{10}$/.test(accountNumber)) throw new ApiError(422, "INVALID_ACCOUNT", "Enter the 10-digit account number.");
  const bankCode = input.bankCode || bankCodeFor(input.bankName);
  if (!bankCode) throw new ApiError(422, "UNKNOWN_BANK", "Select a supported Nigerian bank.");

  // Prefer live name enquiry so the member does not type the account name.
  if (paystackConfigured()) {
    const resolved = await resolvePaystackAccount(accountNumber, bankCode);
    const status: IdentityStatus = nameMatchesAccount(resolved.accountName, input.firstName, input.lastName)
      ? "VERIFIED"
      : "REQUIRES_UPDATE";
    return {
      status,
      reference: `paystack:${accountNumber}`,
      provider: "paystack",
      accountName: resolved.accountName,
    };
  }

  if (provider() === "demo") {
    const accountName = input.accountName?.trim() || `${input.firstName} ${input.lastName}`.trim();
    return {
      status: verifyBank(accountNumber, accountName, input.firstName, input.lastName),
      reference: null,
      provider: "demo",
      accountName,
    };
  }

  if (!input.bvn || !input.bvnHash || !codesMatch(input.bvn, input.bvnHash)) {
    throw new ApiError(422, "BVN_REQUIRED", "Enter the same BVN that was verified on this account.");
  }
  const result = await matchBankAccount({ bvn: input.bvn, bankCode, bankAccount: accountNumber });
  return { ...result, provider: "otobill", accountName: input.accountName };
}
