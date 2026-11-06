import { env } from "../config.ts";
import { ApiError } from "../http.ts";

export type IdentityStatus = "VERIFIED" | "FAILED" | "REQUIRES_UPDATE";

type MatchFields = {
  nameMatchRlt?: string;
  namesMatchPercentage?: string;
  birthdayMatchRlt?: string;
  genderMatchRlt?: string;
  phoneNumberMatchRlt?: string;
};

const BANKS: Record<string, string> = {
  "access bank": "044",
  "citibank nigeria": "023",
  citibank: "023",
  ecobank: "050",
  "fidelity bank": "070",
  "first bank of nigeria": "011",
  "first bank": "011",
  "first city monument bank": "214",
  fcmb: "214",
  "globus bank": "00103",
  "guaranty trust bank": "058",
  gtbank: "058",
  "gt bank": "058",
  gtb: "058",
  "heritage bank": "030",
  "keystone bank": "082",
  "kuda bank": "090267",
  kuda: "090267",
  opay: "100004",
  palmpay: "100033",
  "polaris bank": "076",
  "providus bank": "101",
  "stanbic ibtc bank": "221",
  "stanbic ibtc": "221",
  "standard chartered": "068",
  "sterling bank": "232",
  "union bank": "032",
  "united bank for africa": "033",
  uba: "033",
  "unity bank": "215",
  "wema bank": "035",
  "zenith bank": "057",
};

export function bankCodeFor(bankName: string) {
  const key = bankName.trim().toLowerCase().replace(/\s+/g, " ");
  return BANKS[key] ?? null;
}

export function interpretMatch(fields: MatchFields): IdentityStatus {
  if (fields.nameMatchRlt === "No Match" || !fields.nameMatchRlt) return "FAILED";
  if (fields.nameMatchRlt === "Partial Match") return "REQUIRES_UPDATE";
  if (fields.nameMatchRlt !== "Exact Match") return "FAILED";
  // Phone is never used for NIN/BVN decisions — only the number the member typed, plus name / DOB / gender.
  const extras = [fields.birthdayMatchRlt, fields.genderMatchRlt].filter(Boolean);
  if (extras.some((value) => value !== "Exact Match")) return "REQUIRES_UPDATE";
  return "VERIFIED";
}

function findMatch(value: unknown): MatchFields | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (typeof record.nameMatchRlt === "string") return record as MatchFields;
  for (const child of Object.values(record)) {
    const found = findMatch(child);
    if (found) return found;
  }
  return null;
}

function nestedSuccess(value: unknown): boolean | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (record.success === false) return false;
  if (record.data && typeof record.data === "object") {
    const inner = nestedSuccess(record.data);
    if (inner !== null) return inner;
  }
  return record.success === true ? true : null;
}

function transactionId(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (typeof record.transactionId === "string") return record.transactionId;
  for (const child of Object.values(record)) {
    const found = transactionId(child);
    if (found) return found;
  }
  return null;
}

export function readIdentityResult(payload: unknown, kind: "match" | "lookup"): { status: IdentityStatus; reference: string | null } {
  const reference = transactionId(payload);
  if (kind === "match") {
    const fields = findMatch(payload);
    if (!fields) return { status: "FAILED", reference };
    return { status: interpretMatch(fields), reference };
  }
  const success = nestedSuccess(payload);
  return { status: success === true ? "VERIFIED" : "FAILED", reference };
}

export type NinProfile = {
  firstName: string;
  middleName: string;
  lastName: string;
  birthday: string;
};

export type NinEnquiry = {
  status: IdentityStatus;
  reference: string | null;
  message: string;
  profile: NinProfile | null;
};

function text(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function providerMessage(payload: unknown) {
  if (!payload || typeof payload !== "object") return "";
  const record = payload as Record<string, unknown>;
  const nested = record.data && typeof record.data === "object" ? text((record.data as Record<string, unknown>).message) : "";
  return nested || text(record.message);
}

/** Turn NIMC-style dates into yyyy-MM-dd for the profile form. */
export function normalizeIdentityDate(value: string) {
  const raw = value.trim();
  const iso = raw.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (iso) return `${iso[1]}-${iso[2]}-${iso[3]}`;
  const dmy = raw.match(/^(\d{2})[-/](\d{2})[-/](\d{4})$/);
  if (dmy) return `${dmy[3]}-${dmy[2]}-${dmy[1]}`;
  return "";
}

function slipRecord(payload: unknown): Record<string, unknown> | null {
  if (!payload || typeof payload !== "object") return null;
  const root = payload as Record<string, unknown>;
  const data = root.data && typeof root.data === "object" ? (root.data as Record<string, unknown>) : null;
  const inner = data?.data && typeof data.data === "object" ? (data.data as Record<string, unknown>) : null;
  const candidate = inner ?? data;
  if (!candidate) return null;
  if (text(candidate.firstName) || text(candidate.lastName) || text(candidate.birthday) || text(candidate.dateOfBirth)) return candidate;
  return null;
}

function lookupFailed(payload: unknown) {
  if (!payload || typeof payload !== "object") return true;
  const root = payload as Record<string, unknown>;
  if (root.success === false) return true;
  const data = root.data;
  if (data && typeof data === "object" && (data as Record<string, unknown>).success === false) return true;
  return false;
}

/** Read a NIN slip lookup. Failed checks keep Otobill's own message. */
export function readNinEnquiry(payload: unknown): NinEnquiry {
  const reference = transactionId(payload);
  const message = providerMessage(payload);
  if (lookupFailed(payload) || !slipRecord(payload)) {
    return {
      status: "FAILED",
      reference,
      message: message || "NIN could not be verified.",
      profile: null,
    };
  }
  const slip = slipRecord(payload)!;
  const birthday = normalizeIdentityDate(text(slip.birthday) || text(slip.dateOfBirth) || text(slip.birthDate) || text(slip.dob));
  const profile: NinProfile = {
    firstName: text(slip.firstName),
    middleName: text(slip.middleName),
    lastName: text(slip.lastName),
    birthday,
  };
  if (!profile.firstName || !profile.lastName || !profile.birthday) {
    return {
      status: "FAILED",
      reference,
      message: message && !/completed successfully/i.test(message) ? message : "The NIN record did not include a full name and date of birth.",
      profile: null,
    };
  }
  return {
    status: "VERIFIED",
    reference,
    message: "NIN verified. Your name and date of birth were taken from this NIN.",
    profile,
  };
}

export async function enquireNin(nin: string): Promise<NinEnquiry> {
  const payload = await post("/api/v1/developer/verify/nin", {
    verificationMethod: "by_nin_id",
    verificationType: "standard_slip",
    value: nin,
  }, { allowFailedCheck: true });
  return readNinEnquiry(payload);
}

async function post(path: string, body: Record<string, unknown>, options?: { allowFailedCheck?: boolean }) {
  if (!env.otobillApiKey) {
    throw new ApiError(503, "IDENTITY_NOT_CONFIGURED", "Add the Otobill API key before identity verification can run.");
  }
  let response: Response;
  try {
    response = await fetch(`${env.otobillBaseUrl}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": env.otobillApiKey,
      },
      body: JSON.stringify(body),
    });
  } catch {
    throw new ApiError(502, "IDENTITY_PROVIDER", "Identity verification could not be reached.");
  }
  const payload = await response.json().catch(() => null);
  if (response.status === 401 || response.status === 403) {
    throw new ApiError(502, "IDENTITY_PROVIDER", providerMessage(payload) || "Identity verification is not authorised. Check the API key and IP whitelist.");
  }
  const failedCheck = !payload || (payload as { success?: boolean }).success === false;
  if (!response.ok || (failedCheck && !options?.allowFailedCheck)) {
    throw new ApiError(502, "IDENTITY_PROVIDER", providerMessage(payload) || "Identity verification could not be completed.");
  }
  return payload;
}

export async function matchNin(input: {
  nin: string;
  firstName: string;
  lastName: string;
  middleName?: string;
  gender?: string;
  birthday?: string;
}) {
  // Do not send phoneNumber — verification must use the NIN the member typed.
  const payload = await post("/api/v1/developer/kyc/nin/basic", {
    nin: input.nin,
    firstName: input.firstName,
    lastName: input.lastName,
    ...(input.middleName ? { middleName: input.middleName } : {}),
    ...(input.gender ? { gender: input.gender } : {}),
    ...(input.birthday ? { birthday: input.birthday } : {}),
  });
  return readIdentityResult(payload, "match");
}

export async function matchBvn(input: {
  bvn: string;
  firstName: string;
  lastName: string;
  middleName?: string;
  gender?: string;
  birthday?: string;
}) {
  // Do not send phoneNumber — verification must use the BVN the member typed.
  const payload = await post("/api/v1/developer/kyc/bvn/basic", {
    bvn: input.bvn,
    firstName: input.firstName,
    lastName: input.lastName,
    ...(input.middleName ? { middleName: input.middleName } : {}),
    ...(input.gender ? { gender: input.gender } : {}),
    ...(input.birthday ? { birthday: input.birthday } : {}),
  });
  return readIdentityResult(payload, "match");
}

export async function matchBankAccount(input: { bvn: string; bankCode: string; bankAccount: string }) {
  const payload = await post("/api/v1/developer/kyc/bank-account", input);
  return readIdentityResult(payload, "lookup");
}
