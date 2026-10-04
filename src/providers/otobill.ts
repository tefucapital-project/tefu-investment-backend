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
  const extras = [fields.birthdayMatchRlt, fields.genderMatchRlt, fields.phoneNumberMatchRlt].filter(Boolean);
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

async function post(path: string, body: Record<string, unknown>) {
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
    throw new ApiError(502, "IDENTITY_PROVIDER", "Identity verification is not authorised. Check the API key and IP whitelist.");
  }
  if (!response.ok || !payload || (payload as { success?: boolean }).success === false) {
    throw new ApiError(502, "IDENTITY_PROVIDER", "Identity verification could not be completed.");
  }
  return payload;
}

export async function matchNin(input: { nin: string; firstName: string; lastName: string; middleName?: string; gender?: string; birthday?: string; phoneNumber?: string }) {
  const payload = await post("/api/v1/developer/kyc/nin/basic", input);
  return readIdentityResult(payload, "match");
}

export async function matchBvn(input: { bvn: string; firstName: string; lastName: string; middleName?: string; gender?: string; birthday?: string; phoneNumber?: string }) {
  const payload = await post("/api/v1/developer/kyc/bvn/basic", input);
  return readIdentityResult(payload, "match");
}

export async function matchBankAccount(input: { bvn: string; bankCode: string; bankAccount: string }) {
  const payload = await post("/api/v1/developer/kyc/bank-account", input);
  return readIdentityResult(payload, "lookup");
}
