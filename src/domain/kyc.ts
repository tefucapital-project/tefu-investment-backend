export type Check = "NOT_STARTED" | "PENDING" | "VERIFIED" | "FAILED" | "REQUIRES_UPDATE" | "COMPLETE";

export type KycParts = {
  personal: Check;
  nin: Check;
  bvn: Check;
  bank: Check;
  document: Check;
  identity: Check;
};

const WEIGHTS: Record<keyof KycParts, number> = {
  personal: 20,
  nin: 20,
  bvn: 20,
  bank: 15,
  document: 15,
  identity: 10,
};

function done(part: keyof KycParts, status: Check) {
  if (part === "personal") return status === "COMPLETE";
  if (part === "document" || part === "identity") return status === "VERIFIED" || status === "COMPLETE";
  return status === "VERIFIED";
}

export function kycCompletion(parts: KycParts) {
  const score = (Object.keys(WEIGHTS) as (keyof KycParts)[]).reduce(
    (sum, key) => sum + (done(key, parts[key]) ? WEIGHTS[key] : 0),
    0,
  );
  return score;
}

export function kycReadyForApproval(parts: KycParts, feeSuccessful: boolean) {
  return feeSuccessful && (Object.keys(WEIGHTS) as (keyof KycParts)[]).every((key) => done(key, parts[key]));
}
