export const ONBOARDING_FEE_KOBO = 500_000;
export const WITHDRAWAL_FEE_KOBO = 10_000;
export const MUDARABAH_FEE_BPS = 50;
export const MIN_DEPOSIT_KOBO = 100_000;
export const MAX_DEPOSIT_KOBO = 500_000_000;
export const MIN_WITHDRAWAL_KOBO = 50_000;

export function arrangementFee(kind: "MUDARABAH" | "IJARAH", amountKobo: number) {
  if (kind === "IJARAH") return 0;
  return Math.round((amountKobo * MUDARABAH_FEE_BPS) / 10_000);
}

export function withdrawalAllowed(input: {
  accountActive: boolean;
  kycApproved: boolean;
  bankVerified: boolean;
  amountKobo: number;
  availableKobo: number;
}) {
  if (!input.accountActive) return "ACCOUNT_INACTIVE";
  if (!input.kycApproved) return "KYC_REQUIRED";
  if (!input.bankVerified) return "BANK_REQUIRED";
  if (input.amountKobo < MIN_WITHDRAWAL_KOBO) return "AMOUNT_TOO_SMALL";
  if (input.amountKobo + WITHDRAWAL_FEE_KOBO > input.availableKobo) return "INSUFFICIENT_BALANCE";
  return null;
}

export function splitDistribution(input: {
  kind: "MUDARABAH" | "IJARAH";
  performanceKobo: number;
  investorShare: number;
  capitals: number[];
}) {
  const pool =
    input.kind === "MUDARABAH"
      ? Math.round((input.performanceKobo * input.investorShare) / 100)
      : input.performanceKobo;
  const total = input.capitals.reduce((sum, value) => sum + value, 0);
  if (total <= 0) return [];
  const lines = input.capitals.map((capital) => Math.floor((pool * capital) / total));
  const drift = pool - lines.reduce((sum, value) => sum + value, 0);
  if (lines.length) lines[lines.length - 1] += drift;
  return lines;
}
