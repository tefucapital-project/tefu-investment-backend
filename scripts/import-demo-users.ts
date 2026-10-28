/**
 * Import browser-demo clients into MongoDB.
 *
 * Usage:
 *   npx tsx scripts/import-demo-users.ts path/to/tefu.investment.user.v1.json
 *
 * Export from a browser that still has the signup:
 *   copy(localStorage.getItem("tefu.investment.user.v1"))
 */
import { readFileSync } from "node:fs";
import { hashPassword } from "../src/auth.ts";
import { env } from "../src/config.ts";
import { prisma } from "../src/db.ts";

const TEMP_PASSWORD = process.env.DEMO_IMPORT_PASSWORD ?? "DemoRecover123!";

function normalizeNgPhone(value: string) {
  const digits = value.replace(/\D/g, "");
  if (digits.startsWith("234") && digits.length === 13) return `+${digits}`;
  if (digits.startsWith("0") && digits.length === 11) return `+234${digits.slice(1)}`;
  if (digits.length === 10) return `+234${digits}`;
  throw new Error("Invalid Nigerian phone number.");
}

function mapStatus(status?: string) {
  const key = (status ?? "kyc_locked").toLowerCase();
  const map: Record<string, "KYC_LOCKED" | "KYC_IN_PROGRESS" | "KYC_PENDING_REVIEW" | "KYC_APPROVED" | "KYC_REJECTED" | "ACTIVE" | "SUSPENDED" | "OTP_PENDING"> = {
    registered: "KYC_LOCKED",
    otp_pending: "OTP_PENDING",
    kyc_locked: "KYC_LOCKED",
    kyc_in_progress: "KYC_IN_PROGRESS",
    kyc_pending_review: "KYC_PENDING_REVIEW",
    kyc_approved: "KYC_APPROVED",
    kyc_rejected: "KYC_REJECTED",
    active: "ACTIVE",
    suspended: "SUSPENDED",
  };
  return map[key] ?? "KYC_LOCKED";
}

async function main() {
  const file = process.argv[2];
  if (!file) {
    console.error("Pass a JSON file exported from localStorage key tefu.investment.user.v1");
    process.exit(1);
  }
  const raw = JSON.parse(readFileSync(file, "utf8")) as { users?: Array<Record<string, unknown>> } | Array<Record<string, unknown>>;
  const users = Array.isArray(raw) ? raw : raw.users ?? [];
  if (!users.length) {
    console.error("No users found in file.");
    process.exit(1);
  }
  const passwordHash = await hashPassword(TEMP_PASSWORD);
  let created = 0;
  let skipped = 0;
  for (const row of users) {
    const email = String(row.email ?? "").toLowerCase().trim();
    const phoneRaw = String(row.phone ?? "");
    if (!email || !phoneRaw) {
      console.log("skip missing email/phone", row);
      skipped += 1;
      continue;
    }
    let phone: string;
    try {
      phone = normalizeNgPhone(phoneRaw);
    } catch (error) {
      console.log("skip", email, error instanceof Error ? error.message : error);
      skipped += 1;
      continue;
    }
    const existing = await prisma.user.findFirst({ where: { OR: [{ email }, { phone }] } });
    if (existing) {
      console.log("skip exists", email);
      skipped += 1;
      continue;
    }
    const accountStatus = mapStatus(typeof row.status === "string" ? row.status : undefined);
    const createdAt = typeof row.createdAt === "number" ? new Date(row.createdAt) : new Date();
    const user = await prisma.user.create({
      data: {
        kind: "CLIENT",
        email,
        phone,
        passwordHash,
        firstName: String(row.firstName ?? "Client").trim() || "Client",
        middleName: String(row.middleName ?? "").trim(),
        lastName: String(row.lastName ?? "User").trim() || "User",
        accountStatus,
        referralCode: typeof row.referralCode === "string" ? row.referralCode : null,
        acceptedTerms: true,
        acceptedPrivacy: true,
        createdAt,
        wallet: { create: { currency: env.currency } },
        kyc: { create: { status: accountStatus === "ACTIVE" ? "KYC_APPROVED" : "KYC_LOCKED" } },
      },
    });
    created += 1;
    console.log("created", user.email, user.id);
  }
  console.log({ created, skipped, temporaryPassword: TEMP_PASSWORD });
  await prisma.$disconnect();
}

main().catch(async (error) => {
  console.error(error);
  await prisma.$disconnect();
  process.exit(1);
});
