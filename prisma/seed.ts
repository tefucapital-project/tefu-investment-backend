import bcrypt from "bcryptjs";
import { PrismaClient, type AdminRole } from "@prisma/client";
import { PERMISSIONS, ROLE_GRANTS } from "../src/domain/rbac.ts";

const prisma = new PrismaClient();
const password = await bcrypt.hash("Admin123!", 10);

const staff = [
  { email: "admin@tefuinvestment.com", firstName: "Ada", lastName: "Okonkwo", role: "SUPER_ADMIN" as const },
  { email: "compliance@tefuinvestment.com", firstName: "Ibrahim", lastName: "Lawal", role: "COMPLIANCE_ADMIN" as const },
  { email: "invest@tefuinvestment.com", firstName: "Zainab", lastName: "Yusuf", role: "INVESTMENT_ADMIN" as const },
  { email: "finance@tefuinvestment.com", firstName: "Chinedu", lastName: "Okafor", role: "FINANCE_ADMIN" as const },
  { email: "support@tefuinvestment.com", firstName: "Maryam", lastName: "Bello", role: "SUPPORT_ADMIN" as const },
];

for (const name of PERMISSIONS) {
  await prisma.permission.upsert({ where: { name }, update: {}, create: { name } });
}

for (const [role, grants] of Object.entries(ROLE_GRANTS)) {
  for (const permission of grants) {
    await prisma.rolePermission.upsert({
      where: { role_permission: { role: role as AdminRole, permission } },
      update: {},
      create: { role: role as AdminRole, permission },
    });
  }
}

for (const account of staff) {
  await prisma.user.upsert({
    where: { email: account.email },
    update: { passwordHash: password, role: account.role, adminActive: true, kind: "ADMIN" },
    create: {
      kind: "ADMIN",
      email: account.email,
      passwordHash: password,
      firstName: account.firstName,
      lastName: account.lastName,
      role: account.role,
      accountStatus: "ACTIVE",
    },
  });
}

await prisma.feeType.upsert({
  where: { name: "Client Onboarding Fee" },
  update: { amount: 500000, mode: "FIXED", currency: "NGN" },
  create: { name: "Client Onboarding Fee", amount: 500000, mode: "FIXED", currency: "NGN" },
});

await prisma.systemSetting.upsert({ where: { key: "currency" }, update: { value: "NGN" }, create: { key: "currency", value: "NGN" } });
await prisma.systemSetting.upsert({
  where: { key: "supportEmail" },
  update: { value: "support@tefuinvestment.com" },
  create: { key: "supportEmail", value: "support@tefuinvestment.com" },
});

const agreements = [
  { code: "TERMS", title: "Terms of use", version: "1.0", body: "Using Tefu Investment means you accept these terms." },
  { code: "PRIVACY", title: "Privacy notice", version: "1.0", body: "We store identity and financial records to operate your account." },
  { code: "MUDARABAH", title: "Mudarabah agreement", version: "1.2", body: "Profit is shared from actual venture performance. It is not guaranteed interest." },
  { code: "IJARAH", title: "Ijarah agreement", version: "1.1", body: "Rental is shared from actual lease collections. It is not guaranteed interest." },
];

for (const agreement of agreements) {
  await prisma.agreement.upsert({
    where: { code_version: { code: agreement.code, version: agreement.version } },
    update: { body: agreement.body, active: true },
    create: { ...agreement, active: true },
  });
}

const invest = await prisma.user.findUniqueOrThrow({ where: { email: "invest@tefuinvestment.com" } });
const superAdmin = await prisma.user.findUniqueOrThrow({ where: { email: "admin@tefuinvestment.com" } });

const opportunities = [
  {
    id: "mud-grains",
    kind: "MUDARABAH" as const,
    name: "Kano Grains",
    summary: "Seasonal grain trading. Profit is shared from the venture result.",
    minKobo: 5_000_000,
    maxKobo: 5_000_000_00,
    targetKobo: 20_000_000_00,
    durationMonths: 6,
    investorShare: 70,
    risk: "Trade, price, and harvest risk.",
    shariah: "Mudarabah profit-sharing from actual performance.",
  },
  {
    id: "ij-solar",
    kind: "IJARAH" as const,
    name: "School Solar",
    summary: "Leased solar equipment for a school. Rent is shared from collections.",
    minKobo: 5_000_000,
    maxKobo: 5_000_000_00,
    targetKobo: 15_000_000_00,
    durationMonths: 12,
    investorShare: 100,
    risk: "Lease, asset, and collection risk.",
    shariah: "Ijarah rental from the lease. Not guaranteed interest.",
  },
];

for (const item of opportunities) {
  await prisma.opportunity.upsert({
    where: { id: item.id },
    update: { status: "FUNDING" },
    create: { ...item, status: "FUNDING", createdById: invest.id, approvedById: superAdmin.id },
  });
}

console.log("Seeded Tefu Investment staff, fees, agreements, and opportunities.");
await prisma.$disconnect();
