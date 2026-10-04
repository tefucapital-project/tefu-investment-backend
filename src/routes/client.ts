import { Router } from "express";
import { z } from "zod";
import { codesMatch, hashCode, hashPassword, oneTimeCode, readRefresh, verifyPassword } from "../auth.ts";
import { env } from "../config.ts";
import { prisma } from "../db.ts";
import { kycCompletion } from "../domain/kyc.ts";
import { arrangementFee, MAX_DEPOSIT_KOBO, MIN_DEPOSIT_KOBO, ONBOARDING_FEE_KOBO, withdrawalAllowed, WITHDRAWAL_FEE_KOBO } from "../domain/money.ts";
import { ApiError, kobo, naira, reference, send } from "../http.ts";
import { requireKind, requireUser } from "../middleware.ts";
import { checkBank, checkBvn, checkNin } from "../providers/identity.ts";
import {
  applyProviderResult,
  assertKycUnlocked,
  audit,
  consumeOtp,
  debitAvailable,
  issueOtp,
  lockFunds,
  notify,
  once,
  savePrivateFile,
  sessionFor,
} from "../services.ts";

export const client = Router();

const password = z.string().min(8).regex(/[A-Za-z]/).regex(/\d/);

function phone(value: string) {
  const digits = value.replace(/\D/g, "");
  if (digits.startsWith("234") && digits.length === 13) return `+${digits}`;
  if (digits.startsWith("0") && digits.length === 11) return `+234${digits.slice(1)}`;
  throw new ApiError(400, "INVALID_PHONE", "Enter a Nigerian phone number.");
}

client.post("/auth/register", async (req, res) => {
  const body = z.object({
    firstName: z.string().min(2).max(60),
    middleName: z.string().max(60).optional(),
    lastName: z.string().min(2).max(60),
    email: z.string().email(),
    phone: z.string().min(10),
    password,
    referralCode: z.string().nullable().optional(),
    acceptedTerms: z.literal(true),
    acceptedPrivacy: z.literal(true),
  }).parse(req.body);
  const normalized = phone(body.phone);
  const email = body.email.toLowerCase();
  const existing = await prisma.user.findFirst({ where: { OR: [{ email }, { phone: normalized }] } });
  if (existing) throw new ApiError(409, "ACCOUNT_EXISTS", "An account with this email or phone already exists.");
  const user = await prisma.user.create({
    data: {
      kind: "CLIENT",
      email,
      phone: normalized,
      passwordHash: await hashPassword(body.password),
      firstName: body.firstName,
      middleName: body.middleName ?? "",
      lastName: body.lastName,
      accountStatus: "OTP_PENDING",
      referralCode: body.referralCode ?? null,
      acceptedTerms: true,
      acceptedPrivacy: true,
      wallet: { create: { currency: env.currency } },
      kyc: { create: { status: "KYC_LOCKED" } },
    },
  });
  const code = await issueOtp(user.id, "REGISTER");
  await audit(user.id, "USER_REGISTERED", "USER", user.id, undefined, req.ip);
  send(res, 201, "Account created. Verify the code sent to you.", {
    userId: user.id,
    ...(env.exposeOtp ? { devCode: code } : {}),
  });
});

client.post("/auth/verify-otp", async (req, res) => {
  const body = z.object({ email: z.string().email(), code: z.string().length(6) }).parse(req.body);
  const user = await prisma.user.findUnique({ where: { email: body.email.toLowerCase() } });
  if (!user || user.kind !== "CLIENT") throw new ApiError(400, "OTP_INVALID", "The code is incorrect.");
  await consumeOtp(user.id, "REGISTER", body.code);
  if (user.accountStatus === "OTP_PENDING") {
    await prisma.user.update({ where: { id: user.id }, data: { accountStatus: "KYC_LOCKED" } });
  }
  await audit(user.id, "OTP_VERIFIED", "USER", user.id, undefined, req.ip);
  const tokens = await sessionFor({ id: user.id, kind: "CLIENT", role: null });
  send(res, 200, "Phone and email verified. Pay the Client Onboarding Fee to begin KYC.", tokens);
});

client.post("/auth/resend-otp", async (req, res) => {
  const body = z.object({ email: z.string().email() }).parse(req.body);
  const user = await prisma.user.findUnique({ where: { email: body.email.toLowerCase() } });
  if (!user || user.kind !== "CLIENT") {
    send(res, 200, "If the account exists, a new code has been sent.");
    return;
  }
  const code = await issueOtp(user.id, "REGISTER");
  send(res, 200, "A new code has been sent.", env.exposeOtp ? { devCode: code } : null);
});

client.post("/auth/login", async (req, res) => {
  const body = z.object({ email: z.string().email(), password: z.string() }).parse(req.body);
  const user = await prisma.user.findUnique({ where: { email: body.email.toLowerCase() } });
  if (!user || user.kind !== "CLIENT") throw new ApiError(401, "INVALID_LOGIN", "Email or password is incorrect.");
  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
    throw new ApiError(429, "ACCOUNT_LOCKED", "Too many attempts. Try again in a few minutes.");
  }
  if (!(await verifyPassword(body.password, user.passwordHash))) {
    const failed = user.failedLogins + 1;
    await prisma.user.update({
      where: { id: user.id },
      data: { failedLogins: failed, lockedUntil: failed >= 5 ? new Date(Date.now() + 2 * 60_000) : null },
    });
    throw new ApiError(401, "INVALID_LOGIN", "Email or password is incorrect.");
  }
  if (user.accountStatus === "SUSPENDED") throw new ApiError(403, "ACCOUNT_SUSPENDED", "This account is suspended.");
  await prisma.user.update({ where: { id: user.id }, data: { failedLogins: 0, lockedUntil: null } });
  const tokens = await sessionFor({ id: user.id, kind: "CLIENT", role: null });
  send(res, 200, "Signed in.", tokens);
});

client.post("/auth/forgot-password", async (req, res) => {
  const body = z.object({ email: z.string().email() }).parse(req.body);
  const email = body.email.toLowerCase();
  const user = await prisma.user.findUnique({ where: { email } });
  let devCode: string | undefined;
  if (user && user.kind === "CLIENT") {
    const code = oneTimeCode();
    await prisma.passwordReset.create({
      data: { email, codeHash: hashCode(code), expiresAt: new Date(Date.now() + 15 * 60_000) },
    });
    devCode = code;
  }
  send(res, 200, "If the account exists, a reset code has been sent.", env.exposeOtp && devCode ? { devCode } : null);
});

client.post("/auth/reset-password", async (req, res) => {
  const body = z.object({ email: z.string().email(), code: z.string().length(6), password }).parse(req.body);
  const email = body.email.toLowerCase();
  const row = await prisma.passwordReset.findFirst({ where: { email, usedAt: null }, orderBy: { createdAt: "desc" } });
  if (!row || row.expiresAt.getTime() < Date.now() || row.attempts >= 5) {
    throw new ApiError(400, "RESET_INVALID", "This reset code is no longer valid.");
  }
  if (!codesMatch(body.code, row.codeHash)) {
    await prisma.passwordReset.update({ where: { id: row.id }, data: { attempts: { increment: 1 } } });
    throw new ApiError(400, "RESET_INVALID", "This reset code is no longer valid.");
  }
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new ApiError(400, "RESET_INVALID", "This reset code is no longer valid.");
  await prisma.user.update({ where: { id: user.id }, data: { passwordHash: await hashPassword(body.password) } });
  await prisma.passwordReset.update({ where: { id: row.id }, data: { usedAt: new Date() } });
  await prisma.refreshToken.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: new Date() } });
  send(res, 200, "Password updated. Sign in with the new password.");
});

client.post("/auth/refresh", async (req, res) => {
  const body = z.object({ refreshToken: z.string() }).parse(req.body);
  let userId = "";
  try {
    const claims = readRefresh(body.refreshToken);
    if (claims.typ !== "refresh") throw new Error("type");
    userId = claims.sub;
  } catch {
    throw new ApiError(401, "INVALID_TOKEN", "The refresh token is invalid.");
  }
  const saved = await prisma.refreshToken.findUnique({ where: { tokenHash: hashCode(body.refreshToken) } });
  if (!saved || saved.revokedAt || saved.expiresAt.getTime() < Date.now()) {
    throw new ApiError(401, "INVALID_TOKEN", "The refresh token is invalid.");
  }
  await prisma.refreshToken.update({ where: { id: saved.id }, data: { revokedAt: new Date() } });
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
  const tokens = await sessionFor({ id: user.id, kind: user.kind, role: user.role });
  send(res, 200, "Session refreshed.", tokens);
});

client.post("/auth/logout", requireUser, requireKind("CLIENT"), async (req, res) => {
  const body = z.object({ refreshToken: z.string().optional() }).parse(req.body ?? {});
  if (body.refreshToken) {
    await prisma.refreshToken.updateMany({ where: { tokenHash: hashCode(body.refreshToken) }, data: { revokedAt: new Date() } });
  }
  send(res, 200, "Signed out.");
});

const authed = Router();
authed.use(requireUser, requireKind("CLIENT"));

authed.get("/profile", async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });
  send(res, 200, "Profile loaded.", publicUser(user));
});

authed.patch("/profile", async (req, res) => {
  const body = z.object({
    firstName: z.string().min(2).optional(),
    middleName: z.string().optional(),
    lastName: z.string().min(2).optional(),
  }).parse(req.body);
  const user = await prisma.user.update({ where: { id: req.user!.id }, data: body });
  send(res, 200, "Profile updated.", publicUser(user));
});

authed.post("/security/pin", async (req, res) => {
  const body = z.object({ pin: z.string().regex(/^\d{4}$/) }).parse(req.body);
  await prisma.user.update({ where: { id: req.user!.id }, data: { pinHash: hashCode(body.pin) } });
  send(res, 200, "Security PIN saved.");
});

authed.get("/account", async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id }, include: { kyc: true } });
  const fee = await prisma.clientFee.findFirst({ where: { userId: user.id, name: "Client Onboarding Fee", status: "SUCCESSFUL" } });
  send(res, 200, "Account loaded.", {
    status: user.accountStatus,
    kycUnlocked: !["OTP_PENDING", "REGISTERED", "OTP_VERIFIED", "KYC_LOCKED"].includes(user.accountStatus),
    canInvest: user.accountStatus === "ACTIVE",
    onboardingFeePaid: Boolean(fee),
    currency: env.currency,
  });
});

authed.get("/onboarding-fee", async (req, res) => {
  const fee = await prisma.clientFee.findFirst({ where: { userId: req.user!.id, name: "Client Onboarding Fee" }, orderBy: { createdAt: "desc" } });
  send(res, 200, "Client Onboarding Fee loaded.", {
    name: "Client Onboarding Fee",
    amount: naira(ONBOARDING_FEE_KOBO),
    currency: env.currency,
    latest: fee ? feeView(fee) : null,
  });
});

authed.post("/onboarding-fee/initialize", async (req, res) => {
  const body = z.object({ outcome: z.enum(["SUCCESSFUL", "FAILED", "PENDING"]).optional() }).parse(req.body ?? {});
  const result = await once(req.user!.id, req.header("idempotency-key") ?? undefined, async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });
    if (user.accountStatus === "OTP_PENDING") throw new ApiError(403, "OTP_REQUIRED", "Verify your account before paying the Client Onboarding Fee.");
    const paid = await prisma.clientFee.findFirst({ where: { userId: user.id, name: "Client Onboarding Fee", status: "SUCCESSFUL" } });
    if (paid) throw new ApiError(409, "FEE_ALREADY_PAID", "The Client Onboarding Fee has already been paid.");
    const ref = reference("COF");
    await prisma.clientFee.create({
      data: { userId: user.id, name: "Client Onboarding Fee", amountKobo: ONBOARDING_FEE_KOBO, reference: ref, provider: env.paymentsMode, status: "PENDING" },
    });
    await prisma.payment.create({
      data: { userId: user.id, purpose: "ONBOARDING_FEE", reference: ref, amountKobo: ONBOARDING_FEE_KOBO, provider: env.paymentsMode, status: "PENDING" },
    });
    if (env.paymentsMode === "demo" && body.outcome && body.outcome !== "PENDING") {
      await applyProviderResult(ref, body.outcome, `demo:${ref}`);
    }
    const fee = await prisma.clientFee.findUniqueOrThrow({ where: { reference: ref } });
    return { success: true, message: "Client Onboarding Fee payment started.", data: feeView(fee) };
  });
  res.status(200).json(result);
});

authed.get("/onboarding-fee/status", async (req, res) => {
  const fee = await prisma.clientFee.findFirst({ where: { userId: req.user!.id, name: "Client Onboarding Fee" }, orderBy: { createdAt: "desc" } });
  send(res, 200, "Payment status loaded.", fee ? feeView(fee) : null);
});

authed.get("/onboarding-fee/receipt", async (req, res) => {
  const fee = await prisma.clientFee.findFirst({ where: { userId: req.user!.id, name: "Client Onboarding Fee", status: "SUCCESSFUL" }, orderBy: { createdAt: "desc" } });
  if (!fee) throw new ApiError(404, "RECEIPT_NOT_FOUND", "No successful Client Onboarding Fee receipt exists.");
  send(res, 200, "Receipt loaded.", feeView(fee));
});

authed.get("/kyc", async (req, res) => {
  send(res, 200, "KYC loaded.", await kycView(req.user!.id));
});

authed.patch("/kyc", async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });
  assertKycUnlocked(user.accountStatus);
  const body = z.object({
    dateOfBirth: z.string(),
    gender: z.string().min(1),
    nationality: z.string().min(2),
    address: z.string().min(5),
    state: z.string().min(2),
    lga: z.string().min(2),
  }).parse(req.body);
  const born = new Date(body.dateOfBirth);
  const adult = Date.now() - born.getTime() > 18 * 365.25 * 24 * 3600_000;
  if (!adult) throw new ApiError(422, "NOT_ADULT", "You must be 18 or older.");
  await prisma.kycRecord.update({
    where: { userId: user.id },
    data: { ...body, personalStatus: "COMPLETE", status: user.accountStatus === "KYC_PENDING_REVIEW" ? undefined : "KYC_IN_PROGRESS" },
  });
  if (user.accountStatus === "KYC_LOCKED") {
    throw new ApiError(403, "KYC_LOCKED", "Complete your Client Onboarding Fee payment to begin KYC verification.");
  }
  send(res, 200, "Personal information saved.", await kycView(user.id));
});

authed.post("/kyc/nin/verify", async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id }, include: { kyc: true } });
  assertKycUnlocked(user.accountStatus);
  if (user.kyc?.personalStatus !== "COMPLETE") throw new ApiError(422, "PERSONAL_REQUIRED", "Save personal information before NIN verification.");
  const body = z.object({ nin: z.string(), consent: z.boolean().optional() }).parse(req.body);
  const result = await checkNin({
    nin: body.nin,
    firstName: user.firstName,
    lastName: user.lastName,
    middleName: user.middleName,
    gender: user.kyc?.gender ?? null,
    birthday: user.kyc?.dateOfBirth ?? null,
    phone: user.phone,
    consent: body.consent === true,
  });
  await prisma.kycRecord.update({
    where: { userId: user.id },
    data: {
      ninStatus: result.status,
      ninLast4: body.nin.slice(-4),
      ninHash: hashCode(body.nin),
      ninReference: result.reference ?? reference("NIN"),
    },
  });
  await audit(user.id, "NIN_CHECKED", "KYC", user.kyc!.id, `${result.provider}:${result.status}`, req.ip);
  send(res, 200, identityMessage("NIN", result.status), await kycView(user.id));
});

authed.post("/kyc/bvn/verify", async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id }, include: { kyc: true } });
  assertKycUnlocked(user.accountStatus);
  const body = z.object({ bvn: z.string(), consent: z.boolean().optional() }).parse(req.body);
  const result = await checkBvn({
    bvn: body.bvn,
    firstName: user.firstName,
    lastName: user.lastName,
    middleName: user.middleName,
    gender: user.kyc?.gender ?? null,
    birthday: user.kyc?.dateOfBirth ?? null,
    phone: user.phone,
    consent: body.consent === true,
  });
  await prisma.kycRecord.update({
    where: { userId: user.id },
    data: {
      bvnStatus: result.status,
      bvnLast4: body.bvn.slice(-4),
      bvnHash: hashCode(body.bvn),
      bvnReference: result.reference ?? reference("BVN"),
    },
  });
  await audit(user.id, "BVN_CHECKED", "KYC", user.kyc!.id, `${result.provider}:${result.status}`, req.ip);
  send(res, 200, identityMessage("BVN", result.status), await kycView(user.id));
});

authed.post("/kyc/bank-account/verify", async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id }, include: { kyc: true } });
  assertKycUnlocked(user.accountStatus);
  if (env.identityMode === "otobill" && user.kyc?.bvnStatus !== "VERIFIED") {
    throw new ApiError(422, "BVN_REQUIRED", "Verify BVN before the bank account.");
  }
  const body = z.object({
    bankName: z.string().min(2),
    bankCode: z.string().optional(),
    accountNumber: z.string(),
    accountName: z.string().min(3),
    bvn: z.string().optional(),
  }).parse(req.body);
  const result = await checkBank({
    bankName: body.bankName,
    bankCode: body.bankCode,
    accountNumber: body.accountNumber,
    accountName: body.accountName,
    firstName: user.firstName,
    lastName: user.lastName,
    bvn: body.bvn,
    bvnHash: user.kyc?.bvnHash ?? null,
  });
  await prisma.bankAccount.create({
    data: {
      kycId: user.kyc!.id,
      bankName: body.bankName,
      accountNumber: body.accountNumber,
      accountName: body.accountName,
      status: result.status,
      eligible: result.status === "VERIFIED",
      reference: result.reference ?? reference("BNK"),
    },
  });
  await prisma.kycRecord.update({ where: { userId: user.id }, data: { bankStatus: result.status } });
  await audit(user.id, "BANK_CHECKED", "KYC", user.kyc!.id, `${result.provider}:${result.status}`, req.ip);
  send(res, 200, identityMessage("Bank account", result.status), await kycView(user.id));
});

authed.post("/kyc/documents", async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id }, include: { kyc: true } });
  assertKycUnlocked(user.accountStatus);
  const body = z.object({
    kind: z.enum(["IDENTITY", "SELFIE"]),
    fileName: z.string().min(1),
    contentBase64: z.string().min(8),
  }).parse(req.body);
  const storageKey = await savePrivateFile(user.id, body.fileName, body.contentBase64);
  await prisma.document.create({
    data: { userId: user.id, kycId: user.kyc!.id, kind: body.kind, fileName: body.fileName, storageKey, status: "PENDING" },
  });
  const field = body.kind === "IDENTITY" ? "documentStatus" : "identityStatus";
  await prisma.kycRecord.update({ where: { userId: user.id }, data: { [field]: "PENDING" } });
  send(res, 201, "Document stored.", await kycView(user.id));
});

authed.post("/kyc/submit", async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id }, include: { kyc: true } });
  assertKycUnlocked(user.accountStatus);
  const kyc = user.kyc!;
  if (kyc.personalStatus !== "COMPLETE" || kyc.documentStatus === "NOT_STARTED" || kyc.identityStatus === "NOT_STARTED") {
    throw new ApiError(422, "KYC_INCOMPLETE", "Finish personal information, documents, and identity before submitting KYC.");
  }
  await prisma.kycRecord.update({ where: { id: kyc.id }, data: { status: "KYC_PENDING_REVIEW", submittedAt: new Date() } });
  await prisma.user.update({ where: { id: user.id }, data: { accountStatus: "KYC_PENDING_REVIEW" } });
  await audit(user.id, "KYC_SUBMITTED", "KYC", kyc.id, undefined, req.ip);
  send(res, 200, "KYC submitted for review.", await kycView(user.id));
});

authed.get("/wallet", async (req, res) => {
  const wallet = await prisma.wallet.findUniqueOrThrow({ where: { userId: req.user!.id } });
  send(res, 200, "Wallet loaded.", walletView(wallet));
});

authed.get("/wallet/transactions", async (req, res) => {
  const wallet = await prisma.wallet.findUniqueOrThrow({ where: { userId: req.user!.id } });
  const rows = await prisma.ledgerEntry.findMany({ where: { walletId: wallet.id }, orderBy: { createdAt: "desc" } });
  send(res, 200, "Transactions loaded.", rows.map(entryView));
});

authed.post("/wallet/deposit", async (req, res) => {
  const body = z.object({ amount: z.number().positive(), outcome: z.enum(["SUCCESSFUL", "FAILED", "PENDING"]).optional() }).parse(req.body);
  const amountKobo = kobo(body.amount);
  if (amountKobo < MIN_DEPOSIT_KOBO || amountKobo > MAX_DEPOSIT_KOBO) {
    throw new ApiError(422, "DEPOSIT_LIMIT", "Deposits must be between 1,000 and 5,000,000.");
  }
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });
  if (user.accountStatus !== "ACTIVE") throw new ApiError(403, "ACCOUNT_INACTIVE", "Deposits are available after the account is active.");
  const result = await once(req.user!.id, req.header("idempotency-key") ?? undefined, async () => {
    const ref = reference("DEP");
    await prisma.payment.create({
      data: { userId: user.id, purpose: "DEPOSIT", reference: ref, amountKobo, provider: env.paymentsMode, status: "PENDING" },
    });
    if (env.paymentsMode === "demo" && body.outcome && body.outcome !== "PENDING") {
      await applyProviderResult(ref, body.outcome, `demo:${ref}`);
    }
    const payment = await prisma.payment.findUniqueOrThrow({ where: { reference: ref } });
    return { success: true, message: "Deposit submitted for confirmation.", data: { reference: payment.reference, status: payment.status, amount: naira(payment.amountKobo) } };
  });
  res.status(200).json(result);
});

authed.post("/wallet/withdraw", async (req, res) => {
  const body = z.object({ amount: z.number().positive(), bankAccountId: z.string(), pin: z.string().regex(/^\d{4}$/) }).parse(req.body);
  const result = await once(req.user!.id, req.header("idempotency-key") ?? undefined, async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id }, include: { wallet: true, kyc: { include: { bankAccounts: true } } } });
    if (!user.pinHash || !codesMatch(body.pin, user.pinHash)) throw new ApiError(401, "PIN_INVALID", "The security PIN is incorrect.");
    const bank = user.kyc?.bankAccounts.find((item) => item.id === body.bankAccountId && item.eligible);
    const amountKobo = kobo(body.amount);
    const problem = withdrawalAllowed({
      accountActive: user.accountStatus === "ACTIVE",
      kycApproved: user.accountStatus === "ACTIVE",
      bankVerified: Boolean(bank),
      amountKobo,
      availableKobo: user.wallet!.availableKobo,
    });
    if (problem) throw new ApiError(422, problem, "This withdrawal cannot be created.");
    const ref = reference("WDR");
    await prisma.$transaction(async (tx) => {
      await lockFunds(tx, user.wallet!.id, amountKobo + WITHDRAWAL_FEE_KOBO);
      await tx.withdrawal.create({
        data: { userId: user.id, bankAccountId: bank!.id, amountKobo, feeKobo: WITHDRAWAL_FEE_KOBO, reference: ref, status: "PENDING" },
      });
    });
    await audit(user.id, "WITHDRAWAL_REQUESTED", "WITHDRAWAL", ref, undefined, req.ip);
    return { success: true, message: "Withdrawal submitted for review.", data: { reference: ref, status: "PENDING", amount: body.amount, fee: naira(WITHDRAWAL_FEE_KOBO) } };
  });
  res.status(200).json(result);
});

authed.get("/mudarabah", async (_req, res) => {
  const rows = await prisma.opportunity.findMany({ where: { kind: "MUDARABAH", status: { in: ["PUBLISHED", "FUNDING", "FULLY_FUNDED", "ACTIVE"] } } });
  send(res, 200, "Mudarabah opportunities loaded.", rows.map(opportunityView));
});

authed.get("/mudarabah/:id", async (req, res) => {
  const row = await prisma.opportunity.findFirst({ where: { id: req.params.id, kind: "MUDARABAH" } });
  if (!row || !["PUBLISHED", "FUNDING", "FULLY_FUNDED", "ACTIVE"].includes(row.status)) throw new ApiError(404, "NOT_FOUND", "Opportunity not found.");
  send(res, 200, "Opportunity loaded.", opportunityView(row));
});

authed.post("/mudarabah/:id/invest", async (req, res) => {
  res.status(200).json(await invest(req, "MUDARABAH"));
});

authed.get("/ijarah", async (_req, res) => {
  const rows = await prisma.opportunity.findMany({ where: { kind: "IJARAH", status: { in: ["PUBLISHED", "FUNDING", "FULLY_FUNDED", "ACTIVE", "LEASE_ACTIVE"] } } });
  send(res, 200, "Ijarah opportunities loaded.", rows.map(opportunityView));
});

authed.get("/ijarah/:id", async (req, res) => {
  const row = await prisma.opportunity.findFirst({ where: { id: req.params.id, kind: "IJARAH" } });
  if (!row || !["PUBLISHED", "FUNDING", "FULLY_FUNDED", "ACTIVE", "LEASE_ACTIVE"].includes(row.status)) throw new ApiError(404, "NOT_FOUND", "Opportunity not found.");
  send(res, 200, "Opportunity loaded.", opportunityView(row));
});

authed.post("/ijarah/:id/invest", async (req, res) => {
  res.status(200).json(await invest(req, "IJARAH"));
});

authed.get("/investments", async (req, res) => {
  const rows = await prisma.holding.findMany({ where: { userId: req.user!.id }, include: { opportunity: true }, orderBy: { createdAt: "desc" } });
  send(res, 200, "Investments loaded.", rows.map(holdingView));
});

authed.get("/investments/portfolio", async (req, res) => {
  const rows = await prisma.holding.findMany({ where: { userId: req.user!.id } });
  const invested = rows.reduce((sum, row) => sum + row.amountKobo, 0);
  send(res, 200, "Portfolio loaded.", { count: rows.length, invested: naira(invested), currency: env.currency });
});

authed.get("/investments/:id", async (req, res) => {
  const row = await prisma.holding.findFirst({ where: { id: req.params.id, userId: req.user!.id }, include: { opportunity: true } });
  if (!row) throw new ApiError(404, "NOT_FOUND", "Investment not found.");
  send(res, 200, "Investment loaded.", holdingView(row));
});

authed.get("/distributions", async (req, res) => {
  const rows = await prisma.distributionLine.findMany({
    where: { holding: { userId: req.user!.id }, distribution: { status: "COMPLETED" } },
    include: { distribution: true },
  });
  send(res, 200, "Distributions loaded.", rows.map((row) => ({ id: row.id, amount: naira(row.amountKobo), kind: row.distribution.kind, reference: row.distribution.reference })));
});

authed.get("/agreements", async (_req, res) => {
  const rows = await prisma.agreement.findMany({ where: { active: true } });
  send(res, 200, "Agreements loaded.", rows.map((row) => ({ id: row.id, code: row.code, title: row.title, version: row.version, body: row.body })));
});

authed.post("/agreements/:id/accept", async (req, res) => {
  const agreement = await prisma.agreement.findUnique({ where: { id: req.params.id } });
  if (!agreement) throw new ApiError(404, "NOT_FOUND", "Agreement not found.");
  const acceptance = await prisma.agreementAcceptance.create({
    data: { userId: req.user!.id, agreementId: agreement.id, reference: reference("AGR") },
  });
  send(res, 201, "Agreement accepted.", { reference: acceptance.reference, version: agreement.version, acceptedAt: acceptance.createdAt });
});

authed.get("/notifications", async (req, res) => {
  const rows = await prisma.notification.findMany({ where: { userId: req.user!.id }, orderBy: { createdAt: "desc" } });
  send(res, 200, "Notifications loaded.", rows);
});

authed.patch("/notifications/:id/read", async (req, res) => {
  await prisma.notification.updateMany({ where: { id: req.params.id, userId: req.user!.id }, data: { readAt: new Date() } });
  send(res, 200, "Notification marked read.");
});

authed.get("/support/tickets", async (req, res) => {
  const rows = await prisma.supportTicket.findMany({ where: { userId: req.user!.id }, orderBy: { createdAt: "desc" } });
  send(res, 200, "Tickets loaded.", rows);
});

authed.post("/support/tickets", async (req, res) => {
  const body = z.object({ subject: z.string().min(3), message: z.string().min(3) }).parse(req.body);
  const ticket = await prisma.supportTicket.create({
    data: { userId: req.user!.id, subject: body.subject, messages: { create: { authorId: req.user!.id, body: body.message } } },
  });
  send(res, 201, "Ticket opened.", ticket);
});

authed.get("/support/tickets/:id", async (req, res) => {
  const ticket = await prisma.supportTicket.findFirst({ where: { id: req.params.id, userId: req.user!.id }, include: { messages: true } });
  if (!ticket) throw new ApiError(404, "NOT_FOUND", "Ticket not found.");
  send(res, 200, "Ticket loaded.", ticket);
});

authed.post("/support/tickets/:id/messages", async (req, res) => {
  const body = z.object({ message: z.string().min(1) }).parse(req.body);
  const ticket = await prisma.supportTicket.findFirst({ where: { id: req.params.id, userId: req.user!.id } });
  if (!ticket) throw new ApiError(404, "NOT_FOUND", "Ticket not found.");
  const message = await prisma.supportMessage.create({ data: { ticketId: ticket.id, authorId: req.user!.id, body: body.message } });
  send(res, 201, "Message sent.", message);
});

client.use(authed);

function identityMessage(label: string, status: string) {
  if (status === "VERIFIED") return `${label} verified.`;
  if (status === "REQUIRES_UPDATE") return `${label} details do not fully match this profile.`;
  return `${label} could not be verified.`;
}

function publicUser(user: { id: string; email: string; phone: string | null; firstName: string; middleName: string; lastName: string; accountStatus: string }) {
  return { id: user.id, email: user.email, phone: user.phone, firstName: user.firstName, middleName: user.middleName, lastName: user.lastName, status: user.accountStatus };
}

function feeView(fee: { reference: string; amountKobo: number; status: string; paidAt: Date | null; createdAt: Date }) {
  return { name: "Client Onboarding Fee", reference: fee.reference, amount: naira(fee.amountKobo), currency: env.currency, status: fee.status, paidAt: fee.paidAt, createdAt: fee.createdAt };
}

function walletView(wallet: { id: string; availableKobo: number; lockedKobo: number; balanceKobo: number; currency: string; status: string }) {
  return { id: wallet.id, available: naira(wallet.availableKobo), locked: naira(wallet.lockedKobo), balance: naira(wallet.balanceKobo), currency: wallet.currency, status: wallet.status };
}

function entryView(entry: { reference: string; type: string; amountKobo: number; direction: string; status: string; description: string; createdAt: Date }) {
  return { reference: entry.reference, type: entry.type, amount: naira(entry.amountKobo), direction: entry.direction, status: entry.status, description: entry.description, createdAt: entry.createdAt };
}

function opportunityView(row: { id: string; kind: string; name: string; summary: string; status: string; minKobo: number; maxKobo: number; targetKobo: number; fundedKobo: number; durationMonths: number; investorShare: number; risk: string }) {
  return {
    id: row.id,
    kind: row.kind,
    name: row.name,
    summary: row.summary,
    status: row.status,
    minimum: naira(row.minKobo),
    maximum: naira(row.maxKobo),
    target: naira(row.targetKobo),
    funded: naira(row.fundedKobo),
    durationMonths: row.durationMonths,
    investorShare: row.investorShare,
    risk: row.risk,
    currency: env.currency,
  };
}

function holdingView(row: { id: string; amountKobo: number; feeKobo: number; reference: string; status: string; maturesAt: Date; opportunity: { name: string; kind: string } }) {
  return { id: row.id, name: row.opportunity.name, kind: row.opportunity.kind, amount: naira(row.amountKobo), fee: naira(row.feeKobo), reference: row.reference, status: row.status, maturesAt: row.maturesAt };
}

async function kycView(userId: string) {
  const kyc = await prisma.kycRecord.findUniqueOrThrow({ where: { userId }, include: { bankAccounts: true, documents: true } });
  const parts = {
    personal: kyc.personalStatus,
    nin: kyc.ninStatus,
    bvn: kyc.bvnStatus,
    bank: kyc.bankStatus,
    document: kyc.documentStatus,
    identity: kyc.identityStatus,
  };
  return {
    id: kyc.id,
    status: kyc.status,
    completion: kycCompletion(parts),
    parts,
    ninLast4: kyc.ninLast4,
    bvnLast4: kyc.bvnLast4,
    rejectionReason: kyc.rejectionReason,
    updateReason: kyc.updateReason,
    banks: kyc.bankAccounts.map((bank) => ({ id: bank.id, bankName: bank.bankName, accountName: bank.accountName, last4: bank.accountNumber.slice(-4), status: bank.status, eligible: bank.eligible })),
    documents: kyc.documents.map((doc) => ({ id: doc.id, kind: doc.kind, fileName: doc.fileName, status: doc.status })),
  };
}

async function invest(req: { user?: { id: string }; header: (name: string) => string | undefined; body: unknown; params: { id?: string }; ip?: string }, kind: "MUDARABAH" | "IJARAH") {
  const body = z.object({
    amount: z.number().positive(),
    agreementId: z.string(),
    pin: z.string().regex(/^\d{4}$/),
  }).parse(req.body);
  return once(req.user!.id, req.header("idempotency-key"), async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id }, include: { wallet: true } });
    if (user.accountStatus !== "ACTIVE") throw new ApiError(403, "NOT_ELIGIBLE", "Investment is available after KYC approval activates the account.");
    if (!user.pinHash || !codesMatch(body.pin, user.pinHash)) throw new ApiError(401, "PIN_INVALID", "The security PIN is incorrect.");
    const agreement = await prisma.agreement.findFirst({ where: { id: body.agreementId, active: true, code: kind } });
    if (!agreement) throw new ApiError(422, "AGREEMENT_REQUIRED", "Accept the current agreement for this investment.");
    const amountKobo = kobo(body.amount);
    const fee = arrangementFee(kind, amountKobo);
    const holding = await prisma.$transaction(async (tx) => {
      const opportunity = await tx.opportunity.findFirst({ where: { id: req.params.id, kind } });
      if (!opportunity || !["PUBLISHED", "FUNDING", "ACTIVE", "LEASE_ACTIVE"].includes(opportunity.status)) {
        throw new ApiError(422, "OPPORTUNITY_CLOSED", "This opportunity is not open for investment.");
      }
      if (amountKobo < opportunity.minKobo || amountKobo > opportunity.maxKobo) {
        throw new ApiError(422, "AMOUNT_LIMIT", "The amount is outside the investment limits.");
      }
      if (opportunity.fundedKobo + amountKobo > opportunity.targetKobo) {
        throw new ApiError(422, "OPPORTUNITY_FULL", "This opportunity does not have enough remaining capacity.");
      }
      const ledgerRef = await debitAvailable(tx, user.wallet!.id, amountKobo + fee, `${kind}_INVESTMENT`, `${opportunity.name} investment`);
      if (fee > 0) {
        await tx.clientFee.create({
          data: { userId: user.id, name: "Arrangement fee", amountKobo: fee, status: "SUCCESSFUL", reference: reference("FEE"), provider: "wallet", paidAt: new Date() },
        });
      }
      const nextFunded = opportunity.fundedKobo + amountKobo;
      const moved = await tx.opportunity.updateMany({
        where: { id: opportunity.id, fundedKobo: opportunity.fundedKobo },
        data: { fundedKobo: nextFunded, status: nextFunded >= opportunity.targetKobo ? "FULLY_FUNDED" : opportunity.status === "PUBLISHED" ? "FUNDING" : opportunity.status },
      });
      if (moved.count !== 1) throw new ApiError(409, "CONFLICT", "The opportunity changed. Try again.");
      const created = await tx.holding.create({
        data: {
          userId: user.id,
          opportunityId: opportunity.id,
          amountKobo,
          feeKobo: fee,
          reference: ledgerRef,
          maturesAt: new Date(Date.now() + opportunity.durationMonths * 30 * 24 * 3600_000),
        },
      });
      await tx.agreementAcceptance.create({
        data: { userId: user.id, agreementId: agreement.id, holdingId: created.id, reference: reference("AGR") },
      });
      return created;
    });
    await notify(user.id, "Investment recorded", `${kind === "MUDARABAH" ? "Mudarabah" : "Ijarah"} investment ${holding.reference} is active.`);
    await audit(user.id, "INVESTMENT_CREATED", "HOLDING", holding.id, undefined, req.ip);
    return { success: true, message: "Investment created successfully.", data: { id: holding.id, reference: holding.reference, amount: naira(holding.amountKobo), fee: naira(holding.feeKobo) } };
  });
}
