import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Prisma } from "@prisma/client";
import { codesMatch, hashCode, oneTimeCode, signAccess, signRefresh } from "./auth.ts";
import { env } from "./config.ts";
import { prisma } from "./db.ts";
import { ApiError, naira, reference } from "./http.ts";

export type Tx = Prisma.TransactionClient;

const LOCK_MESSAGE = "Complete your Client Onboarding Fee payment to begin KYC verification.";

export async function audit(actorId: string | null, action: string, resourceType: string, resourceId: string, reason?: string, ip?: string) {
  await prisma.auditLog.create({
    data: { actorId, action, resourceType, resourceId, reason, ipAddress: ip },
  });
}

export async function notify(userId: string, title: string, body: string) {
  await prisma.notification.create({ data: { userId, title, body } });
}

export async function issueOtp(userId: string, purpose: string) {
  const latest = await prisma.otpCode.findFirst({
    where: { userId, purpose, usedAt: null },
    orderBy: { createdAt: "desc" },
  });
  if (latest && Date.now() - latest.createdAt.getTime() < 30_000) {
    throw new ApiError(429, "OTP_COOLDOWN", "Wait 30 seconds before requesting another code.");
  }
  await prisma.otpCode.updateMany({ where: { userId, purpose, usedAt: null }, data: { usedAt: new Date() } });
  const code = oneTimeCode();
  await prisma.otpCode.create({
    data: {
      userId,
      purpose,
      codeHash: hashCode(code),
      expiresAt: new Date(Date.now() + 5 * 60_000),
    },
  });
  return code;
}

export async function consumeOtp(userId: string, purpose: string, code: string) {
  const row = await prisma.otpCode.findFirst({
    where: { userId, purpose, usedAt: null },
    orderBy: { createdAt: "desc" },
  });
  if (!row || row.expiresAt.getTime() < Date.now()) {
    throw new ApiError(400, "OTP_EXPIRED", "This code has expired. Request a new one.");
  }
  if (row.attempts >= 5) throw new ApiError(429, "OTP_LOCKED", "Too many attempts. Request a new code.");
  if (!codesMatch(code, row.codeHash)) {
    await prisma.otpCode.update({ where: { id: row.id }, data: { attempts: { increment: 1 } } });
    throw new ApiError(400, "OTP_INVALID", "The code is incorrect.");
  }
  await prisma.otpCode.update({ where: { id: row.id }, data: { usedAt: new Date() } });
}

export async function sessionFor(user: { id: string; kind: "CLIENT" | "ADMIN"; role: string | null }) {
  const refresh = signRefresh(user.id);
  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      tokenHash: hashCode(refresh),
      expiresAt: new Date(Date.now() + 7 * 24 * 3600_000),
    },
  });
  return {
    accessToken: signAccess({ sub: user.id, kind: user.kind, role: user.role }),
    refreshToken: refresh,
  };
}

export function assertKycUnlocked(status: string) {
  if (status === "OTP_PENDING" || status === "REGISTERED" || status === "OTP_VERIFIED" || status === "KYC_LOCKED") {
    throw new ApiError(403, "KYC_LOCKED", LOCK_MESSAGE);
  }
}

export async function debitAvailable(tx: Tx, walletId: string, amountKobo: number, type: string, description: string) {
  const moved = await tx.wallet.updateMany({
    where: { id: walletId, availableKobo: { gte: amountKobo } },
    data: { availableKobo: { decrement: amountKobo }, balanceKobo: { decrement: amountKobo } },
  });
  if (moved.count !== 1) throw new ApiError(409, "INSUFFICIENT_BALANCE", "Available balance is not enough for this transaction.");
  const ref = reference("TX");
  await tx.ledgerEntry.create({
    data: { walletId, reference: ref, type, amountKobo, direction: "DEBIT", status: "COMPLETED", description },
  });
  return ref;
}

export async function creditWallet(tx: Tx, walletId: string, amountKobo: number, type: string, description: string, ref = reference("TX")) {
  await tx.wallet.update({
    where: { id: walletId },
    data: { availableKobo: { increment: amountKobo }, balanceKobo: { increment: amountKobo } },
  });
  await tx.ledgerEntry.create({
    data: { walletId, reference: ref, type, amountKobo, direction: "CREDIT", status: "COMPLETED", description },
  });
  return ref;
}

export async function lockFunds(tx: Tx, walletId: string, amountKobo: number) {
  const moved = await tx.wallet.updateMany({
    where: { id: walletId, availableKobo: { gte: amountKobo } },
    data: { availableKobo: { decrement: amountKobo }, lockedKobo: { increment: amountKobo } },
  });
  if (moved.count !== 1) throw new ApiError(409, "INSUFFICIENT_BALANCE", "Available balance is not enough for this withdrawal.");
}

export async function releaseLock(tx: Tx, walletId: string, amountKobo: number) {
  const moved = await tx.wallet.updateMany({
    where: { id: walletId, lockedKobo: { gte: amountKobo } },
    data: { lockedKobo: { decrement: amountKobo }, availableKobo: { increment: amountKobo } },
  });
  if (moved.count !== 1) throw new ApiError(409, "LOCK_MISSING", "The locked amount could not be released.");
}

export function verifyNin(nin: string) {
  if (!/^\d{11}$/.test(nin)) return "FAILED" as const;
  if (nin.startsWith("000")) return "FAILED" as const;
  if (nin.endsWith("1111")) return "REQUIRES_UPDATE" as const;
  return "VERIFIED" as const;
}

export function verifyBvn(bvn: string) {
  if (!/^\d{11}$/.test(bvn)) return "FAILED" as const;
  if (bvn.startsWith("999")) return "FAILED" as const;
  if (bvn.endsWith("2222")) return "REQUIRES_UPDATE" as const;
  return "VERIFIED" as const;
}

export function verifyBank(accountNumber: string, accountName: string, firstName: string, lastName: string) {
  if (!/^\d{10}$/.test(accountNumber) || accountNumber.startsWith("0000")) return "FAILED" as const;
  const name = accountName.toLowerCase();
  if (!name.includes(firstName.toLowerCase()) || !name.includes(lastName.toLowerCase())) return "FAILED" as const;
  return "VERIFIED" as const;
}

export async function applyProviderResult(referenceId: string, status: "SUCCESSFUL" | "FAILED", eventKey: string) {
  return prisma.$transaction(async (tx) => {
    const seen = await tx.paymentWebhook.findUnique({ where: { eventKey } });
    if (seen) return { duplicate: true as const };
    const payment = await tx.payment.findUnique({ where: { reference: referenceId } });
    if (!payment) throw new ApiError(404, "PAYMENT_NOT_FOUND", "Payment reference was not found.");
    await tx.paymentWebhook.create({
      data: { eventKey, paymentId: payment.id, payload: { reference: referenceId, status } },
    });
    if (payment.applied) return { duplicate: true as const };
    if (status !== "SUCCESSFUL") {
      await tx.payment.update({ where: { id: payment.id }, data: { status } });
      await tx.clientFee.updateMany({ where: { reference: referenceId }, data: { status } });
      return { duplicate: false as const, purpose: payment.purpose, status };
    }
    await tx.payment.update({ where: { id: payment.id }, data: { status: "SUCCESSFUL", applied: true, paidAt: new Date() } });
    if (payment.purpose === "ONBOARDING_FEE") {
      await tx.clientFee.updateMany({ where: { reference: referenceId }, data: { status: "SUCCESSFUL", paidAt: new Date() } });
      const user = await tx.user.findUniqueOrThrow({ where: { id: payment.userId } });
      if (user.accountStatus === "KYC_LOCKED" || user.accountStatus === "OTP_VERIFIED") {
        await tx.user.update({ where: { id: user.id }, data: { accountStatus: "KYC_IN_PROGRESS" } });
        await tx.kycRecord.update({ where: { userId: user.id }, data: { status: "KYC_IN_PROGRESS" } });
      }
    }
    if (payment.purpose === "DEPOSIT") {
      const wallet = await tx.wallet.findUniqueOrThrow({ where: { userId: payment.userId } });
      await creditWallet(tx, wallet.id, payment.amountKobo, "DEPOSIT", "Wallet deposit", referenceId);
    }
    return { duplicate: false as const, purpose: payment.purpose, status: "SUCCESSFUL" as const, userId: payment.userId, amount: naira(payment.amountKobo) };
  });
}

export async function savePrivateFile(userId: string, fileName: string, contentBase64: string) {
  const buffer = Buffer.from(contentBase64, "base64");
  if (buffer.length > 2_000_000) throw new ApiError(400, "FILE_TOO_LARGE", "Files must be 2MB or smaller.");
  const key = path.join(userId, `${reference("DOC")}-${fileName.replace(/[^\w.]+/g, "_")}`);
  const full = path.join(env.storageDir, key);
  await mkdir(path.dirname(full), { recursive: true });
  await writeFile(full, buffer);
  return key;
}

export async function once(userId: string, key: string | undefined, work: () => Promise<Record<string, unknown>>) {
  if (!key) throw new ApiError(400, "IDEMPOTENCY_KEY_REQUIRED", "Send an Idempotency-Key header.");
  const found = await prisma.idempotencyRecord.findUnique({ where: { userId_key: { userId, key } } });
  if (found) {
    const saved = found.response as { pending?: boolean };
    if (saved.pending) throw new ApiError(409, "REQUEST_IN_PROGRESS", "This request is already being processed.");
    return found.response as Record<string, unknown>;
  }
  try {
    await prisma.idempotencyRecord.create({ data: { userId, key, response: { pending: true } } });
  } catch {
    const raced = await prisma.idempotencyRecord.findUnique({ where: { userId_key: { userId, key } } });
    if (!raced) throw new ApiError(409, "DUPLICATE_REQUEST", "This request was already processed.");
    const saved = raced.response as { pending?: boolean };
    if (saved.pending) throw new ApiError(409, "REQUEST_IN_PROGRESS", "This request is already being processed.");
    return raced.response as Record<string, unknown>;
  }
  try {
    const response = await work();
    await prisma.idempotencyRecord.update({
      where: { userId_key: { userId, key } },
      data: { response: response as Prisma.InputJsonValue },
    });
    return response;
  } catch (error) {
    await prisma.idempotencyRecord.delete({ where: { userId_key: { userId, key } } }).catch(() => undefined);
    throw error;
  }
}
