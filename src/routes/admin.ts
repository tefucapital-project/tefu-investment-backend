import { Router } from "express";
import { z } from "zod";
import { hashPassword, verifyPassword } from "../auth.ts";
import { env } from "../config.ts";
import { prisma } from "../db.ts";
import { kycCompletion, kycReadyForApproval } from "../domain/kyc.ts";
import { splitDistribution } from "../domain/money.ts";
import { ApiError, kobo, naira, reference, send } from "../http.ts";
import { rateLimitAuth, rateLimitMoney, requireKind, requirePermission, requireUser } from "../middleware.ts";
import { audit, creditWallet, debitAvailable, notify, once, releaseLock, sessionFor } from "../services.ts";
import { nairaAmountSchema, purposeSchema } from "../validation.ts";

export const admin = Router();

admin.post("/auth/login", rateLimitAuth, async (req, res) => {
  const body = z.object({ email: z.string().email(), password: z.string().min(1).max(200) }).parse(req.body);
  const user = await prisma.user.findUnique({ where: { email: body.email.toLowerCase() } });
  if (!user || user.kind !== "ADMIN" || !user.adminActive) throw new ApiError(401, "INVALID_LOGIN", "Email or password is incorrect.");
  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) throw new ApiError(429, "ACCOUNT_LOCKED", "Too many attempts. Try again shortly.");
  if (!(await verifyPassword(body.password, user.passwordHash))) {
    const failed = user.failedLogins + 1;
    await prisma.user.update({
      where: { id: user.id },
      data: { failedLogins: failed, lockedUntil: failed >= 5 ? new Date(Date.now() + 2 * 60_000) : null },
    });
    throw new ApiError(401, "INVALID_LOGIN", "Email or password is incorrect.");
  }
  await prisma.user.update({ where: { id: user.id }, data: { failedLogins: 0, lockedUntil: null } });
  const tokens = await sessionFor({ id: user.id, kind: "ADMIN", role: user.role });
  send(res, 200, "Signed in.", { ...tokens, role: user.role, name: `${user.firstName} ${user.lastName}` });
});

admin.post("/auth/logout", requireUser, requireKind("ADMIN"), async (_req, res) => {
  send(res, 200, "Signed out.");
});

const staff = Router();
staff.use(requireUser, requireKind("ADMIN"));

staff.get("/me", async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user!.id } });
  if (!user || user.kind !== "ADMIN") throw new ApiError(401, "UNAUTHORIZED", "Sign in again.");
  send(res, 200, "Admin profile loaded.", {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    name: `${user.firstName} ${user.lastName}`,
    role: user.role,
  });
});

staff.get("/clients", requirePermission("CLIENT_VIEW"), async (_req, res) => {
  const rows = await prisma.user.findMany({
    where: { kind: "CLIENT" },
    include: { kyc: true, wallet: true, holdings: true },
    orderBy: { createdAt: "desc" },
    take: 500,
  });
  send(res, 200, "Clients loaded.", rows.map(clientCard));
});

/** Import clients that only existed in browser demo localStorage (`tefu.investment.user.v1`). */
staff.post("/clients/import-demo", requirePermission("ADMIN_MANAGE"), async (req, res) => {
  const body = z
    .object({
      temporaryPassword: z.string().min(8).max(100).optional(),
      users: z
        .array(
          z.object({
            firstName: z.string().min(1).max(60),
            middleName: z.string().max(60).optional().nullable(),
            lastName: z.string().min(1).max(60),
            email: z.string().email(),
            phone: z.string().min(7).max(30),
            status: z.string().optional(),
            createdAt: z.union([z.number(), z.string()]).optional(),
            referralCode: z.string().optional().nullable(),
          }),
        )
        .min(1)
        .max(500),
    })
    .parse(req.body);

  const temporaryPassword = body.temporaryPassword ?? "DemoRecover123!";
  const passwordHash = await hashPassword(temporaryPassword);
  const created: { email: string; id: string }[] = [];
  const skipped: { email: string; reason: string }[] = [];

  for (const row of body.users) {
    const email = row.email.toLowerCase().trim();
    let phone: string;
    try {
      phone = normalizeNgPhone(row.phone);
    } catch {
      skipped.push({ email, reason: "Invalid Nigerian phone number." });
      continue;
    }
    const existing = await prisma.user.findFirst({ where: { OR: [{ email }, { phone }] } });
    if (existing) {
      skipped.push({ email, reason: existing.email === email ? "Email already exists." : "Phone already exists." });
      continue;
    }
    const accountStatus = mapDemoAccountStatus(row.status);
    const createdAt = parseDemoDate(row.createdAt);
    const user = await prisma.user.create({
      data: {
        kind: "CLIENT",
        email,
        phone,
        passwordHash,
        firstName: row.firstName.trim(),
        middleName: row.middleName?.trim() ?? "",
        lastName: row.lastName.trim(),
        accountStatus,
        referralCode: row.referralCode ?? null,
        acceptedTerms: true,
        acceptedPrivacy: true,
        createdAt,
        wallet: { create: { currency: env.currency } },
        kyc: { create: { status: accountStatus === "ACTIVE" ? "KYC_APPROVED" : "KYC_LOCKED" } },
      },
    });
    await audit(req.user!.id, "DEMO_CLIENT_IMPORTED", "USER", user.id, email, req.ip);
    created.push({ email, id: user.id });
  }

  send(res, 201, "Demo client import finished.", {
    created: created.length,
    skipped: skipped.length,
    temporaryPassword,
    items: created,
    skippedItems: skipped,
  });
});

staff.get("/clients/:id", requirePermission("CLIENT_VIEW"), async (req, res) => {
  const user = await prisma.user.findFirst({
    where: { id: String(req.params.id), kind: "CLIENT" },
    include: { kyc: { include: { bankAccounts: true, documents: true } }, wallet: true, holdings: true },
  });
  if (!user) throw new ApiError(404, "NOT_FOUND", "Client not found.");
  send(res, 200, "Client loaded.", clientCard(user));
});

staff.patch("/clients/:id/status", requirePermission("CLIENT_SUSPEND"), async (req, res) => {
  const body = z.object({ status: z.enum(["ACTIVE", "SUSPENDED"]), reason: z.string().min(3) }).parse(req.body);
  const user = await prisma.user.findFirst({ where: { id: String(req.params.id), kind: "CLIENT" }, include: { kyc: true } });
  if (!user) throw new ApiError(404, "NOT_FOUND", "Client not found.");
  if (body.status === "ACTIVE" && user.kyc?.status !== "KYC_APPROVED") {
    throw new ApiError(422, "KYC_REQUIRED", "Only a KYC-approved client can be activated.");
  }
  await prisma.user.update({ where: { id: user.id }, data: { accountStatus: body.status } });
  await audit(req.user!.id, body.status === "SUSPENDED" ? "CLIENT_SUSPENDED" : "CLIENT_ACTIVATED", "USER", user.id, body.reason, req.ip);
  send(res, 200, "Client status updated.", { status: body.status });
});

staff.get("/kyc", requirePermission("KYC_VIEW"), async (_req, res) => {
  const rows = await prisma.kycRecord.findMany({ include: { user: true }, orderBy: { updatedAt: "desc" }, take: 200 });
  send(res, 200, "KYC queue loaded.", rows.map((row) => ({ id: row.id, client: `${row.user.firstName} ${row.user.lastName}`, status: row.status, completion: completionOf(row) })));
});

staff.get("/kyc/:id", requirePermission("KYC_VIEW"), async (req, res) => {
  const row = await prisma.kycRecord.findUnique({ where: { id: String(req.params.id) }, include: { user: true, documents: true, bankAccounts: true } });
  if (!row) throw new ApiError(404, "NOT_FOUND", "KYC record not found.");
  const fullBank = ["SUPER_ADMIN", "COMPLIANCE_ADMIN", "FINANCE_ADMIN"].includes(req.user!.role ?? "");
  send(res, 200, "KYC loaded.", {
    id: row.id,
    clientId: row.userId,
    status: row.status,
    completion: completionOf(row),
    parts: partsOf(row),
    ninLast4: row.ninLast4,
    bvnLast4: row.bvnLast4,
    banks: row.bankAccounts.map((bank) => ({ id: bank.id, bankName: bank.bankName, accountName: bank.accountName, accountNumber: fullBank ? bank.accountNumber : `••••${bank.accountNumber.slice(-4)}`, status: bank.status })),
    documents: row.documents.map((doc) => ({ id: doc.id, kind: doc.kind, fileName: doc.fileName, status: doc.status })),
  });
});

staff.post("/kyc/:id/approve", requirePermission("KYC_APPROVE"), async (req, res) => {
  const row = await prisma.kycRecord.findUnique({ where: { id: String(req.params.id) }, include: { user: true } });
  if (!row) throw new ApiError(404, "NOT_FOUND", "KYC record not found.");
  const fee = await prisma.clientFee.findFirst({ where: { userId: row.userId, name: "Client Onboarding Fee", status: "SUCCESSFUL" } });
  if (!kycReadyForApproval(partsOf(row), Boolean(fee))) {
    throw new ApiError(422, "KYC_INCOMPLETE", "KYC approval is not permitted because required verification is incomplete or the Client Onboarding Fee is unpaid.");
  }
  await prisma.kycRecord.update({ where: { id: row.id }, data: { status: "KYC_APPROVED", reviewedAt: new Date(), reviewedById: req.user!.id } });
  await prisma.user.update({ where: { id: row.userId }, data: { accountStatus: "ACTIVE" } });
  await audit(req.user!.id, "KYC_APPROVED", "KYC", row.id, undefined, req.ip);
  await notify(row.userId, "Account active", "Your KYC has been approved. You can now fund your wallet and invest.");
  send(res, 200, "KYC approved and the account is active.");
});

staff.post("/kyc/:id/reject", requirePermission("KYC_REJECT"), async (req, res) => {
  const body = z.object({ reason: z.string().min(3) }).parse(req.body);
  const row = await prisma.kycRecord.findUnique({ where: { id: String(req.params.id) } });
  if (!row) throw new ApiError(404, "NOT_FOUND", "KYC record not found.");
  await prisma.kycRecord.update({ where: { id: row.id }, data: { status: "KYC_REJECTED", rejectionReason: body.reason, reviewedAt: new Date(), reviewedById: req.user!.id } });
  await prisma.user.update({ where: { id: row.userId }, data: { accountStatus: "KYC_REJECTED" } });
  await audit(req.user!.id, "KYC_REJECTED", "KYC", row.id, body.reason, req.ip);
  await notify(row.userId, "KYC needs attention", body.reason);
  send(res, 200, "KYC rejected.");
});

staff.post("/kyc/:id/request-update", requirePermission("KYC_REQUEST_UPDATE"), async (req, res) => {
  const body = z.object({ reason: z.string().min(3) }).parse(req.body);
  const row = await prisma.kycRecord.findUnique({ where: { id: String(req.params.id) } });
  if (!row) throw new ApiError(404, "NOT_FOUND", "KYC record not found.");
  await prisma.kycRecord.update({ where: { id: row.id }, data: { status: "KYC_UPDATE_REQUIRED", updateReason: body.reason, reviewedById: req.user!.id } });
  await prisma.user.update({ where: { id: row.userId }, data: { accountStatus: "KYC_UPDATE_REQUIRED" } });
  await audit(req.user!.id, "KYC_UPDATE_REQUESTED", "KYC", row.id, body.reason, req.ip);
  send(res, 200, "Update requested.");
});

staff.get("/fees", requirePermission("FEE_VIEW"), async (_req, res) => {
  const rows = await prisma.clientFee.findMany({ orderBy: { createdAt: "desc" }, take: 200 });
  send(res, 200, "Fees loaded.", rows.map((fee) => ({ id: fee.id, userId: fee.userId, name: fee.name, amount: naira(fee.amountKobo), status: fee.status, reference: fee.reference })));
});

staff.get("/wallets", requirePermission("WALLET_VIEW"), async (_req, res) => {
  const rows = await prisma.wallet.findMany({ include: { user: true }, take: 200 });
  send(res, 200, "Wallets loaded.", rows.map((wallet) => ({ id: wallet.id, client: `${wallet.user.firstName} ${wallet.user.lastName}`, available: naira(wallet.availableKobo), locked: naira(wallet.lockedKobo), balance: naira(wallet.balanceKobo), currency: wallet.currency })));
});

staff.post("/wallets/:id/adjust", requirePermission("WALLET_ADJUST"), rateLimitMoney, async (req, res) => {
  const body = z
    .object({
      amount: nairaAmountSchema,
      direction: z.enum(["CREDIT", "DEBIT"]),
      reason: purposeSchema.min(8, "Reason must be at least 8 characters."),
    })
    .parse(req.body);
  const result = await once(req.user!.id, req.header("idempotency-key"), async () => {
    const wallet = await prisma.wallet.findUnique({ where: { id: String(req.params.id) } });
    if (!wallet) throw new ApiError(404, "NOT_FOUND", "Wallet not found.");
    const amountKobo = kobo(body.amount);
    await prisma.$transaction(async (tx) => {
      if (body.direction === "DEBIT") await debitAvailable(tx, wallet.id, amountKobo, "ADJUSTMENT", body.reason);
      else await creditWallet(tx, wallet.id, amountKobo, "ADJUSTMENT", body.reason);
    });
    await audit(req.user!.id, "WALLET_ADJUSTED", "WALLET", wallet.id, body.reason, req.ip);
    return { success: true, message: "Wallet adjusted.", data: { walletId: wallet.id, amount: body.amount, direction: body.direction } };
  });
  res.status(200).json(result);
});

staff.get("/deposits", requirePermission("DEPOSIT_VIEW"), async (_req, res) => {
  const rows = await prisma.payment.findMany({ where: { purpose: "DEPOSIT" }, orderBy: { createdAt: "desc" }, take: 200 });
  send(res, 200, "Deposits loaded.", rows.map((row) => ({ id: row.id, userId: row.userId, reference: row.reference, amount: naira(row.amountKobo), status: row.status })));
});

staff.get("/withdrawals", requirePermission("WITHDRAWAL_VIEW"), async (_req, res) => {
  const rows = await prisma.withdrawal.findMany({ orderBy: { createdAt: "desc" }, take: 200 });
  send(res, 200, "Withdrawals loaded.", rows.map((row) => ({ id: row.id, userId: row.userId, reference: row.reference, amount: naira(row.amountKobo), fee: naira(row.feeKobo), status: row.status })));
});

staff.post("/withdrawals/:id/approve", requirePermission("WITHDRAWAL_APPROVE"), async (req, res) => {
  const row = await prisma.withdrawal.findUnique({ where: { id: String(req.params.id) }, include: { user: { include: { wallet: true } } } });
  if (!row || row.status !== "PENDING") throw new ApiError(422, "INVALID_STATE", "Only a pending withdrawal can be approved.");
  await prisma.withdrawal.update({ where: { id: row.id }, data: { status: "APPROVED" } });
  await audit(req.user!.id, "WITHDRAWAL_APPROVED", "WITHDRAWAL", row.id, undefined, req.ip);
  send(res, 200, "Withdrawal approved.");
});

staff.post("/withdrawals/:id/complete", requirePermission("WITHDRAWAL_APPROVE"), async (req, res) => {
  const row = await prisma.withdrawal.findUnique({ where: { id: String(req.params.id) }, include: { user: { include: { wallet: true } } } });
  if (!row || (row.status !== "APPROVED" && row.status !== "PROCESSING")) throw new ApiError(422, "INVALID_STATE", "Approve the withdrawal before completing it.");
  await prisma.$transaction(async (tx) => {
    const total = row.amountKobo + row.feeKobo;
    const moved = await tx.wallet.updateMany({
      where: { id: row.user.wallet!.id, lockedKobo: { gte: total } },
      data: { lockedKobo: { decrement: total }, balanceKobo: { decrement: total } },
    });
    if (moved.count !== 1) throw new ApiError(409, "LOCK_MISSING", "Locked funds were not available.");
    await tx.ledgerEntry.create({
      data: { walletId: row.user.wallet!.id, reference: row.reference, type: "WITHDRAWAL", amountKobo: row.amountKobo, direction: "DEBIT", status: "COMPLETED", description: "Withdrawal" },
    });
    if (row.feeKobo > 0) {
      await tx.ledgerEntry.create({
        data: { walletId: row.user.wallet!.id, reference: `${row.reference}-FEE`, type: "OTHER_APPROVED_FEE", amountKobo: row.feeKobo, direction: "DEBIT", status: "COMPLETED", description: "Withdrawal fee" },
      });
    }
    await tx.withdrawal.update({ where: { id: row.id }, data: { status: "COMPLETED" } });
  });
  await notify(row.userId, "Withdrawal completed", `${row.reference} has been paid to your verified bank account.`);
  await audit(req.user!.id, "WITHDRAWAL_COMPLETED", "WITHDRAWAL", row.id, undefined, req.ip);
  send(res, 200, "Withdrawal completed.");
});

staff.post("/withdrawals/:id/reject", requirePermission("WITHDRAWAL_REJECT"), async (req, res) => {
  const body = z.object({ reason: z.string().min(3) }).parse(req.body);
  const row = await prisma.withdrawal.findUnique({ where: { id: String(req.params.id) }, include: { user: { include: { wallet: true } } } });
  if (!row || !["PENDING", "APPROVED", "UNDER_REVIEW"].includes(row.status)) throw new ApiError(422, "INVALID_STATE", "This withdrawal can no longer be rejected.");
  await prisma.$transaction(async (tx) => {
    await releaseLock(tx, row.user.wallet!.id, row.amountKobo + row.feeKobo);
    await tx.withdrawal.update({ where: { id: row.id }, data: { status: "REJECTED", reason: body.reason } });
  });
  await audit(req.user!.id, "WITHDRAWAL_REJECTED", "WITHDRAWAL", row.id, body.reason, req.ip);
  send(res, 200, "Withdrawal rejected and the locked funds were released.");
});

staff.get("/mudarabah", requirePermission("CLIENT_VIEW"), async (_req, res) => {
  send(res, 200, "Mudarabah loaded.", await prisma.opportunity.findMany({ where: { kind: "MUDARABAH" } }));
});

staff.post("/mudarabah", requirePermission("MUDARABAH_CREATE"), async (req, res) => {
  send(res, 201, "Mudarabah draft created.", await createOpportunity(req, "MUDARABAH"));
});

staff.post("/mudarabah/:id/submit", requirePermission("MUDARABAH_CREATE"), async (req, res) => {
  send(res, 200, "Mudarabah submitted for review.", await submitOpportunity(req));
});

staff.post("/mudarabah/:id/approve", requirePermission("MUDARABAH_APPROVE"), async (req, res) => {
  send(res, 200, "Mudarabah approved.", await approveOpportunity(req));
});

staff.post("/mudarabah/:id/publish", requirePermission("MUDARABAH_PUBLISH"), async (req, res) => {
  send(res, 200, "Mudarabah published.", await publishOpportunity(req));
});

staff.get("/ijarah", requirePermission("CLIENT_VIEW"), async (_req, res) => {
  send(res, 200, "Ijarah loaded.", await prisma.opportunity.findMany({ where: { kind: "IJARAH" } }));
});

staff.post("/ijarah", requirePermission("IJARAH_CREATE"), async (req, res) => {
  send(res, 201, "Ijarah draft created.", await createOpportunity(req, "IJARAH"));
});

staff.post("/ijarah/:id/submit", requirePermission("IJARAH_CREATE"), async (req, res) => {
  send(res, 200, "Ijarah submitted for review.", await submitOpportunity(req));
});

staff.post("/ijarah/:id/approve", requirePermission("IJARAH_APPROVE"), async (req, res) => {
  send(res, 200, "Ijarah approved.", await approveOpportunity(req));
});

staff.post("/ijarah/:id/publish", requirePermission("IJARAH_PUBLISH"), async (req, res) => {
  send(res, 200, "Ijarah published.", await publishOpportunity(req));
});

staff.get("/investments", requirePermission("CLIENT_VIEW"), async (_req, res) => {
  const rows = await prisma.holding.findMany({ include: { opportunity: true, user: true }, take: 200, orderBy: { createdAt: "desc" } });
  send(res, 200, "Investments loaded.", rows.map((row) => ({ id: row.id, client: `${row.user.firstName} ${row.user.lastName}`, name: row.opportunity.name, amount: naira(row.amountKobo), status: row.status, reference: row.reference })));
});

staff.get("/distributions", requirePermission("CLIENT_VIEW"), async (_req, res) => {
  const rows = await prisma.distribution.findMany({ orderBy: { createdAt: "desc" }, take: 100 });
  send(res, 200, "Distributions loaded.", rows.map((row) => ({ id: row.id, kind: row.kind, status: row.status, performance: naira(row.performanceKobo), reference: row.reference })));
});

staff.post("/distributions", requirePermission("DISTRIBUTION_CREATE"), async (req, res) => {
  const body = z.object({ opportunityId: z.string(), performance: z.number().positive() }).parse(req.body);
  const opportunity = await prisma.opportunity.findUnique({ where: { id: body.opportunityId } });
  if (!opportunity) throw new ApiError(404, "NOT_FOUND", "Opportunity not found.");
  const holdings = await prisma.holding.findMany({ where: { opportunityId: opportunity.id, status: "ACTIVE" } });
  const shares = splitDistribution({
    kind: opportunity.kind,
    performanceKobo: kobo(body.performance),
    investorShare: opportunity.investorShare,
    capitals: holdings.map((holding) => holding.amountKobo),
  });
  const created = await prisma.distribution.create({
    data: {
      opportunityId: opportunity.id,
      kind: opportunity.kind,
      performanceKobo: kobo(body.performance),
      status: "PENDING_APPROVAL",
      reference: reference("DST"),
      preparedById: req.user!.id,
      lines: { create: holdings.map((holding, index) => ({ holdingId: holding.id, amountKobo: shares[index] ?? 0 })) },
    },
  });
  send(res, 201, "Distribution submitted for approval.", { id: created.id, reference: created.reference });
});

staff.post("/distributions/:id/approve", requirePermission("DISTRIBUTION_APPROVE"), async (req, res) => {
  const row = await prisma.distribution.findUnique({ where: { id: String(req.params.id) } });
  if (!row || row.status !== "PENDING_APPROVAL") throw new ApiError(422, "INVALID_STATE", "This distribution is not waiting for approval.");
  if (row.preparedById === req.user!.id && req.user!.role !== "SUPER_ADMIN") {
    throw new ApiError(403, "SELF_APPROVAL", "Another authorised admin must approve a distribution you prepared.");
  }
  await prisma.distribution.update({ where: { id: row.id }, data: { status: "APPROVED", approvedById: req.user!.id } });
  await audit(req.user!.id, "DISTRIBUTION_APPROVED", "DISTRIBUTION", row.id, undefined, req.ip);
  send(res, 200, "Distribution approved.");
});

staff.post("/distributions/:id/execute", requirePermission("DISTRIBUTION_EXECUTE"), async (req, res) => {
  const row = await prisma.distribution.findUnique({ where: { id: String(req.params.id) }, include: { lines: { include: { holding: { include: { user: { include: { wallet: true } } } } } } } });
  if (!row || (row.status !== "APPROVED" && row.status !== "COMPLETED")) throw new ApiError(422, "INVALID_STATE", "Approve the distribution before executing it.");
  if (row.status === "COMPLETED") {
    send(res, 200, "Distribution was already completed.");
    return;
  }
  const notices: Array<{ userId: string; title: string; body: string }> = [];
  await prisma.$transaction(async (tx) => {
    for (const line of row.lines) {
      if (line.applied || line.amountKobo <= 0) continue;
      const type = row.kind === "MUDARABAH" ? "MUDARABAH_PROFIT" : "IJARAH_RENTAL";
      await creditWallet(tx, line.holding.user.wallet!.id, line.amountKobo, type, `${type} ${row.reference}`, `${row.reference}-${line.id}`);
      await tx.distributionLine.update({ where: { id: line.id }, data: { applied: true } });
      notices.push({
        userId: line.holding.userId,
        title: row.kind === "MUDARABAH" ? "Profit distribution" : "Rental distribution",
        body: `${naira(line.amountKobo)} was credited from recorded ${row.kind === "MUDARABAH" ? "profit" : "rent"}.`,
      });
    }
    await tx.distribution.update({ where: { id: row.id }, data: { status: "COMPLETED" } });
  });
  for (const notice of notices) await notify(notice.userId, notice.title, notice.body);
  await audit(req.user!.id, "DISTRIBUTION_COMPLETED", "DISTRIBUTION", row.id, undefined, req.ip);
  send(res, 200, "Distribution completed.");
});

staff.get("/documents", requirePermission("DOCUMENT_REVIEW"), async (_req, res) => {
  const rows = await prisma.document.findMany({ orderBy: { createdAt: "desc" }, take: 200 });
  send(res, 200, "Documents loaded.", rows.map((doc) => ({ id: doc.id, userId: doc.userId, kind: doc.kind, fileName: doc.fileName, status: doc.status })));
});

staff.patch("/documents/:id/status", requirePermission("DOCUMENT_REVIEW"), async (req, res) => {
  const body = z.object({ status: z.enum(["APPROVED", "REJECTED", "REQUIRES_UPDATE"]) }).parse(req.body);
  const doc = await prisma.document.findUnique({ where: { id: String(req.params.id) } });
  if (!doc) throw new ApiError(404, "NOT_FOUND", "Document not found.");
  await prisma.document.update({ where: { id: doc.id }, data: { status: body.status } });
  const mapped = body.status === "APPROVED" ? "VERIFIED" : body.status === "REJECTED" ? "FAILED" : "REQUIRES_UPDATE";
  const field = doc.kind === "SELFIE" ? "identityStatus" : "documentStatus";
  if (doc.kycId) await prisma.kycRecord.update({ where: { id: doc.kycId }, data: { [field]: mapped } });
  send(res, 200, "Document status updated.");
});

staff.get("/support/tickets", requirePermission("TICKET_MANAGE"), async (_req, res) => {
  send(res, 200, "Tickets loaded.", await prisma.supportTicket.findMany({ orderBy: { createdAt: "desc" }, take: 100 }));
});

staff.post("/support/tickets/:id/reply", requirePermission("TICKET_MANAGE"), async (req, res) => {
  const body = z.object({ message: z.string().min(1), status: z.string().optional() }).parse(req.body);
  const ticket = await prisma.supportTicket.findUnique({ where: { id: String(req.params.id) } });
  if (!ticket) throw new ApiError(404, "NOT_FOUND", "Ticket not found.");
  await prisma.supportMessage.create({ data: { ticketId: ticket.id, authorId: req.user!.id, body: body.message, staff: true } });
  if (body.status) await prisma.supportTicket.update({ where: { id: ticket.id }, data: { status: body.status } });
  send(res, 201, "Reply sent.");
});

staff.post("/notifications", requirePermission("NOTIFICATION_SEND"), async (req, res) => {
  const body = z.object({ userId: z.string(), title: z.string().min(2), body: z.string().min(2) }).parse(req.body);
  await notify(body.userId, body.title, body.body);
  send(res, 201, "Notification sent.");
});

staff.get("/reports/:kind", requirePermission("REPORT_VIEW"), async (req, res) => {
  const kind = String(req.params.kind);
  const [clients, active, deposits, withdrawals, invested, distributed] = await Promise.all([
    prisma.user.count({ where: { kind: "CLIENT" } }),
    prisma.user.count({ where: { kind: "CLIENT", accountStatus: "ACTIVE" } }),
    prisma.payment.aggregate({ where: { purpose: "DEPOSIT", status: "SUCCESSFUL" }, _sum: { amountKobo: true } }),
    prisma.withdrawal.aggregate({ where: { status: "COMPLETED" }, _sum: { amountKobo: true } }),
    prisma.holding.aggregate({ _sum: { amountKobo: true } }),
    prisma.distributionLine.aggregate({ where: { applied: true }, _sum: { amountKobo: true } }),
  ]);
  send(res, 200, "Report loaded.", {
    kind,
    clients,
    activeClients: active,
    deposits: naira(deposits._sum.amountKobo ?? 0),
    withdrawals: naira(withdrawals._sum.amountKobo ?? 0),
    invested: naira(invested._sum.amountKobo ?? 0),
    distributed: naira(distributed._sum.amountKobo ?? 0),
    currency: env.currency,
  });
});

staff.get("/reconciliation", requirePermission("RECONCILIATION_VIEW"), async (_req, res) => {
  const wallets = await prisma.wallet.findMany();
  const broken = wallets.filter((wallet) => wallet.balanceKobo !== wallet.availableKobo + wallet.lockedKobo);
  const deposits = await prisma.payment.findMany({ where: { purpose: "DEPOSIT", status: "SUCCESSFUL" } });
  const credits = await prisma.ledgerEntry.findMany({ where: { type: "DEPOSIT", direction: "CREDIT" } });
  const creditRefs = new Set(credits.map((entry) => entry.reference));
  const unmatched = deposits.filter((payment) => !creditRefs.has(payment.reference));
  send(res, 200, "Reconciliation loaded.", {
    balanceMismatches: broken.map((wallet) => wallet.id),
    unmatchedDeposits: unmatched.map((payment) => payment.reference),
  });
});

staff.get("/audit-logs", requirePermission("AUDIT_VIEW"), async (_req, res) => {
  const rows = await prisma.auditLog.findMany({ orderBy: { createdAt: "desc" }, take: 200 });
  send(res, 200, "Audit log loaded.", rows);
});

staff.get("/settings", requirePermission("SETTINGS_MANAGE"), async (_req, res) => {
  send(res, 200, "Settings loaded.", await prisma.systemSetting.findMany());
});

staff.post("/admins", requirePermission("ADMIN_MANAGE"), async (req, res) => {
  const body = z.object({
    firstName: z.string().min(2),
    lastName: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(8),
    role: z.enum(["SUPER_ADMIN", "COMPLIANCE_ADMIN", "INVESTMENT_ADMIN", "FINANCE_ADMIN", "SUPPORT_ADMIN"]),
  }).parse(req.body);
  const created = await prisma.user.create({
    data: {
      kind: "ADMIN",
      email: body.email.toLowerCase(),
      passwordHash: await hashPassword(body.password),
      firstName: body.firstName,
      lastName: body.lastName,
      role: body.role,
      accountStatus: "ACTIVE",
    },
  });
  await audit(req.user!.id, "ADMIN_CREATED", "USER", created.id, body.role, req.ip);
  send(res, 201, "Admin created.", { id: created.id, email: created.email, role: created.role });
});

admin.use(staff);

function normalizeNgPhone(value: string) {
  const digits = value.replace(/\D/g, "");
  if (digits.startsWith("234") && digits.length === 13) return `+${digits}`;
  if (digits.startsWith("0") && digits.length === 11) return `+234${digits.slice(1)}`;
  if (digits.length === 10) return `+234${digits}`;
  throw new Error("invalid phone");
}

function mapDemoAccountStatus(status?: string) {
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

function parseDemoDate(value?: number | string) {
  if (typeof value === "number" && Number.isFinite(value)) return new Date(value);
  if (typeof value === "string" && value.trim()) {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return new Date(parsed);
  }
  return new Date();
}

function clientCard(user: {
  id: string;
  firstName: string;
  middleName?: string | null;
  lastName: string;
  email: string;
  phone?: string | null;
  accountStatus: string;
  createdAt: Date;
  updatedAt?: Date;
  kyc?: {
    status: string;
    dateOfBirth?: string | null;
    gender?: string | null;
    nationality?: string | null;
    address?: string | null;
    state?: string | null;
    lga?: string | null;
    ninLast4?: string | null;
    ninReference?: string | null;
    ninStatus?: string;
    bvnLast4?: string | null;
    bvnReference?: string | null;
    bvnStatus?: string;
    personalStatus?: string;
    bankStatus?: string;
    documentStatus?: string;
    identityStatus?: string;
    rejectionReason?: string | null;
    updateReason?: string | null;
    submittedAt?: Date | null;
    reviewedAt?: Date | null;
    reviewedById?: string | null;
    bankAccounts?: { bankName: string; accountNumber: string; accountName: string; status: string }[];
    documents?: { kind: string; status: string; fileName: string }[];
  } | null;
  wallet?: { availableKobo: number; lockedKobo: number; balanceKobo: number } | null;
  holdings?: { amountKobo: number; status: string }[];
}) {
  const bank = user.kyc?.bankAccounts?.[0];
  const investedKobo = (user.holdings ?? [])
    .filter((holding) => holding.status !== "SUSPENDED")
    .reduce((sum, holding) => sum + holding.amountKobo, 0);
  return {
    id: user.id,
    firstName: user.firstName,
    middleName: user.middleName ?? "",
    lastName: user.lastName,
    name: `${user.firstName} ${user.lastName}`.trim(),
    email: user.email,
    phone: user.phone ?? "",
    status: user.accountStatus,
    accountStatus: user.accountStatus,
    createdAt: user.createdAt.toISOString(),
    updatedAt: user.updatedAt?.toISOString() ?? user.createdAt.toISOString(),
    kycStatus: user.kyc?.status ?? "KYC_LOCKED",
    kyc: user.kyc
      ? {
          status: user.kyc.status,
          personalStatus: user.kyc.personalStatus ?? "NOT_STARTED",
          ninStatus: user.kyc.ninStatus ?? "NOT_STARTED",
          bvnStatus: user.kyc.bvnStatus ?? "NOT_STARTED",
          bankStatus: user.kyc.bankStatus ?? "NOT_STARTED",
          documentStatus: user.kyc.documentStatus ?? "NOT_STARTED",
          identityStatus: user.kyc.identityStatus ?? "NOT_STARTED",
          dateOfBirth: user.kyc.dateOfBirth ?? "",
          gender: user.kyc.gender ?? "",
          nationality: user.kyc.nationality ?? "",
          address: user.kyc.address ?? "",
          state: user.kyc.state ?? "",
          lga: user.kyc.lga ?? "",
          ninLast4: user.kyc.ninLast4 ?? "",
          ninReference: user.kyc.ninReference ?? "",
          bvnLast4: user.kyc.bvnLast4 ?? "",
          bvnReference: user.kyc.bvnReference ?? "",
          rejectionReason: user.kyc.rejectionReason ?? "",
          updateReason: user.kyc.updateReason ?? "",
          submittedAt: user.kyc.submittedAt?.toISOString() ?? null,
          reviewedAt: user.kyc.reviewedAt?.toISOString() ?? null,
          reviewedById: user.kyc.reviewedById ?? "",
          bank: bank
            ? {
                bankName: bank.bankName,
                accountNumber: bank.accountNumber,
                accountName: bank.accountName,
                status: bank.status,
              }
            : null,
        }
      : null,
    wallet: user.wallet
      ? {
          available: naira(user.wallet.availableKobo),
          locked: naira(user.wallet.lockedKobo),
          balance: naira(user.wallet.balanceKobo),
        }
      : { available: 0, locked: 0, balance: 0 },
    invested: naira(investedKobo),
  };
}

function partsOf(row: { personalStatus: "NOT_STARTED" | "PENDING" | "VERIFIED" | "FAILED" | "REQUIRES_UPDATE" | "COMPLETE"; ninStatus: "NOT_STARTED" | "PENDING" | "VERIFIED" | "FAILED" | "REQUIRES_UPDATE" | "COMPLETE"; bvnStatus: "NOT_STARTED" | "PENDING" | "VERIFIED" | "FAILED" | "REQUIRES_UPDATE" | "COMPLETE"; bankStatus: "NOT_STARTED" | "PENDING" | "VERIFIED" | "FAILED" | "REQUIRES_UPDATE" | "COMPLETE"; documentStatus: "NOT_STARTED" | "PENDING" | "VERIFIED" | "FAILED" | "REQUIRES_UPDATE" | "COMPLETE"; identityStatus: "NOT_STARTED" | "PENDING" | "VERIFIED" | "FAILED" | "REQUIRES_UPDATE" | "COMPLETE" }) {
  return { personal: row.personalStatus, nin: row.ninStatus, bvn: row.bvnStatus, bank: row.bankStatus, document: row.documentStatus, identity: row.identityStatus };
}

function completionOf(row: Parameters<typeof partsOf>[0]) {
  return kycCompletion(partsOf(row));
}

const opportunityBody = z.object({
  name: z.string().min(3),
  summary: z.string().min(3),
  minimum: z.number().positive(),
  maximum: z.number().positive(),
  target: z.number().positive(),
  durationMonths: z.number().int().positive(),
  investorShare: z.number().int().min(1).max(100).optional(),
  risk: z.string().min(3),
  shariah: z.string().min(3),
});

async function createOpportunity(req: { body: unknown; user?: { id: string } }, kind: "MUDARABAH" | "IJARAH") {
  const body = opportunityBody.parse(req.body);
  if (/interest/i.test(`${body.shariah} ${body.summary}`)) {
    throw new ApiError(422, "SHARIAH_LANGUAGE", "Describe profit-sharing or rental from actual performance. Do not describe a guaranteed interest return.");
  }
  return prisma.opportunity.create({
    data: {
      kind,
      name: body.name,
      summary: body.summary,
      minKobo: kobo(body.minimum),
      maxKobo: kobo(body.maximum),
      targetKobo: kobo(body.target),
      durationMonths: body.durationMonths,
      investorShare: body.investorShare ?? (kind === "MUDARABAH" ? 70 : 100),
      risk: body.risk,
      shariah: body.shariah,
      createdById: req.user!.id,
      status: "DRAFT",
    },
  });
}

async function submitOpportunity(req: { params: { id?: string } }) {
  const row = await prisma.opportunity.findUnique({ where: { id: String(req.params.id) } });
  if (!row || row.status !== "DRAFT") throw new ApiError(422, "INVALID_STATE", "Only a draft opportunity can be submitted.");
  return prisma.opportunity.update({ where: { id: row.id }, data: { status: "PENDING_REVIEW" } });
}

async function approveOpportunity(req: { params: { id?: string }; user?: { id: string; role: string | null }; ip?: string }) {
  const row = await prisma.opportunity.findUnique({ where: { id: String(req.params.id) } });
  if (!row || row.status !== "PENDING_REVIEW") throw new ApiError(422, "INVALID_STATE", "Submit the opportunity for review before approval.");
  if (row.createdById === req.user!.id && req.user!.role !== "SUPER_ADMIN") {
    throw new ApiError(403, "SELF_APPROVAL", "Another authorised admin must approve an opportunity you created.");
  }
  const updated = await prisma.opportunity.update({ where: { id: row.id }, data: { status: "APPROVED", approvedById: req.user!.id } });
  await audit(req.user!.id, "OPPORTUNITY_APPROVED", "OPPORTUNITY", row.id, undefined, req.ip);
  return updated;
}

async function publishOpportunity(req: { params: { id?: string }; user?: { id: string; role: string | null }; ip?: string }) {
  const row = await prisma.opportunity.findUnique({ where: { id: String(req.params.id) } });
  if (!row || row.status !== "APPROVED") throw new ApiError(422, "INVALID_STATE", "An opportunity can be published only after approval.");
  const updated = await prisma.opportunity.update({ where: { id: row.id }, data: { status: "FUNDING" } });
  await audit(req.user!.id, "OPPORTUNITY_PUBLISHED", "OPPORTUNITY", row.id, undefined, req.ip);
  return updated;
}
