import { Router } from "express";
import { z } from "zod";
import { hashCode, hashPassword, verifyPassword } from "../auth.ts";
import { prisma } from "../db.ts";
import { ApiError, kobo, naira, reference, send } from "../http.ts";
import { rateLimitAuth, rateLimitMoney, requireKind, requireUser } from "../middleware.ts";
import { audit, creditWallet, notify, once, sessionFor } from "../services.ts";
import {
  externalReferenceSchema,
  nairaAmountSchema,
  nonNegativeNairaSchema,
  noteSchema,
  purposeSchema,
  readIdempotencyKey,
} from "../validation.ts";

export const cashier = Router();

function startOfDay(date = new Date()) {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate());
}

function maskAccount(id: string) {
  if (id.length <= 8) return `****${id.slice(-4)}`;
  return `${id.slice(0, 4)}••••${id.slice(-4)}`;
}

function customerEligible(status: string) {
  return status === "ACTIVE" || status === "KYC_APPROVED";
}

function amountInWords(amountKobo: number) {
  const nairaValue = Math.floor(amountKobo / 100);
  return `${nairaValue.toLocaleString("en-NG")} naira`;
}

async function openShift(cashierId: string) {
  const existing = await prisma.cashierShift.findFirst({ where: { cashierId, status: "OPEN" }, orderBy: { openedAt: "desc" } });
  if (existing) return existing;
  return prisma.cashierShift.create({ data: { cashierId, status: "OPEN" } });
}

async function cashierLimits(cashierId: string) {
  const profile = await prisma.cashierProfile.findUnique({ where: { userId: cashierId } });
  if (!profile) throw new ApiError(403, "CASHIER_PROFILE_MISSING", "This cashier profile is not provisioned.");
  return profile;
}

async function todayTotals(cashierId: string) {
  const from = startOfDay();
  const posted = await prisma.creditRequest.findMany({
    where: { cashierId, status: "POSTED", postedAt: { gte: from } },
  });
  const pending = await prisma.creditRequest.count({
    where: { cashierId, status: { in: ["PENDING_APPROVAL", "PENDING_VERIFICATION"] } },
  });
  const rejected = await prisma.creditRequest.count({
    where: { cashierId, status: "REJECTED", updatedAt: { gte: from } },
  });
  const cash = posted.filter((item) => item.source === "CASH").reduce((sum, item) => sum + item.amountKobo, 0);
  const transfers = posted.filter((item) => item.source === "BANK_TRANSFER").reduce((sum, item) => sum + item.amountKobo, 0);
  const total = posted.reduce((sum, item) => sum + item.amountKobo, 0);
  return { postedCount: posted.length, pending, rejected, cashKobo: cash, transferKobo: transfers, totalKobo: total };
}

cashier.post("/auth/login", rateLimitAuth, async (req, res) => {
  const body = z.object({ email: z.string().min(3).max(120), password: z.string().min(1).max(200) }).parse(req.body);
  const identity = body.email.trim().toLowerCase();
  const profile = await prisma.cashierProfile.findFirst({
    where: { OR: [{ staffId: body.email.trim() }, { user: { email: identity } }] },
    include: { user: true },
  });
  const user = profile?.user ?? (await prisma.user.findUnique({ where: { email: identity } }));
  if (!user || user.kind !== "CASHIER" || !user.adminActive) throw new ApiError(401, "INVALID_LOGIN", "Email or password is incorrect.");
  if (user.accountStatus === "SUSPENDED") throw new ApiError(403, "ACCOUNT_SUSPENDED", "This cashier account is suspended.");
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
  await openShift(user.id);
  const tokens = await sessionFor({ id: user.id, kind: "CASHIER", role: "CASHIER" });
  const cashierProfile = await prisma.cashierProfile.findUniqueOrThrow({ where: { userId: user.id } });
  send(res, 200, "Signed in.", {
    ...tokens,
    name: `${user.firstName} ${user.lastName}`,
    staffId: cashierProfile.staffId,
    branch: cashierProfile.branch,
  });
});

cashier.post("/auth/logout", requireUser, requireKind("CASHIER"), async (_req, res) => {
  send(res, 200, "Signed out.");
});

cashier.post("/auth/forgot-password", rateLimitAuth, async (req, res) => {
  const body = z.object({ email: z.string().email() }).parse(req.body);
  const user = await prisma.user.findUnique({ where: { email: body.email.toLowerCase() } });
  if (user?.kind === "CASHIER") {
    await prisma.passwordReset.create({
      data: {
        email: user.email,
        codeHash: hashCode("000000"),
        expiresAt: new Date(Date.now() + 5 * 60_000),
      },
    });
  }
  send(res, 200, "If that email is registered, a reset code was issued.");
});

const desk = Router();
desk.use(requireUser, requireKind("CASHIER"));

desk.get("/me", async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id }, include: { cashierProfile: true } });
  const shift = await openShift(user.id);
  const limits = await cashierLimits(user.id);
  send(res, 200, "Cashier profile loaded.", {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    staffId: limits.staffId,
    branch: limits.branch,
    singleLimit: naira(limits.singleLimitKobo),
    dailyLimit: naira(limits.dailyLimitKobo),
    mfaEnabled: limits.mfaEnabled,
    shift: { id: shift.id, status: shift.status, openedAt: shift.openedAt },
  });
});

desk.get("/dashboard", async (req, res) => {
  const shift = await openShift(req.user!.id);
  const totals = await todayTotals(req.user!.id);
  const latest = await prisma.creditRequest.findMany({
    where: { cashierId: req.user!.id },
    include: { customer: true },
    orderBy: { createdAt: "desc" },
    take: 8,
  });
  send(res, 200, "Dashboard loaded.", {
    shift: { id: shift.id, status: shift.status, openedAt: shift.openedAt },
    totals: {
      postedCredits: naira(totals.totalKobo),
      cashReceived: naira(totals.cashKobo),
      transfersReceived: naira(totals.transferKobo),
      pendingApprovals: totals.pending,
      rejectedCredits: totals.rejected,
      completedTransactions: totals.postedCount,
    },
    latest: latest.map((item) => ({
      id: item.id,
      reference: item.reference,
      amount: naira(item.amountKobo),
      status: item.status,
      source: item.source,
      customerName: `${item.customer.firstName} ${item.customer.lastName}`,
      createdAt: item.createdAt,
    })),
  });
});

desk.get("/customers/search", async (req, res) => {
  const q = String(req.query.q ?? "").trim();
  if (q.length < 2) throw new ApiError(400, "QUERY_REQUIRED", "Enter at least two characters to search.");
  const page = Math.max(1, Number(req.query.page ?? 1));
  const take = 20;
  const skip = (page - 1) * take;
  const phoneQ = q.replace(/\D/g, "");
  const rows = await prisma.user.findMany({
    where: {
      kind: "CLIENT",
      OR: [
        { email: { contains: q.toLowerCase() } },
        ...(phoneQ ? [{ phone: { contains: phoneQ } }] : []),
        { firstName: { contains: q } },
        { lastName: { contains: q } },
        { id: q },
      ],
    },
    include: { wallet: true },
    orderBy: { createdAt: "desc" },
    skip,
    take,
  });
  send(res, 200, "Customers loaded.", {
    page,
    results: rows.map((user) => ({
      id: user.id,
      accountMasked: maskAccount(user.id),
      fullName: `${user.firstName} ${user.middleName ? `${user.middleName} ` : ""}${user.lastName}`.replace(/\s+/g, " ").trim(),
      emailMasked: user.email.replace(/(.{2}).+(@.+)/, "$1***$2"),
      phoneMasked: user.phone ? `${user.phone.slice(0, 4)}****${user.phone.slice(-2)}` : null,
      status: user.accountStatus,
      eligible: customerEligible(user.accountStatus),
      available: user.wallet ? naira(user.wallet.availableKobo) : 0,
    })),
  });
});

desk.get("/customers/:id", async (req, res) => {
  const user = await prisma.user.findFirst({
    where: { id: String(req.params.id), kind: "CLIENT" },
    include: { wallet: true, kyc: true },
  });
  if (!user) throw new ApiError(404, "CUSTOMER_NOT_FOUND", "Customer was not found.");
  const recent = await prisma.creditRequest.findMany({
    where: { customerId: user.id, status: "POSTED" },
    orderBy: { postedAt: "desc" },
    take: 5,
  });
  send(res, 200, "Customer loaded.", {
    id: user.id,
    accountMasked: maskAccount(user.id),
    fullName: `${user.firstName} ${user.middleName ? `${user.middleName} ` : ""}${user.lastName}`.replace(/\s+/g, " ").trim(),
    status: user.accountStatus,
    verificationStatus: user.kyc?.status ?? "NOT_STARTED",
    eligible: customerEligible(user.accountStatus),
    available: user.wallet ? naira(user.wallet.availableKobo) : 0,
    pending: user.wallet ? naira(user.wallet.lockedKobo) : 0,
    restrictions: customerEligible(user.accountStatus) ? [] : [`Account status ${user.accountStatus} blocks ordinary credits.`],
    recentCredits: recent.map((item) => ({
      reference: item.reference,
      amount: naira(item.amountKobo),
      source: item.source,
      postedAt: item.postedAt,
    })),
  });
});

desk.post("/deposits", rateLimitMoney, async (req, res) => {
  const body = z
    .object({
      customerId: z.string().min(1).optional(),
      amount: nairaAmountSchema,
      method: z.enum(["CASH", "BANK_TRANSFER"]),
      externalReference: externalReferenceSchema,
      note: noteSchema,
    })
    .parse(req.body);
  const result = await once(req.user!.id, req.header("idempotency-key"), async () => {
    const amountKobo = kobo(body.amount);
    const shift = await openShift(req.user!.id);
    const externalReference = body.externalReference.trim();
    const existing = await prisma.cashierDeposit.findUnique({ where: { externalReference } });
    if (existing) throw new ApiError(409, "DUPLICATE_REFERENCE", "This external payment reference was already recorded.");
    const deposit = await prisma.cashierDeposit.create({
      data: {
        reference: reference("CDR"),
        customerId: body.customerId,
        cashierId: req.user!.id,
        shiftId: shift.id,
        amountKobo,
        method: body.method,
        externalReference,
        note: body.note,
        verified: body.method === "CASH",
      },
    });
    await prisma.cashierShift.update({
      where: { id: shift.id },
      data:
        body.method === "CASH"
          ? { cashReceivedKobo: { increment: amountKobo } }
          : { transferReceivedKobo: { increment: amountKobo } },
    });
    await audit(req.user!.id, "CASHIER_DEPOSIT_RECORDED", "CashierDeposit", deposit.id, externalReference);
    return {
      success: true,
      message: "Deposit recorded.",
      data: {
        id: deposit.id,
        reference: deposit.reference,
        amount: naira(deposit.amountKobo),
        method: deposit.method,
        externalReference: deposit.externalReference,
        verified: deposit.verified,
      },
    };
  });
  res.status(200).json(result);
});

desk.post("/credits", rateLimitMoney, async (req, res) => {
  const body = z
    .object({
      customerId: z.string().min(1, "Customer is required."),
      amount: nairaAmountSchema,
      source: z.enum(["CASH", "BANK_TRANSFER", "ADJUSTMENT"]),
      externalReference: externalReferenceSchema,
      purpose: purposeSchema,
      evidenceNote: noteSchema,
      confirm: z.literal(true, { errorMap: () => ({ message: "Confirm the credit before submitting." }) }),
    })
    .parse(req.body);
  const idempotencyKey = readIdempotencyKey(req.header("idempotency-key"));
  const result = await once(req.user!.id, idempotencyKey, async () => {
    const amountKobo = kobo(body.amount);
    const limits = await cashierLimits(req.user!.id);
    const shift = await openShift(req.user!.id);
    if (shift.status !== "OPEN") throw new ApiError(409, "SHIFT_CLOSED", "Open a shift before posting credits.");
    if (amountKobo > limits.singleLimitKobo) {
      throw new ApiError(422, "SINGLE_LIMIT", `This credit exceeds the single-transaction limit of ${naira(limits.singleLimitKobo)}.`);
    }
    const totals = await todayTotals(req.user!.id);
    if (totals.totalKobo + amountKobo > limits.dailyLimitKobo) {
      throw new ApiError(422, "DAILY_LIMIT", `This credit would exceed the daily limit of ${naira(limits.dailyLimitKobo)}.`);
    }
    const customer = await prisma.user.findFirst({
      where: { id: body.customerId, kind: "CLIENT" },
      include: { wallet: true },
    });
    if (!customer?.wallet) throw new ApiError(404, "CUSTOMER_NOT_FOUND", "Customer wallet was not found.");
    if (!customerEligible(customer.accountStatus)) {
      throw new ApiError(403, "ACCOUNT_RESTRICTED", "This account cannot receive ordinary cashier credits.");
    }
    if (customer.id === req.user!.id) throw new ApiError(403, "SELF_CREDIT_BLOCKED", "Cashiers cannot credit their own account.");
    const externalReference = body.externalReference.trim();
    const duplicate = await prisma.creditRequest.findUnique({ where: { externalReference } });
    if (duplicate) throw new ApiError(409, "DUPLICATE_REFERENCE", "This external payment reference already exists.");

    const needsApproval = body.source === "ADJUSTMENT" || amountKobo > Math.floor(limits.singleLimitKobo * 0.5);
    const creditRef = reference("CCR");

    if (needsApproval) {
      const pending = await prisma.creditRequest.create({
        data: {
          reference: creditRef,
          idempotencyKey,
          customerId: customer.id,
          cashierId: req.user!.id,
          shiftId: shift.id,
          amountKobo,
          source: body.source,
          externalReference,
          purpose: body.purpose,
          evidenceNote: body.evidenceNote,
          status: "PENDING_APPROVAL",
        },
      });
      await prisma.cashierShift.update({ where: { id: shift.id }, data: { pendingCount: { increment: 1 } } });
      await audit(req.user!.id, "CASHIER_CREDIT_PENDING", "CreditRequest", pending.id, body.purpose);
      return {
        success: true,
        message: "Credit submitted for independent approval.",
        data: {
          id: pending.id,
          reference: pending.reference,
          status: pending.status,
          amount: naira(pending.amountKobo),
          amountWords: amountInWords(pending.amountKobo),
          customerName: `${customer.firstName} ${customer.lastName}`,
          accountMasked: maskAccount(customer.id),
          source: pending.source,
          posted: false,
        },
      };
    }

    const posted = await prisma.$transaction(async (tx) => {
      const created = await tx.creditRequest.create({
        data: {
          reference: creditRef,
          idempotencyKey,
          customerId: customer.id,
          cashierId: req.user!.id,
          shiftId: shift.id,
          amountKobo,
          source: body.source,
          externalReference,
          purpose: body.purpose,
          evidenceNote: body.evidenceNote,
          status: "POSTED",
          ledgerReference: creditRef,
          postedAt: new Date(),
        },
      });
      await creditWallet(tx, customer.wallet!.id, amountKobo, "CASHIER_CREDIT", body.purpose, creditRef);
      await tx.cashierShift.update({
        where: { id: shift.id },
        data: {
          postedCreditsKobo: { increment: amountKobo },
          ...(body.source === "CASH"
            ? { cashReceivedKobo: { increment: amountKobo } }
            : body.source === "BANK_TRANSFER"
              ? { transferReceivedKobo: { increment: amountKobo } }
              : {}),
        },
      });
      return created;
    });

    await notify(customer.id, "Wallet credited", `Your wallet was credited with ₦${naira(amountKobo).toLocaleString("en-NG")}. Ref ${posted.reference}.`);
    await audit(req.user!.id, "CASHIER_CREDIT_POSTED", "CreditRequest", posted.id, body.purpose);
    return {
      success: true,
      message: "Credit posted successfully.",
      data: {
        id: posted.id,
        reference: posted.reference,
        status: posted.status,
        amount: naira(posted.amountKobo),
        amountWords: amountInWords(posted.amountKobo),
        customerName: `${customer.firstName} ${customer.lastName}`,
        accountMasked: maskAccount(customer.id),
        source: posted.source,
        posted: true,
        ledgerReference: posted.ledgerReference,
        postedAt: posted.postedAt,
      },
    };
  });
  res.status(200).json(result);
});

desk.get("/credits", async (req, res) => {
  const status = req.query.status ? String(req.query.status) : undefined;
  const rows = await prisma.creditRequest.findMany({
    where: {
      cashierId: req.user!.id,
      ...(status ? { status: status as never } : {}),
    },
    include: { customer: true },
    orderBy: { createdAt: "desc" },
    take: 100,
  });
  send(res, 200, "Credits loaded.", rows.map((item) => ({
    id: item.id,
    reference: item.reference,
    amount: naira(item.amountKobo),
    source: item.source,
    status: item.status,
    purpose: item.purpose,
    externalReference: item.externalReference,
    customerName: `${item.customer.firstName} ${item.customer.lastName}`,
    accountMasked: maskAccount(item.customerId),
    createdAt: item.createdAt,
    postedAt: item.postedAt,
  })));
});

desk.get("/credits/:id", async (req, res) => {
  const item = await prisma.creditRequest.findFirst({
    where: { id: String(req.params.id), cashierId: req.user!.id },
    include: { customer: true, cashier: true, approver: true },
  });
  if (!item) throw new ApiError(404, "CREDIT_NOT_FOUND", "Credit request was not found.");
  send(res, 200, "Credit details loaded.", {
    id: item.id,
    reference: item.reference,
    idempotencyKey: item.idempotencyKey,
    amount: naira(item.amountKobo),
    amountWords: amountInWords(item.amountKobo),
    source: item.source,
    status: item.status,
    purpose: item.purpose,
    externalReference: item.externalReference,
    evidenceNote: item.evidenceNote,
    ledgerReference: item.ledgerReference,
    rejectionReason: item.rejectionReason,
    customerName: `${item.customer.firstName} ${item.customer.lastName}`,
    accountMasked: maskAccount(item.customerId),
    cashierName: `${item.cashier.firstName} ${item.cashier.lastName}`,
    approverName: item.approver ? `${item.approver.firstName} ${item.approver.lastName}` : null,
    createdAt: item.createdAt,
    postedAt: item.postedAt,
  });
});

desk.get("/pending", async (req, res) => {
  const rows = await prisma.creditRequest.findMany({
    where: { cashierId: req.user!.id, status: "PENDING_APPROVAL" },
    include: { customer: true },
    orderBy: { createdAt: "desc" },
  });
  send(res, 200, "Pending approvals loaded.", rows.map((item) => ({
    id: item.id,
    reference: item.reference,
    amount: naira(item.amountKobo),
    source: item.source,
    purpose: item.purpose,
    evidenceNote: item.evidenceNote,
    customerName: `${item.customer.firstName} ${item.customer.lastName}`,
    createdAt: item.createdAt,
  })));
});

desk.post("/pending/:id/withdraw", async (req, res) => {
  const item = await prisma.creditRequest.findFirst({
    where: { id: String(req.params.id), cashierId: req.user!.id, status: "PENDING_APPROVAL" },
  });
  if (!item) throw new ApiError(404, "CREDIT_NOT_FOUND", "Pending credit was not found.");
  await prisma.creditRequest.update({ where: { id: item.id }, data: { status: "REJECTED", rejectionReason: "Withdrawn by cashier" } });
  if (item.shiftId) {
    await prisma.cashierShift.update({ where: { id: item.shiftId }, data: { pendingCount: { decrement: 1 } } }).catch(() => undefined);
  }
  await audit(req.user!.id, "CASHIER_CREDIT_WITHDRAWN", "CreditRequest", item.id);
  send(res, 200, "Pending credit withdrawn.");
});

desk.get("/reconciliation", async (req, res) => {
  const shift = await openShift(req.user!.id);
  const totals = await todayTotals(req.user!.id);
  send(res, 200, "Reconciliation loaded.", {
    shift: {
      id: shift.id,
      status: shift.status,
      openedAt: shift.openedAt,
      openingFloat: naira(shift.openingFloatKobo),
      cashReceived: naira(shift.cashReceivedKobo || totals.cashKobo),
      transfersReceived: naira(shift.transferReceivedKobo || totals.transferKobo),
      postedCredits: naira(shift.postedCreditsKobo || totals.totalKobo),
      pendingCount: shift.pendingCount || totals.pending,
      countedCash: shift.countedCashKobo == null ? null : naira(shift.countedCashKobo),
      variance: shift.varianceKobo == null ? null : naira(shift.varianceKobo),
      varianceReason: shift.varianceReason,
    },
  });
});

desk.post("/reconciliation/close", rateLimitMoney, async (req, res) => {
  const body = z
    .object({
      countedCash: nonNegativeNairaSchema,
      varianceReason: noteSchema,
      note: noteSchema,
    })
    .parse(req.body);
  const shift = await openShift(req.user!.id);
  const countedCashKobo = kobo(body.countedCash);
  const expected = shift.openingFloatKobo + shift.cashReceivedKobo;
  const varianceKobo = countedCashKobo - expected;
  if (varianceKobo !== 0 && !body.varianceReason?.trim()) {
    throw new ApiError(422, "VARIANCE_REASON_REQUIRED", "Explain the cash variance before closing the shift.");
  }
  const closed = await prisma.cashierShift.update({
    where: { id: shift.id },
    data: {
      status: "CLOSED",
      closedAt: new Date(),
      countedCashKobo,
      varianceKobo,
      varianceReason: body.varianceReason,
      closedNote: body.note,
    },
  });
  await audit(req.user!.id, "CASHIER_SHIFT_CLOSED", "CashierShift", closed.id, body.varianceReason);
  send(res, 200, "Shift closed.", {
    id: closed.id,
    status: closed.status,
    variance: naira(closed.varianceKobo ?? 0),
    closedAt: closed.closedAt,
  });
});

desk.get("/notifications", async (req, res) => {
  const rows = await prisma.notification.findMany({
    where: { userId: req.user!.id },
    orderBy: { createdAt: "desc" },
    take: 50,
  });
  send(res, 200, "Notifications loaded.", rows);
});

desk.post("/profile/password", async (req, res) => {
  const body = z.object({ currentPassword: z.string().min(1), newPassword: z.string().min(8).regex(/[A-Za-z]/).regex(/\d/) }).parse(req.body);
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });
  if (!(await verifyPassword(body.currentPassword, user.passwordHash))) {
    throw new ApiError(401, "PASSWORD_INVALID", "The current password is incorrect.");
  }
  await prisma.user.update({ where: { id: user.id }, data: { passwordHash: await hashPassword(body.newPassword) } });
  await audit(user.id, "CASHIER_PASSWORD_CHANGED", "User", user.id);
  send(res, 200, "Password updated.");
});

cashier.use(desk);

export async function seedCashierAccount() {
  const passwordHash = await hashPassword("Admin123!");
  const email = "cashier@tefuinvestment.com";
  const existing = await prisma.user.findUnique({ where: { email } });
  const user =
    existing ??
    (await prisma.user.create({
      data: {
        kind: "CASHIER",
        email,
        phone: "08010000010",
        passwordHash,
        firstName: "Fatima",
        lastName: "Bello",
        accountStatus: "ACTIVE",
        adminActive: true,
      },
    }));
  if (existing) {
    await prisma.user.update({
      where: { id: existing.id },
      data: { kind: "CASHIER", passwordHash, accountStatus: "ACTIVE", adminActive: true },
    });
  }
  await prisma.cashierProfile.upsert({
    where: { userId: user.id },
    update: { staffId: "CSF-1001", branch: "Lagos Island", singleLimitKobo: 50000000, dailyLimitKobo: 500000000 },
    create: {
      userId: user.id,
      staffId: "CSF-1001",
      branch: "Lagos Island",
      singleLimitKobo: 50000000,
      dailyLimitKobo: 500000000,
    },
  });
  return user;
}
