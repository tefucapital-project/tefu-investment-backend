import { Router } from "express";
import { z } from "zod";
import { hashPassword, verifyPassword } from "../auth.ts";
import { prisma } from "../db.ts";
import { kycCompletion } from "../domain/kyc.ts";
import { ApiError, naira, send } from "../http.ts";
import { rateLimitAuth, requireKind, requirePermission, requireUser } from "../middleware.ts";
import { audit, notify, sessionFor } from "../services.ts";

export const operations = Router();

const GROUP_MIN = 5;
const GROUP_MAX = 7;

function maskEmail(email: string) {
  return email.replace(/(.{2}).+(@.+)/, "$1***$2");
}

function maskPhone(phone: string | null) {
  if (!phone) return null;
  return `${phone.slice(0, 4)}****${phone.slice(-2)}`;
}

function maskId(value: string | null | undefined) {
  if (!value) return null;
  return value.length <= 4 ? "****" : `****${value.slice(-4)}`;
}

function clientName(user: { firstName: string; middleName?: string | null; lastName: string }) {
  return `${user.firstName} ${user.middleName ? `${user.middleName} ` : ""}${user.lastName}`.replace(/\s+/g, " ").trim();
}

async function activeMemberCount(groupId: string) {
  return prisma.groupMember.count({ where: { groupId, status: "ACTIVE" } });
}

async function logGroupActivity(groupId: string, staffId: string, action: string, affectedMemberId?: string, note?: string) {
  await prisma.groupActivityLog.create({
    data: { groupId, staffId, action, affectedMemberId, note },
  });
}

operations.post("/auth/login", rateLimitAuth, async (req, res) => {
  const body = z.object({ email: z.string().email(), password: z.string().min(1).max(200) }).parse(req.body);
  const user = await prisma.user.findUnique({ where: { email: body.email.toLowerCase() } });
  if (!user || user.kind !== "OPERATIONS" || !user.adminActive) {
    throw new ApiError(401, "INVALID_LOGIN", "Email or password is incorrect.");
  }
  if (user.accountStatus === "SUSPENDED") throw new ApiError(403, "ACCOUNT_SUSPENDED", "This operations account is suspended.");
  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
    throw new ApiError(429, "ACCOUNT_LOCKED", "Too many attempts. Try again shortly.");
  }
  if (!(await verifyPassword(body.password, user.passwordHash))) {
    const failed = user.failedLogins + 1;
    await prisma.user.update({
      where: { id: user.id },
      data: { failedLogins: failed, lockedUntil: failed >= 5 ? new Date(Date.now() + 2 * 60_000) : null },
    });
    throw new ApiError(401, "INVALID_LOGIN", "Email or password is incorrect.");
  }
  await prisma.user.update({ where: { id: user.id }, data: { failedLogins: 0, lockedUntil: null } });
  const tokens = await sessionFor({ id: user.id, kind: "OPERATIONS", role: user.role ?? "OPERATIONS_OFFICER" });
  send(res, 200, "Signed in.", {
    ...tokens,
    name: `${user.firstName} ${user.lastName}`,
    role: user.role,
  });
});

operations.post("/auth/logout", requireUser, requireKind("OPERATIONS"), async (_req, res) => {
  send(res, 200, "Signed out.");
});

const desk = Router();
desk.use(requireUser, requireKind("OPERATIONS"));

desk.get("/me", async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });
  send(res, 200, "Operations profile loaded.", {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    staffId: `OPS-${user.id.slice(-6).toUpperCase()}`,
    role: user.role ?? "OPERATIONS_OFFICER",
    team: "Operations",
  });
});

desk.get("/dashboard", requirePermission("OPS_DASHBOARD"), async (_req, res) => {
  const [
    totalClients,
    activeClients,
    awaitingKyc,
    incompleteKyc,
    pendingFees,
    pendingDeposits,
    pendingWithdrawals,
    activeMudarabah,
    activeIjarah,
    totalGroups,
    activeGroups,
    openTickets,
    failedPayments,
  ] = await Promise.all([
    prisma.user.count({ where: { kind: "CLIENT" } }),
    prisma.user.count({ where: { kind: "CLIENT", accountStatus: "ACTIVE" } }),
    prisma.user.count({ where: { kind: "CLIENT", accountStatus: "KYC_PENDING_REVIEW" } }),
    prisma.user.count({
      where: {
        kind: "CLIENT",
        accountStatus: { in: ["KYC_LOCKED", "KYC_IN_PROGRESS", "OTP_VERIFIED", "REGISTERED"] },
      },
    }),
    prisma.clientFee.count({ where: { name: "Client Onboarding Fee", status: { in: ["PENDING", "PROCESSING"] } } }),
    prisma.payment.count({ where: { purpose: "DEPOSIT", status: { in: ["PENDING", "PROCESSING"] } } }),
    prisma.withdrawal.count({ where: { status: { in: ["PENDING", "APPROVED", "PROCESSING"] } } }),
    prisma.holding.count({ where: { status: "ACTIVE", opportunity: { kind: "MUDARABAH" } } }),
    prisma.holding.count({ where: { status: "ACTIVE", opportunity: { kind: "IJARAH" } } }),
    prisma.userGroup.count(),
    prisma.userGroup.count({ where: { status: "ACTIVE" } }),
    prisma.supportTicket.count({ where: { status: { in: ["OPEN", "IN_PROGRESS"] } } }),
    prisma.payment.count({ where: { status: { in: ["FAILED", "REVERSED"] } } }),
  ]);

  const groupedMembers = await prisma.groupMember.count({ where: { status: "ACTIVE" } });

  const pendingTasks = [
    ...(awaitingKyc ? [{ type: "KYC_REVIEW", label: `${awaitingKyc} KYC application(s) awaiting review`, count: awaitingKyc }] : []),
    ...(pendingFees ? [{ type: "ONBOARDING_FEE", label: `${pendingFees} Client Onboarding Fee payment(s) pending`, count: pendingFees }] : []),
    ...(pendingDeposits ? [{ type: "DEPOSIT", label: `${pendingDeposits} deposit(s) pending confirmation`, count: pendingDeposits }] : []),
    ...(pendingWithdrawals ? [{ type: "WITHDRAWAL", label: `${pendingWithdrawals} withdrawal(s) needing action`, count: pendingWithdrawals }] : []),
    ...(failedPayments ? [{ type: "FAILED_PAYMENT", label: `${failedPayments} failed or reversed payment(s)`, count: failedPayments }] : []),
    ...(openTickets ? [{ type: "SUPPORT", label: `${openTickets} open support ticket(s)`, count: openTickets }] : []),
  ];

  const recentUsers = await prisma.user.findMany({
    where: { kind: "CLIENT" },
    orderBy: { createdAt: "desc" },
    take: 8,
  });
  const recentFees = await prisma.clientFee.findMany({
    where: { name: "Client Onboarding Fee" },
    orderBy: { createdAt: "desc" },
    take: 8,
    include: { user: true },
  });
  const recentTickets = await prisma.supportTicket.findMany({ orderBy: { createdAt: "desc" }, take: 5, include: { user: true } });

  const recentActivity = [
    ...recentUsers.map((user) => ({
      type: "REGISTRATION",
      label: `${clientName(user)} registered`,
      at: user.createdAt,
      ref: user.id,
    })),
    ...recentFees.map((fee) => ({
      type: "ONBOARDING_FEE",
      label: `Client Onboarding Fee ${fee.status.toLowerCase()} for ${clientName(fee.user)}`,
      at: fee.createdAt,
      ref: fee.reference,
    })),
    ...recentTickets.map((ticket) => ({
      type: "SUPPORT",
      label: `Ticket “${ticket.subject}” (${ticket.status})`,
      at: ticket.createdAt,
      ref: ticket.id,
    })),
  ]
    .sort((a, b) => b.at.getTime() - a.at.getTime())
    .slice(0, 20);

  const undersized = await prisma.userGroup.findMany({ where: { status: "ACTIVE" }, include: { members: { where: { status: "ACTIVE" } } } });
  const alerts = [
    ...undersized
      .filter((group) => group.members.length < GROUP_MIN || group.members.length > GROUP_MAX)
      .map((group) => ({
        type: "GROUP_SIZE",
        priority: "HIGH",
        label: `Group “${group.name}” has ${group.members.length} members (requires ${GROUP_MIN}–${GROUP_MAX})`,
        ref: group.id,
      })),
    ...(failedPayments
      ? [{ type: "PAYMENT", priority: "HIGH", label: `${failedPayments} failed or reversed transaction(s) need investigation`, ref: "payments" }]
      : []),
    ...(incompleteKyc
      ? [{ type: "KYC", priority: "MEDIUM", label: `${incompleteKyc} client(s) have incomplete KYC`, ref: "kyc" }]
      : []),
  ];

  send(res, 200, "Operations dashboard loaded.", {
    metrics: [
      { key: "totalClients", label: "Total registered clients", value: String(totalClients) },
      { key: "activeClients", label: "Active clients", value: String(activeClients) },
      { key: "awaitingKyc", label: "Clients awaiting KYC review", value: String(awaitingKyc) },
      { key: "incompleteKyc", label: "Clients with incomplete KYC", value: String(incompleteKyc) },
      { key: "pendingFees", label: "Pending Client Onboarding Fee payments", value: String(pendingFees) },
      { key: "pendingDeposits", label: "Pending deposits", value: String(pendingDeposits) },
      { key: "pendingWithdrawals", label: "Pending withdrawals", value: String(pendingWithdrawals) },
      { key: "activeMudarabah", label: "Active Mudarabah investments", value: String(activeMudarabah) },
      { key: "activeIjarah", label: "Active Ijarah investments", value: String(activeIjarah) },
      { key: "totalGroups", label: "Total user groups", value: String(totalGroups) },
      { key: "activeGroups", label: "Active user groups", value: String(activeGroups) },
      { key: "groupedMembers", label: "Clients assigned to groups", value: String(groupedMembers) },
      { key: "openTickets", label: "Open support tickets", value: String(openTickets) },
      { key: "failedPayments", label: "Failed or reversed transactions", value: String(failedPayments) },
    ],
    pendingTasks: pendingTasks.map((task, index) => ({
      id: `${task.type}-${index}`,
      title: task.label,
      module: task.type,
      priority: task.count > 10 ? "HIGH" : "NORMAL",
    })),
    recentActivity: recentActivity.map((item, index) => ({
      id: `${item.type}-${item.ref}-${index}`,
      summary: item.label,
      actor: "System",
      createdAt: item.at,
    })),
    operationalAlerts: alerts.map((alert, index) => ({
      id: `${alert.type}-${index}`,
      message: alert.label,
      severity: alert.priority,
      createdAt: new Date().toISOString(),
    })),
  });
});

desk.get("/clients", requirePermission("OPS_CLIENT_VIEW"), async (req, res) => {
  const q = String(req.query.q ?? "").trim();
  const status = req.query.status ? String(req.query.status) : undefined;
  const feeStatus = req.query.feeStatus ? String(req.query.feeStatus) : undefined;
  const kycStatus = req.query.kycStatus ? String(req.query.kycStatus) : undefined;
  const page = Math.max(1, Number(req.query.page ?? 1));
  const take = 30;
  const skip = (page - 1) * take;
  const phoneQ = q.replace(/\D/g, "");

  const rows = await prisma.user.findMany({
    where: {
      kind: "CLIENT",
      ...(status ? { accountStatus: status as never } : {}),
      ...(kycStatus ? { kyc: { status: kycStatus as never } } : {}),
      ...(q
        ? {
            OR: [
              { email: { contains: q.toLowerCase() } },
              ...(phoneQ ? [{ phone: { contains: phoneQ } }] : []),
              { firstName: { contains: q } },
              { lastName: { contains: q } },
              { id: q },
            ],
          }
        : {}),
    },
    include: {
      kyc: true,
      fees: { where: { name: "Client Onboarding Fee" }, orderBy: { createdAt: "desc" }, take: 1 },
      groupMemberships: { where: { status: "ACTIVE" }, include: { group: true } },
    },
    orderBy: { createdAt: "desc" },
    skip,
    take,
  });

  const filtered = feeStatus
    ? rows.filter((row) => (row.fees[0]?.status ?? "PENDING") === feeStatus)
    : rows;

  send(res, 200, "Clients loaded.", {
    page,
    items: filtered.map((user) => ({
      id: user.id,
      fullName: clientName(user),
      email: maskEmail(user.email),
      phone: maskPhone(user.phone) ?? "",
      status: user.accountStatus,
      registeredAt: user.createdAt,
      createdAt: user.createdAt,
      verificationStatus: user.accountStatus === "OTP_PENDING" ? "PENDING" : "VERIFIED",
      onboardingFeeStatus: user.fees[0]?.status ?? "PENDING",
      kycStatus: user.kyc?.status ?? "NOT_STARTED",
      accountStatus: user.accountStatus,
      groupName: user.groupMemberships[0]?.group.name,
      groups: user.groupMemberships.map((m) => ({ id: m.group.id, name: m.group.name, role: "MEMBER" })),
      lastActivity: user.updatedAt,
    })),
  });
});

desk.get("/clients/:id", requirePermission("OPS_CLIENT_VIEW"), async (req, res) => {
  const user = await prisma.user.findFirst({
    where: { id: String(req.params.id), kind: "CLIENT" },
    include: {
      kyc: { include: { bankAccounts: true, documents: true } },
      wallet: true,
      fees: { orderBy: { createdAt: "desc" } },
      payments: { orderBy: { createdAt: "desc" }, take: 20 },
      withdrawals: { orderBy: { createdAt: "desc" }, take: 20 },
      holdings: { include: { opportunity: true }, orderBy: { createdAt: "desc" } },
      tickets: { orderBy: { createdAt: "desc" }, take: 20 },
      groupMemberships: { where: { status: "ACTIVE" }, include: { group: true } },
    },
  });
  if (!user) throw new ApiError(404, "CLIENT_NOT_FOUND", "Client was not found.");
  const kyc = user.kyc;
  const parts = kyc
    ? {
        personal: kyc.personalStatus as never,
        nin: kyc.ninStatus as never,
        bvn: kyc.bvnStatus as never,
        bank: kyc.bankStatus as never,
        document: kyc.documentStatus as never,
        identity: kyc.identityStatus as never,
      }
    : null;

  send(res, 200, "Client details loaded.", {
    id: user.id,
    fullName: clientName(user),
    email: maskEmail(user.email),
    phone: maskPhone(user.phone) ?? "",
    status: user.accountStatus,
    accountStatus: user.accountStatus,
    createdAt: user.createdAt,
    registeredAt: user.createdAt,
    address: user.kyc?.address ? `${user.kyc.address}, ${user.kyc.state ?? ""}`.trim() : "Not provided",
    ninMasked: maskId(user.kyc?.ninLast4) ?? "****",
    bvnMasked: maskId(user.kyc?.bvnLast4) ?? "****",
    kycStatus: user.kyc?.status ?? "NOT_STARTED",
    onboardingFeeStatus: user.fees.find((f) => f.name === "Client Onboarding Fee")?.status ?? "PENDING",
    onboardingFees: user.fees.map((fee) => ({
      id: fee.id,
      name: fee.name,
      amount: naira(fee.amountKobo),
      reference: fee.reference,
      status: fee.status,
      paidAt: fee.paidAt,
      createdAt: fee.createdAt,
    })),
    kyc: kyc
      ? {
          status: kyc.status,
          completion: parts ? kycCompletion(parts) : 0,
          parts,
          ninLast4: maskId(kyc.ninLast4),
          bvnLast4: maskId(kyc.bvnLast4),
          rejectionReason: kyc.rejectionReason,
          updateReason: kyc.updateReason,
          banks: kyc.bankAccounts.map((bank) => ({
            id: bank.id,
            bankName: bank.bankName,
            accountName: bank.accountName,
            last4: bank.accountNumber.slice(-4),
            status: bank.status,
            eligible: bank.eligible,
          })),
          documents: kyc.documents.map((doc) => ({ id: doc.id, kind: doc.kind, fileName: doc.fileName, status: doc.status })),
        }
      : null,
    wallet: user.wallet
      ? {
          available: naira(user.wallet.availableKobo),
          locked: naira(user.wallet.lockedKobo),
          balance: naira(user.wallet.balanceKobo),
          currency: user.wallet.currency,
        }
      : null,
    deposits: user.payments
      .filter((p) => p.purpose === "DEPOSIT")
      .map((p) => ({
        id: p.id,
        reference: p.reference,
        amount: naira(p.amountKobo),
        status: p.status,
        createdAt: p.createdAt,
      })),
    withdrawals: user.withdrawals.map((w) => ({
      id: w.id,
      reference: w.reference,
      amount: naira(w.amountKobo),
      fee: naira(w.feeKobo),
      status: w.status,
      createdAt: w.createdAt,
    })),
    investments: user.holdings.map((h) => ({
      id: h.id,
      reference: h.reference,
      type: h.opportunity.kind,
      opportunityName: h.opportunity.name,
      amount: naira(h.amountKobo),
      status: h.status,
      createdAt: h.createdAt,
      maturesAt: h.maturesAt,
    })),
    groups: user.groupMemberships.map((m) => ({
      id: m.group.id,
      name: m.group.name,
      status: m.group.status,
      role: m.group.coordinatorId === user.id ? "COORDINATOR" : "MEMBER",
    })),
    tickets: user.tickets.map((t) => ({
      id: t.id,
      subject: t.subject,
      status: t.status,
      priority: t.priority,
      createdAt: t.createdAt,
    })),
  });
});

desk.get("/groups", requirePermission("OPS_GROUP_MANAGE"), async (req, res) => {
  const q = String(req.query.q ?? "").trim();
  const status = req.query.status ? String(req.query.status) : undefined;
  const rows = await prisma.userGroup.findMany({
    where: {
      ...(status ? { status: status as never } : {}),
      ...(q ? { OR: [{ name: { contains: q } }, { id: q }] } : {}),
    },
    include: {
      members: { where: { status: "ACTIVE" } },
      coordinator: true,
      createdBy: true,
    },
    orderBy: { createdAt: "desc" },
  });
  send(res, 200, "Groups loaded.", {
    items: rows.map((group) => ({
      id: group.id,
      name: group.name,
      description: group.description,
      memberCount: group.members.length,
      capacity: `${group.members.length}/${GROUP_MAX}`,
      coordinatorName: group.coordinator ? clientName(group.coordinator) : "",
      createdAt: group.createdAt,
      createdByName: clientName(group.createdBy),
      status: group.status,
    })),
  });
});

desk.post("/groups", requirePermission("OPS_GROUP_MANAGE"), async (req, res) => {
  const body = z
    .object({
      name: z.string().trim().min(3).max(120),
      description: z.string().trim().max(500).optional(),
      memberIds: z.array(z.string().min(1)).min(GROUP_MIN).max(GROUP_MAX),
      coordinatorId: z.string().optional(),
      status: z.enum(["ACTIVE", "INACTIVE"]).default("ACTIVE"),
    })
    .parse(req.body);

  const uniqueMembers = [...new Set(body.memberIds)];
  if (uniqueMembers.length !== body.memberIds.length) {
    throw new ApiError(422, "DUPLICATE_MEMBERS", "Duplicate members are not allowed in a group.");
  }
  if (uniqueMembers.length < GROUP_MIN || uniqueMembers.length > GROUP_MAX) {
    throw new ApiError(422, "GROUP_SIZE", `An active group must contain ${GROUP_MIN} to ${GROUP_MAX} users.`);
  }
  if (body.coordinatorId && !uniqueMembers.includes(body.coordinatorId)) {
    throw new ApiError(422, "COORDINATOR_NOT_MEMBER", "The coordinator must be a member of the group.");
  }

  const clients = await prisma.user.findMany({ where: { id: { in: uniqueMembers }, kind: "CLIENT" } });
  if (clients.length !== uniqueMembers.length) {
    throw new ApiError(422, "INVALID_MEMBERS", "Only eligible client accounts can be added to a group.");
  }

  const group = await prisma.$transaction(async (tx) => {
    const created = await tx.userGroup.create({
      data: {
        name: body.name,
        description: body.description ?? "",
        status: body.status,
        coordinatorId: body.coordinatorId,
        createdById: req.user!.id,
      },
    });
    await tx.groupMember.createMany({
      data: uniqueMembers.map((clientId) => ({
        groupId: created.id,
        clientId,
        addedById: req.user!.id,
        status: "ACTIVE",
      })),
    });
    await tx.groupActivityLog.create({
      data: {
        groupId: created.id,
        staffId: req.user!.id,
        action: "GROUP_CREATED",
        note: `Created with ${uniqueMembers.length} members`,
      },
    });
    return created;
  });

  await audit(req.user!.id, "OPS_GROUP_CREATED", "UserGroup", group.id, body.name);
  send(res, 201, "Group created.", { id: group.id, name: group.name, status: group.status });
});

desk.get("/groups/:id", requirePermission("OPS_GROUP_MANAGE"), async (req, res) => {
  const group = await prisma.userGroup.findUnique({
    where: { id: String(req.params.id) },
    include: {
      members: { where: { status: "ACTIVE" }, include: { client: true } },
      coordinator: true,
      createdBy: true,
      activities: { orderBy: { createdAt: "desc" }, take: 50, include: { staff: true } },
      announcements: { orderBy: { createdAt: "desc" }, take: 20, include: { sender: true } },
    },
  });
  if (!group) throw new ApiError(404, "GROUP_NOT_FOUND", "Group was not found.");
  send(res, 200, "Group details loaded.", {
    id: group.id,
    name: group.name,
    description: group.description,
    status: group.status,
    memberCount: group.members.length,
    capacity: `${group.members.length}/${GROUP_MAX}`,
    coordinatorId: group.coordinatorId,
    coordinatorName: group.coordinator ? clientName(group.coordinator) : null,
    createdAt: group.createdAt,
    updatedAt: group.updatedAt,
    createdByName: clientName(group.createdBy),
    members: group.members.map((m) => ({
      membershipId: m.id,
      clientId: m.clientId,
      fullName: clientName(m.client),
      email: maskEmail(m.client.email),
      role: group.coordinatorId === m.clientId ? "COORDINATOR" : "MEMBER",
      addedAt: m.addedAt,
    })),
    activity: group.activities.map((a) => ({
      id: a.id,
      action: a.action,
      summary: `${a.action}${a.note ? ` · ${a.note}` : ""}`,
      staffName: clientName(a.staff),
      affectedMemberId: a.affectedMemberId,
      note: a.note,
      createdAt: a.createdAt,
    })),
    announcements: group.announcements.map((a) => ({
      id: a.id,
      title: a.title,
      subject: a.title,
      message: a.message,
      body: a.message,
      senderName: clientName(a.sender),
      sentBy: clientName(a.sender),
      deliveryStatus: a.deliveryStatus,
      sentAt: a.createdAt,
      createdAt: a.createdAt,
    })),
  });
});

desk.patch("/groups/:id", requirePermission("OPS_GROUP_MANAGE"), async (req, res) => {
  const body = z
    .object({
      name: z.string().trim().min(3).max(120).optional(),
      description: z.string().trim().max(500).optional(),
      status: z.enum(["ACTIVE", "INACTIVE", "ARCHIVED"]).optional(),
      coordinatorId: z.string().nullable().optional(),
    })
    .parse(req.body);
  const group = await prisma.userGroup.findUnique({ where: { id: String(req.params.id) } });
  if (!group) throw new ApiError(404, "GROUP_NOT_FOUND", "Group was not found.");

  if (body.status === "ACTIVE") {
    const count = await activeMemberCount(group.id);
    if (count < GROUP_MIN || count > GROUP_MAX) {
      throw new ApiError(422, "GROUP_SIZE", `An active group must contain ${GROUP_MIN} to ${GROUP_MAX} users.`);
    }
  }
  if (body.coordinatorId) {
    const member = await prisma.groupMember.findFirst({
      where: { groupId: group.id, clientId: body.coordinatorId, status: "ACTIVE" },
    });
    if (!member) throw new ApiError(422, "COORDINATOR_NOT_MEMBER", "The coordinator must be a member of the group.");
  }

  const updated = await prisma.userGroup.update({
    where: { id: group.id },
    data: {
      name: body.name,
      description: body.description,
      status: body.status,
      coordinatorId: body.coordinatorId === undefined ? undefined : body.coordinatorId,
    },
  });
  await logGroupActivity(group.id, req.user!.id, "GROUP_UPDATED", undefined, JSON.stringify(body));
  await audit(req.user!.id, "OPS_GROUP_UPDATED", "UserGroup", group.id);
  send(res, 200, "Group updated.", { id: updated.id, status: updated.status });
});

desk.post("/groups/:id/members", requirePermission("OPS_GROUP_MANAGE"), async (req, res) => {
  const body = z.object({ clientId: z.string().min(1) }).parse(req.body);
  const group = await prisma.userGroup.findUnique({ where: { id: String(req.params.id) } });
  if (!group) throw new ApiError(404, "GROUP_NOT_FOUND", "Group was not found.");
  if (group.status === "ARCHIVED") throw new ApiError(422, "GROUP_ARCHIVED", "Archived groups cannot accept new members.");

  const client = await prisma.user.findFirst({ where: { id: body.clientId, kind: "CLIENT" } });
  if (!client) throw new ApiError(404, "CLIENT_NOT_FOUND", "Client was not found.");

  const count = await activeMemberCount(group.id);
  if (count >= GROUP_MAX) {
    throw new ApiError(422, "GROUP_FULL", `This group already has ${GROUP_MAX} members.`);
  }

  const existing = await prisma.groupMember.findUnique({
    where: { groupId_clientId: { groupId: group.id, clientId: body.clientId } },
  });
  if (existing?.status === "ACTIVE") {
    throw new ApiError(409, "ALREADY_MEMBER", "This client is already a member of the group.");
  }

  if (existing) {
    await prisma.groupMember.update({
      where: { id: existing.id },
      data: { status: "ACTIVE", removedAt: null, addedById: req.user!.id, addedAt: new Date() },
    });
  } else {
    await prisma.groupMember.create({
      data: { groupId: group.id, clientId: body.clientId, addedById: req.user!.id, status: "ACTIVE" },
    });
  }
  await logGroupActivity(group.id, req.user!.id, "MEMBER_ADDED", body.clientId);
  await audit(req.user!.id, "OPS_GROUP_MEMBER_ADDED", "UserGroup", group.id, body.clientId);
  send(res, 200, "Member added.", { memberCount: count + 1, capacity: `${count + 1}/${GROUP_MAX}` });
});

desk.delete("/groups/:id/members/:clientId", requirePermission("OPS_GROUP_MANAGE"), async (req, res) => {
  const group = await prisma.userGroup.findUnique({ where: { id: String(req.params.id) } });
  if (!group) throw new ApiError(404, "GROUP_NOT_FOUND", "Group was not found.");
  const clientId = String(req.params.clientId);
  const count = await activeMemberCount(group.id);
  if (group.status === "ACTIVE" && count <= GROUP_MIN) {
    throw new ApiError(
      422,
      "GROUP_MIN_MEMBERS",
      `An active group cannot drop below ${GROUP_MIN} members. Archive or restructure the group first.`,
    );
  }
  const member = await prisma.groupMember.findFirst({ where: { groupId: group.id, clientId, status: "ACTIVE" } });
  if (!member) throw new ApiError(404, "MEMBER_NOT_FOUND", "Member was not found in this group.");

  await prisma.groupMember.update({ where: { id: member.id }, data: { status: "REMOVED", removedAt: new Date() } });
  if (group.coordinatorId === clientId) {
    await prisma.userGroup.update({ where: { id: group.id }, data: { coordinatorId: null } });
  }
  await logGroupActivity(group.id, req.user!.id, "MEMBER_REMOVED", clientId);
  await audit(req.user!.id, "OPS_GROUP_MEMBER_REMOVED", "UserGroup", group.id, clientId);
  send(res, 200, "Member removed.", { memberCount: count - 1, capacity: `${count - 1}/${GROUP_MAX}` });
});

desk.get("/groups/:id/members", requirePermission("OPS_GROUP_MANAGE"), async (req, res) => {
  const group = await prisma.userGroup.findUnique({
    where: { id: String(req.params.id) },
    include: { members: { where: { status: "ACTIVE" }, include: { client: true } } },
  });
  if (!group) throw new ApiError(404, "GROUP_NOT_FOUND", "Group was not found.");
  send(res, 200, "Group members loaded.", {
    coordinatorId: group.coordinatorId ?? "",
    members: group.members.map((m) => ({
      clientId: m.clientId,
      fullName: clientName(m.client),
      role: group.coordinatorId === m.clientId ? "COORDINATOR" : "MEMBER",
    })),
  });
});

desk.put("/groups/:id/members", requirePermission("OPS_GROUP_MANAGE"), async (req, res) => {
  const body = z
    .object({
      memberIds: z.array(z.string().min(1)).min(GROUP_MIN).max(GROUP_MAX),
      replaceClientId: z.string().optional(),
      coordinatorId: z.string().optional(),
    })
    .parse(req.body);
  const group = await prisma.userGroup.findUnique({ where: { id: String(req.params.id) } });
  if (!group) throw new ApiError(404, "GROUP_NOT_FOUND", "Group was not found.");
  if (group.status === "ARCHIVED") throw new ApiError(422, "GROUP_ARCHIVED", "Archived groups cannot change members.");

  const uniqueMembers = [...new Set(body.memberIds)];
  if (uniqueMembers.length < GROUP_MIN || uniqueMembers.length > GROUP_MAX) {
    throw new ApiError(422, "GROUP_SIZE", `An active group must contain ${GROUP_MIN} to ${GROUP_MAX} users.`);
  }
  const clients = await prisma.user.findMany({ where: { id: { in: uniqueMembers }, kind: "CLIENT" } });
  if (clients.length !== uniqueMembers.length) {
    throw new ApiError(422, "INVALID_MEMBERS", "Only eligible client accounts can be added to a group.");
  }
  const coordinatorId = body.coordinatorId ?? group.coordinatorId;
  if (coordinatorId && !uniqueMembers.includes(coordinatorId)) {
    throw new ApiError(422, "COORDINATOR_NOT_MEMBER", "The coordinator must be a member of the group.");
  }

  await prisma.$transaction(async (tx) => {
    const current = await tx.groupMember.findMany({ where: { groupId: group.id, status: "ACTIVE" } });
    const next = new Set(uniqueMembers);
    for (const member of current) {
      if (!next.has(member.clientId)) {
        await tx.groupMember.update({
          where: { id: member.id },
          data: { status: "REMOVED", removedAt: new Date() },
        });
      }
    }
    for (const clientId of uniqueMembers) {
      const existing = await tx.groupMember.findUnique({
        where: { groupId_clientId: { groupId: group.id, clientId } },
      });
      if (existing?.status === "ACTIVE") continue;
      if (existing) {
        await tx.groupMember.update({
          where: { id: existing.id },
          data: { status: "ACTIVE", removedAt: null, addedById: req.user!.id, addedAt: new Date() },
        });
      } else {
        await tx.groupMember.create({
          data: { groupId: group.id, clientId, addedById: req.user!.id, status: "ACTIVE" },
        });
      }
    }
    await tx.userGroup.update({
      where: { id: group.id },
      data: { coordinatorId: coordinatorId ?? null },
    });
    await tx.groupActivityLog.create({
      data: {
        groupId: group.id,
        staffId: req.user!.id,
        action: "MEMBERS_REPLACED",
        note: body.replaceClientId ? `Replaced ${body.replaceClientId}` : `Set ${uniqueMembers.length} members`,
      },
    });
  });

  await audit(req.user!.id, "OPS_GROUP_MEMBERS_UPDATED", "UserGroup", group.id);
  send(res, 200, "Group members updated.", {
    memberCount: uniqueMembers.length,
    capacity: `${uniqueMembers.length}/${GROUP_MAX}`,
  });
});

desk.get("/groups/:id/announcements", requirePermission("OPS_GROUP_ANNOUNCE"), async (req, res) => {
  const rows = await prisma.groupAnnouncement.findMany({
    where: { groupId: String(req.params.id) },
    include: { sender: true },
    orderBy: { createdAt: "desc" },
  });
  send(res, 200, "Announcements loaded.", {
    items: rows.map((a) => ({
      id: a.id,
      subject: a.title,
      body: a.message,
      sentBy: clientName(a.sender),
      sentAt: a.createdAt,
    })),
  });
});

desk.post("/groups/:id/announcements", requirePermission("OPS_GROUP_ANNOUNCE"), async (req, res) => {
  const body = z
    .object({
      title: z.string().trim().min(3).max(120).optional(),
      message: z.string().trim().min(3).max(2000).optional(),
      subject: z.string().trim().min(3).max(120).optional(),
      body: z.string().trim().min(3).max(2000).optional(),
    })
    .parse(req.body);
  const title = body.title ?? body.subject;
  const message = body.message ?? body.body;
  if (!title || !message) throw new ApiError(400, "VALIDATION_ERROR", "Announcement title and message are required.");

  const group = await prisma.userGroup.findUnique({
    where: { id: String(req.params.id) },
    include: { members: { where: { status: "ACTIVE" } } },
  });
  if (!group) throw new ApiError(404, "GROUP_NOT_FOUND", "Group was not found.");
  if (group.status !== "ACTIVE") throw new ApiError(422, "GROUP_INACTIVE", "Announcements can only be sent to active groups.");

  const announcement = await prisma.groupAnnouncement.create({
    data: {
      groupId: group.id,
      title,
      message,
      senderId: req.user!.id,
      deliveryStatus: "SENT",
    },
  });

  for (const member of group.members) {
    await notify(member.clientId, title, message);
  }
  await logGroupActivity(group.id, req.user!.id, "ANNOUNCEMENT_SENT", undefined, announcement.id);
  await audit(req.user!.id, "OPS_GROUP_ANNOUNCEMENT", "GroupAnnouncement", announcement.id, group.id);
  send(res, 201, "Announcement sent.", {
    id: announcement.id,
    title: announcement.title,
    deliveryStatus: announcement.deliveryStatus,
    createdAt: announcement.createdAt,
  });
});

desk.get("/fees", requirePermission("OPS_FEE_VIEW"), async (req, res) => {
  const status = req.query.status ? String(req.query.status) : undefined;
  const q = String(req.query.q ?? "").trim();
  const rows = await prisma.clientFee.findMany({
    where: {
      name: "Client Onboarding Fee",
      ...(status ? { status: status as never } : {}),
      ...(q
        ? {
            OR: [{ reference: { contains: q } }, { user: { email: { contains: q.toLowerCase() } } }, { userId: q }],
          }
        : {}),
    },
    include: { user: true },
    orderBy: { createdAt: "desc" },
    take: 200,
  });
  send(res, 200, "Client Onboarding Fee records loaded.", {
    items: rows.map((fee) => ({
      id: fee.id,
      clientId: fee.userId,
      clientName: clientName(fee.user),
      amount: naira(fee.amountKobo),
      reference: fee.reference,
      method: fee.provider,
      paidAt: fee.paidAt,
      status: fee.status,
      createdAt: fee.createdAt,
    })),
  });
});

desk.get("/kyc", requirePermission("OPS_KYC_VIEW"), async (req, res) => {
  const status = req.query.status ? String(req.query.status) : undefined;
  const rows = await prisma.kycRecord.findMany({
    where: status ? { status: status as never } : undefined,
    include: { user: true },
    orderBy: { updatedAt: "desc" },
    take: 200,
  });
  send(res, 200, "KYC queue loaded.", {
    items: rows.map((kyc) => {
      const parts = {
        personal: kyc.personalStatus as never,
        nin: kyc.ninStatus as never,
        bvn: kyc.bvnStatus as never,
        bank: kyc.bankStatus as never,
        document: kyc.documentStatus as never,
        identity: kyc.identityStatus as never,
      };
      return {
        id: kyc.id,
        clientId: kyc.userId,
        clientName: clientName(kyc.user),
        submittedAt: kyc.submittedAt ?? kyc.createdAt,
        completion: kycCompletion(parts),
        personalStatus: kyc.personalStatus,
        ninStatus: kyc.ninStatus,
        bvnStatus: kyc.bvnStatus,
        bankStatus: kyc.bankStatus,
        documentStatus: kyc.documentStatus,
        selfieStatus: kyc.identityStatus,
        status: kyc.status,
        priority: kyc.status === "KYC_PENDING_REVIEW" ? "HIGH" : "NORMAL",
      };
    }),
  });
});

desk.get("/kyc/:id", requirePermission("OPS_KYC_VIEW"), async (req, res) => {
  const kyc = await prisma.kycRecord.findUnique({
    where: { id: String(req.params.id) },
    include: { user: true, bankAccounts: true, documents: true },
  });
  if (!kyc) throw new ApiError(404, "KYC_NOT_FOUND", "KYC case was not found.");
  const parts = {
    personal: kyc.personalStatus as never,
    nin: kyc.ninStatus as never,
    bvn: kyc.bvnStatus as never,
    bank: kyc.bankStatus as never,
    document: kyc.documentStatus as never,
    identity: kyc.identityStatus as never,
  };
  send(res, 200, "KYC case loaded.", {
    id: kyc.id,
    clientId: kyc.userId,
    clientName: clientName(kyc.user),
    status: kyc.status,
    completion: kycCompletion(parts),
    parts,
    submittedAt: kyc.submittedAt ?? kyc.createdAt,
    nin: { valueMasked: maskId(kyc.ninLast4) ?? "****", status: kyc.ninStatus },
    bvn: { valueMasked: maskId(kyc.bvnLast4) ?? "****", status: kyc.bvnStatus },
    ninLast4: maskId(kyc.ninLast4),
    bvnLast4: maskId(kyc.bvnLast4),
    rejectionReason: kyc.rejectionReason,
    updateReason: kyc.updateReason,
    banks: kyc.bankAccounts.map((bank) => ({
      id: bank.id,
      bankName: bank.bankName,
      accountName: bank.accountName,
      last4: bank.accountNumber.slice(-4),
      status: bank.status,
    })),
    documents: kyc.documents.map((doc) => ({
      id: doc.id,
      type: doc.kind,
      kind: doc.kind,
      fileName: doc.fileName,
      status: doc.status,
      uploadedAt: doc.createdAt,
    })),
    notes: [
      ...(kyc.updateReason
        ? [{ id: "update", body: kyc.updateReason, author: "System", createdAt: kyc.updatedAt }]
        : []),
      ...(kyc.rejectionReason
        ? [{ id: "rejection", body: kyc.rejectionReason, author: "Compliance", createdAt: kyc.reviewedAt ?? kyc.updatedAt }]
        : []),
    ],
    note: "NIN and BVN are required parts of this KYC file, not separate onboarding stages. Only Compliance may approve or reject.",
  });
});

desk.get("/deposits", requirePermission("OPS_DEPOSIT_VIEW"), async (req, res) => {
  const status = req.query.status ? String(req.query.status) : undefined;
  const rows = await prisma.payment.findMany({
    where: { purpose: "DEPOSIT", ...(status ? { status: status as never } : {}) },
    include: { user: true },
    orderBy: { createdAt: "desc" },
    take: 200,
  });
  send(res, 200, "Deposits loaded.", {
    items: rows.map((row) => ({
      id: row.id,
      clientId: row.userId,
      clientName: clientName(row.user),
      amount: naira(row.amountKobo),
      provider: row.provider,
      reference: row.reference,
      status: row.status,
      createdAt: row.createdAt,
    })),
  });
});

desk.get("/withdrawals", requirePermission("OPS_WITHDRAWAL_VIEW"), async (req, res) => {
  const status = req.query.status ? String(req.query.status) : undefined;
  const rows = await prisma.withdrawal.findMany({
    where: status ? { status: status as never } : undefined,
    include: { user: true },
    orderBy: { createdAt: "desc" },
    take: 200,
  });
  const bankIds = [...new Set(rows.map((row) => row.bankAccountId))];
  const banks = await prisma.bankAccount.findMany({ where: { id: { in: bankIds } } });
  const bankMap = new Map(banks.map((bank) => [bank.id, bank]));
  send(res, 200, "Withdrawals loaded.", {
    items: rows.map((row) => {
      const bank = bankMap.get(row.bankAccountId);
      return {
        id: row.id,
        clientId: row.userId,
        clientName: clientName(row.user),
        amount: naira(row.amountKobo),
        fee: naira(row.feeKobo),
        net: naira(row.amountKobo),
        destinationLast4: bank ? bank.accountNumber.slice(-4) : "****",
        bankName: bank?.bankName ?? "Unknown bank",
        reference: row.reference,
        status: row.status,
        createdAt: row.createdAt,
        requestedAt: row.createdAt,
      };
    }),
  });
});

desk.get("/withdrawals/:id", requirePermission("OPS_WITHDRAWAL_VIEW"), async (req, res) => {
  const row = await prisma.withdrawal.findUnique({
    where: { id: String(req.params.id) },
    include: { user: true },
  });
  if (!row) throw new ApiError(404, "WITHDRAWAL_NOT_FOUND", "Withdrawal was not found.");
  const bank = await prisma.bankAccount.findUnique({ where: { id: row.bankAccountId } });
  send(res, 200, "Withdrawal details loaded.", {
    id: row.id,
    clientId: row.userId,
    clientName: clientName(row.user),
    amount: naira(row.amountKobo),
    fee: naira(row.feeKobo),
    net: naira(row.amountKobo),
    destinationLast4: bank ? bank.accountNumber.slice(-4) : "****",
    accountMasked: bank ? `****${bank.accountNumber.slice(-4)}` : "****",
    bankName: bank?.bankName ?? "Unknown bank",
    reference: row.reference,
    status: row.status,
    createdAt: row.createdAt,
    requestedAt: row.createdAt,
    timeline: [
      { id: "requested", label: "Withdrawal requested", at: row.createdAt },
      { id: "status", label: `Current status: ${row.status}`, at: row.updatedAt },
    ],
    note: "Only Finance-authorized staff may approve or process payouts. Operations can monitor and escalate.",
  });
});

desk.get("/investments", requirePermission("OPS_INVESTMENT_VIEW"), async (_req, res) => {
  const opportunities = await prisma.opportunity.findMany({
    include: { holdings: true },
    orderBy: { createdAt: "desc" },
    take: 100,
  });
  const holdings = await prisma.holding.findMany({
    include: { user: true, opportunity: true },
    orderBy: { createdAt: "desc" },
    take: 200,
  });
  send(res, 200, "Investment operations loaded.", {
    items: [
      ...opportunities.map((o) => ({
        id: o.id,
        name: o.name,
        type: o.kind,
        status: o.status,
        target: naira(o.targetKobo),
        funded: naira(o.fundedKobo),
        participants: o.holdings.length,
        activeInvestments: o.holdings.filter((h) => h.status === "ACTIVE").length,
      })),
      ...holdings.map((h) => ({
        id: h.id,
        name: `${clientName(h.user)} · ${h.opportunity.name}`,
        type: h.opportunity.kind,
        status: h.status,
        target: naira(h.amountKobo),
        funded: naira(h.amountKobo),
        participants: 1,
        activeInvestments: h.status === "ACTIVE" ? 1 : 0,
        clientId: h.userId,
        reference: h.reference,
        createdAt: h.createdAt,
        maturesAt: h.maturesAt,
      })),
    ],
    disclaimer: "Mudarabah and Ijarah returns follow the contract and actual results. They are not guaranteed interest.",
  });
});

desk.get("/transactions", requirePermission("OPS_TRANSACTION_VIEW"), async (req, res) => {
  const type = req.query.type ? String(req.query.type) : undefined;
  const status = req.query.status ? String(req.query.status) : undefined;
  const q = String(req.query.q ?? "").trim();
  const payments = await prisma.payment.findMany({
    where: {
      ...(status ? { status: status as never } : {}),
      ...(type ? { purpose: type as never } : {}),
      ...(q ? { OR: [{ reference: { contains: q } }, { userId: q }] } : {}),
    },
    include: { user: true },
    orderBy: { createdAt: "desc" },
    take: 200,
  });
  send(res, 200, "Transactions loaded.", {
    items: payments.map((row) => ({
      id: row.id,
      clientId: row.userId,
      clientName: clientName(row.user),
      type: row.purpose === "ONBOARDING_FEE" ? "Client Onboarding Fee" : row.purpose,
      amount: naira(row.amountKobo),
      reference: row.reference,
      status: row.status,
      createdAt: row.createdAt,
    })),
  });
});

desk.get("/support", requirePermission("OPS_TICKET_MANAGE"), async (req, res) => {
  const status = req.query.status ? String(req.query.status) : undefined;
  const rows = await prisma.supportTicket.findMany({
    where: status ? { status } : undefined,
    include: { user: true, assignee: true },
    orderBy: { createdAt: "desc" },
    take: 200,
  });
  send(res, 200, "Support tickets loaded.", {
    items: rows.map((ticket) => ({
      id: ticket.id,
      clientName: clientName(ticket.user),
      subject: ticket.subject,
      category: ticket.category,
      priority: ticket.priority,
      status: ticket.status,
      assigneeName: ticket.assignee ? clientName(ticket.assignee) : null,
      createdAt: ticket.createdAt,
      updatedAt: ticket.updatedAt,
    })),
  });
});

desk.get("/support/:id", requirePermission("OPS_TICKET_MANAGE"), async (req, res) => {
  const ticket = await prisma.supportTicket.findUnique({
    where: { id: String(req.params.id) },
    include: { user: true, assignee: true, messages: { orderBy: { createdAt: "asc" } } },
  });
  if (!ticket) throw new ApiError(404, "TICKET_NOT_FOUND", "Support ticket was not found.");
  send(res, 200, "Ticket details loaded.", {
    id: ticket.id,
    clientId: ticket.userId,
    clientName: clientName(ticket.user),
    subject: ticket.subject,
    body: ticket.subject,
    category: ticket.category,
    priority: ticket.priority,
    status: ticket.status,
    assigneeName: ticket.assignee ? clientName(ticket.assignee) : null,
    createdAt: ticket.createdAt,
    messages: ticket.messages.map((m) => ({
      id: m.id,
      body: m.body,
      author: m.staff ? "Operations staff" : clientName(ticket.user),
      staff: m.staff,
      createdAt: m.createdAt,
    })),
  });
});

desk.post("/support/:id/reply", requirePermission("OPS_TICKET_MANAGE"), async (req, res) => {
  const body = z
    .object({
      message: z.string().trim().min(1).max(4000),
      internal: z.boolean().optional(),
      status: z.enum(["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"]).optional(),
      priority: z.enum(["LOW", "NORMAL", "HIGH", "URGENT"]).optional(),
    })
    .parse(req.body);
  const ticket = await prisma.supportTicket.findUnique({ where: { id: String(req.params.id) } });
  if (!ticket) throw new ApiError(404, "TICKET_NOT_FOUND", "Support ticket was not found.");
  await prisma.supportMessage.create({
    data: {
      ticketId: ticket.id,
      authorId: req.user!.id,
      body: body.internal ? `[INTERNAL] ${body.message}` : body.message,
      staff: true,
    },
  });
  await prisma.supportTicket.update({
    where: { id: ticket.id },
    data: {
      status: body.status,
      priority: body.priority,
      assigneeId: req.user!.id,
    },
  });
  if (!body.internal) {
    await notify(ticket.userId, "Support reply", body.message);
  }
  await audit(req.user!.id, "OPS_TICKET_REPLY", "SupportTicket", ticket.id);
  send(res, 200, "Reply recorded.");
});

desk.get("/alerts", requirePermission("OPS_ALERT_VIEW"), async (req, res) => {
  const rows = await prisma.notification.findMany({
    where: { userId: req.user!.id },
    orderBy: { createdAt: "desc" },
    take: 100,
  });
  send(res, 200, "Alerts loaded.", {
    items: rows.map((row) => ({
      id: row.id,
      title: row.title,
      body: row.body,
      read: Boolean(row.readAt),
      createdAt: row.createdAt,
    })),
  });
});

desk.post("/alerts/:id/read", requirePermission("OPS_ALERT_VIEW"), async (req, res) => {
  await prisma.notification.updateMany({
    where: { id: String(req.params.id), userId: req.user!.id },
    data: { readAt: new Date() },
  });
  send(res, 200, "Alert marked read.");
});

desk.get("/reports", requirePermission("OPS_REPORT_VIEW"), async (_req, res) => {
  send(res, 200, "Reports catalog loaded.", {
    items: [
      { id: "registrations", name: "Client registration report", description: "New client accounts by date.", path: "/reports/registrations", filename: "registrations.csv" },
      { id: "onboarding-fees", name: "Client Onboarding Fee payment report", description: "Fee payment statuses and references.", path: "/reports/onboarding-fees", filename: "onboarding-fees.csv" },
      { id: "kyc", name: "KYC status report", description: "KYC completion and review statuses.", path: "/reports/kyc", filename: "kyc.csv" },
      { id: "deposits", name: "Deposit report", description: "Wallet deposit activity.", path: "/reports/deposits", filename: "deposits.csv" },
      { id: "withdrawals", name: "Withdrawal report", description: "Withdrawal requests and statuses.", path: "/reports/withdrawals", filename: "withdrawals.csv" },
      { id: "groups", name: "User group membership report", description: "Groups and member counts.", path: "/reports/groups", filename: "groups.csv" },
      { id: "support", name: "Support ticket report", description: "Tickets opened in the period.", path: "/reports/support", filename: "support.csv" },
      { id: "exceptions", name: "Failed payment and exception report", description: "Failed and reversed payments.", path: "/reports/exceptions", filename: "exceptions.csv" },
    ],
  });
});

desk.get("/reports/:kind", requirePermission("OPS_REPORT_VIEW"), async (req, res) => {
  const kind = String(req.params.kind);
  const from = req.query.from ? new Date(String(req.query.from)) : new Date(Date.now() - 30 * 24 * 3600_000);
  const to = req.query.to ? new Date(String(req.query.to)) : new Date();
  let rows: Record<string, unknown>[] = [];

  if (kind === "registrations") {
    const users = await prisma.user.findMany({
      where: { kind: "CLIENT", createdAt: { gte: from, lte: to } },
      orderBy: { createdAt: "desc" },
    });
    rows = users.map((u) => ({ id: u.id, name: clientName(u), email: maskEmail(u.email), status: u.accountStatus, createdAt: u.createdAt }));
  } else if (kind === "onboarding-fees") {
    const fees = await prisma.clientFee.findMany({
      where: { name: "Client Onboarding Fee", createdAt: { gte: from, lte: to } },
      include: { user: true },
      orderBy: { createdAt: "desc" },
    });
    rows = fees.map((f) => ({
      clientId: f.userId,
      clientName: clientName(f.user),
      amount: naira(f.amountKobo),
      reference: f.reference,
      status: f.status,
      createdAt: f.createdAt,
    }));
  } else if (kind === "kyc") {
    const kyc = await prisma.kycRecord.findMany({
      where: { updatedAt: { gte: from, lte: to } },
      include: { user: true },
      orderBy: { updatedAt: "desc" },
    });
    rows = kyc.map((k) => ({ clientId: k.userId, clientName: clientName(k.user), status: k.status, updatedAt: k.updatedAt }));
  } else if (kind === "deposits") {
    const deposits = await prisma.payment.findMany({
      where: { purpose: "DEPOSIT", createdAt: { gte: from, lte: to } },
      include: { user: true },
      orderBy: { createdAt: "desc" },
    });
    rows = deposits.map((d) => ({
      clientId: d.userId,
      clientName: clientName(d.user),
      amount: naira(d.amountKobo),
      reference: d.reference,
      status: d.status,
      createdAt: d.createdAt,
    }));
  } else if (kind === "withdrawals") {
    const withdrawals = await prisma.withdrawal.findMany({
      where: { createdAt: { gte: from, lte: to } },
      include: { user: true },
      orderBy: { createdAt: "desc" },
    });
    rows = withdrawals.map((w) => ({
      clientId: w.userId,
      clientName: clientName(w.user),
      amount: naira(w.amountKobo),
      status: w.status,
      createdAt: w.createdAt,
    }));
  } else if (kind === "groups") {
    const groups = await prisma.userGroup.findMany({
      where: { createdAt: { gte: from, lte: to } },
      include: { members: { where: { status: "ACTIVE" } }, createdBy: true },
      orderBy: { createdAt: "desc" },
    });
    rows = groups.map((g) => ({
      id: g.id,
      name: g.name,
      status: g.status,
      members: g.members.length,
      createdBy: clientName(g.createdBy),
      createdAt: g.createdAt,
    }));
  } else if (kind === "support") {
    const tickets = await prisma.supportTicket.findMany({
      where: { createdAt: { gte: from, lte: to } },
      include: { user: true },
      orderBy: { createdAt: "desc" },
    });
    rows = tickets.map((t) => ({
      id: t.id,
      clientName: clientName(t.user),
      subject: t.subject,
      status: t.status,
      priority: t.priority,
      createdAt: t.createdAt,
    }));
  } else if (kind === "exceptions") {
    const failed = await prisma.payment.findMany({
      where: { status: { in: ["FAILED", "REVERSED"] }, createdAt: { gte: from, lte: to } },
      include: { user: true },
      orderBy: { createdAt: "desc" },
    });
    rows = failed.map((p) => ({
      clientId: p.userId,
      clientName: clientName(p.user),
      purpose: p.purpose,
      reference: p.reference,
      status: p.status,
      amount: naira(p.amountKobo),
      createdAt: p.createdAt,
    }));
  } else {
    throw new ApiError(404, "REPORT_NOT_FOUND", "Unknown report kind.");
  }

  send(res, 200, "Report loaded.", { kind, from, to, rows });
});

desk.get("/audit", requirePermission("OPS_AUDIT_VIEW"), async (req, res) => {
  const rows = await prisma.auditLog.findMany({
    where: {
      OR: [
        { action: { startsWith: "OPS_" } },
        { action: { contains: "KYC" } },
        { action: { contains: "WITHDRAWAL" } },
        { action: { contains: "GROUP" } },
      ],
    },
    orderBy: { createdAt: "desc" },
    take: 200,
  });
  send(res, 200, "Audit activity loaded.", {
    items: rows.map((row) => ({
      id: row.id,
      actorId: row.actorId,
      action: row.action,
      resourceType: row.resourceType,
      resourceId: row.resourceId,
      reason: row.reason,
      createdAt: row.createdAt,
    })),
  });
});

operations.use(desk);

export async function seedOperationsAccount() {
  const passwordHash = await hashPassword("Ops123!");
  const email = "ops@tefuinvestment.com";
  const existing = await prisma.user.findUnique({ where: { email } });
  const user =
    existing ??
    (await prisma.user.create({
      data: {
        kind: "OPERATIONS",
        email,
        phone: "08010000020",
        passwordHash,
        firstName: "Amina",
        lastName: "Okoro",
        role: "OPERATIONS_SUPERVISOR",
        accountStatus: "ACTIVE",
        adminActive: true,
      },
    }));
  if (existing) {
    await prisma.user.update({
      where: { id: existing.id },
      data: {
        kind: "OPERATIONS",
        passwordHash,
        role: "OPERATIONS_SUPERVISOR",
        accountStatus: "ACTIVE",
        adminActive: true,
      },
    });
  }
  return user;
}
