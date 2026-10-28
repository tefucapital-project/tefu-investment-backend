import { prisma } from "../db.ts";
import { ApiError } from "../http.ts";

/** Permanently remove a CLIENT account and related records. */
export async function deleteClientAccount(userId: string) {
  const user = await prisma.user.findFirst({ where: { id: userId, kind: "CLIENT" } });
  if (!user) throw new ApiError(404, "NOT_FOUND", "Client not found.");

  const wallet = await prisma.wallet.findUnique({ where: { userId } });
  const kyc = await prisma.kycRecord.findUnique({ where: { userId } });
  const holdings = await prisma.holding.findMany({ where: { userId }, select: { id: true } });
  const holdingIds = holdings.map((row) => row.id);
  const tickets = await prisma.supportTicket.findMany({ where: { userId }, select: { id: true } });
  const ticketIds = tickets.map((row) => row.id);
  const payments = await prisma.payment.findMany({ where: { userId }, select: { id: true } });
  const paymentIds = payments.map((row) => row.id);

  if (holdingIds.length) {
    await prisma.distributionLine.deleteMany({ where: { holdingId: { in: holdingIds } } });
    await prisma.holding.deleteMany({ where: { id: { in: holdingIds } } });
  }
  if (ticketIds.length) {
    await prisma.supportMessage.deleteMany({ where: { ticketId: { in: ticketIds } } });
    await prisma.supportTicket.deleteMany({ where: { id: { in: ticketIds } } });
  }
  if (paymentIds.length) {
    await prisma.paymentWebhook.deleteMany({ where: { paymentId: { in: paymentIds } } });
    await prisma.payment.deleteMany({ where: { id: { in: paymentIds } } });
  }
  if (wallet) {
    await prisma.ledgerEntry.deleteMany({ where: { walletId: wallet.id } });
    await prisma.wallet.delete({ where: { id: wallet.id } });
  }
  if (kyc) {
    await prisma.bankAccount.deleteMany({ where: { kycId: kyc.id } });
    await prisma.document.deleteMany({ where: { kycId: kyc.id } });
    await prisma.kycRecord.delete({ where: { id: kyc.id } });
  }

  await prisma.document.deleteMany({ where: { userId } });
  await prisma.clientFee.deleteMany({ where: { userId } });
  await prisma.withdrawal.deleteMany({ where: { userId } });
  await prisma.agreementAcceptance.deleteMany({ where: { userId } });
  await prisma.notification.deleteMany({ where: { userId } });
  await prisma.refreshToken.deleteMany({ where: { userId } });
  await prisma.otpCode.deleteMany({ where: { userId } });
  await prisma.idempotencyRecord.deleteMany({ where: { userId } });
  await prisma.groupMember.deleteMany({ where: { clientId: userId } });
  await prisma.creditRequest.deleteMany({ where: { customerId: userId } });
  await prisma.cashierDeposit.deleteMany({ where: { customerId: userId } });
  await prisma.passwordReset.deleteMany({ where: { email: user.email } });
  await prisma.auditLog.updateMany({ where: { actorId: userId }, data: { actorId: null } });

  await prisma.user.delete({ where: { id: userId } });
  return user;
}
