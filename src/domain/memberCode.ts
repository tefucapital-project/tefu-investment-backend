import { prisma } from "../db.ts";
import { ApiError } from "../http.ts";

export const MEMBER_CODE_PREFIX = "Tefu-investment-";

export function formatMemberCode(sequence: number) {
  return `${MEMBER_CODE_PREFIX}${String(sequence).padStart(3, "0")}`;
}

function sequenceFromCode(code: string | null | undefined) {
  if (!code) return 0;
  const match = code.match(/^Tefu-investment-(\d+)$/i);
  return match ? Number(match[1]) : 0;
}

export async function nextMemberCode() {
  const rows = await prisma.user.findMany({
    where: { kind: "CLIENT", memberCode: { not: null } },
    select: { memberCode: true },
  });
  let max = 0;
  for (const row of rows) max = Math.max(max, sequenceFromCode(row.memberCode));
  for (let sequence = max + 1; sequence <= max + 1000; sequence += 1) {
    const code = formatMemberCode(sequence);
    const clash = await prisma.user.findFirst({ where: { memberCode: code } });
    if (!clash) return code;
  }
  throw new ApiError(500, "MEMBER_CODE", "Could not allocate a member code.");
}

export async function ensureMemberCode(userId: string) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user || user.kind !== "CLIENT") return null;
  if (user.memberCode) return user.memberCode;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const code = await nextMemberCode();
    try {
      const updated = await prisma.user.update({ where: { id: userId }, data: { memberCode: code } });
      return updated.memberCode;
    } catch {
      /* unique race — try again */
    }
  }
  throw new ApiError(500, "MEMBER_CODE", "Could not assign a member code.");
}

export async function backfillClientMemberCodes() {
  const clients = await prisma.user.findMany({
    where: { kind: "CLIENT" },
    select: { id: true, memberCode: true },
    orderBy: { createdAt: "asc" },
  });
  const missing = clients.filter((row) => !row.memberCode || !/^Tefu-investment-\d+$/i.test(row.memberCode));
  for (const row of missing) {
    await ensureMemberCode(row.id);
  }
  return missing.length;
}
