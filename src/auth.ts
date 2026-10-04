import bcrypt from "bcryptjs";
import { createHash, randomInt, timingSafeEqual } from "node:crypto";
import jwt from "jsonwebtoken";
import { env } from "./config.ts";

export function hashPassword(password: string) {
  return bcrypt.hash(password, 10);
}

export function verifyPassword(password: string, hash: string) {
  return bcrypt.compare(password, hash);
}

export function oneTimeCode() {
  return String(randomInt(0, 1_000_000)).padStart(6, "0");
}

export function hashCode(code: string) {
  return createHash("sha256").update(`${env.jwtSecret}:${code}`).digest("hex");
}

export function codesMatch(code: string, hash: string) {
  const next = Buffer.from(hashCode(code));
  const current = Buffer.from(hash);
  return next.length === current.length && timingSafeEqual(next, current);
}

type AccessClaims = { sub: string; kind: "CLIENT" | "ADMIN"; role: string | null };

export function signAccess(claims: AccessClaims) {
  return jwt.sign(claims, env.jwtSecret, { expiresIn: "15m" });
}

export function signRefresh(userId: string) {
  return jwt.sign({ sub: userId, typ: "refresh" }, env.jwtRefreshSecret, { expiresIn: "7d" });
}

export function readAccess(token: string) {
  return jwt.verify(token, env.jwtSecret) as AccessClaims;
}

export function readRefresh(token: string) {
  return jwt.verify(token, env.jwtRefreshSecret) as { sub: string; typ: string };
}
