import type { NextFunction, Request, Response } from "express";
import { ZodError } from "zod";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export function ok(message: string, data: unknown = null) {
  return { success: true, message, data };
}

export function fail(message: string, code: string) {
  return { success: false, message, code, data: null };
}

export function send(res: Response, status: number, message: string, data: unknown = null) {
  return res.status(status).json(ok(message, data));
}

export function errorHandler(error: unknown, _req: Request, res: Response, _next: NextFunction) {
  if (error instanceof ZodError) {
    res.status(400).json(fail(error.issues[0]?.message ?? "Check the submitted fields.", "VALIDATION_ERROR"));
    return;
  }
  if (error instanceof ApiError) {
    res.status(error.status).json(fail(error.message, error.code));
    return;
  }
  console.error(error);
  res.status(500).json(fail("The request could not be completed.", "INTERNAL_ERROR"));
}

export function kobo(amount: number) {
  if (!Number.isFinite(amount) || amount < 0) {
    throw new ApiError(400, "INVALID_AMOUNT", "Enter a valid amount.");
  }
  return Math.round(amount * 100);
}

export function naira(amountKobo: number) {
  return amountKobo / 100;
}

export function reference(prefix: string) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  const body = Array.from(bytes, (value) => alphabet[value % alphabet.length]).join("");
  return `${prefix}-${body}`;
}
