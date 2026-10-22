import { z } from "zod";
import { ApiError } from "./http.ts";

export const idempotencyKeySchema = z
  .string({ required_error: "Send an Idempotency-Key header." })
  .trim()
  .min(8, "Idempotency-Key must be at least 8 characters.")
  .max(128, "Idempotency-Key must be at most 128 characters.")
  .regex(/^[A-Za-z0-9._:-]+$/, "Idempotency-Key may only contain letters, numbers, '.', '_', ':', and '-'.");

export const nairaAmountSchema = z
  .number({
    required_error: "Amount is required.",
    invalid_type_error: "Amount must be a number.",
  })
  .finite("Amount must be a finite number.")
  .positive("Amount must be greater than zero.")
  .max(50_000_000, "Amount exceeds the maximum allowed value.")
  .refine((value) => Math.abs(value * 100 - Math.round(value * 100)) < 1e-8, {
    message: "Amount can have at most 2 decimal places.",
  });

export const nonNegativeNairaSchema = z
  .number({
    required_error: "Amount is required.",
    invalid_type_error: "Amount must be a number.",
  })
  .finite("Amount must be a finite number.")
  .min(0, "Amount cannot be negative.")
  .max(50_000_000, "Amount exceeds the maximum allowed value.")
  .refine((value) => Math.abs(value * 100 - Math.round(value * 100)) < 1e-8, {
    message: "Amount can have at most 2 decimal places.",
  });

export const externalReferenceSchema = z
  .string({ required_error: "External reference is required." })
  .trim()
  .min(3, "External reference must be at least 3 characters.")
  .max(120, "External reference must be at most 120 characters.")
  .regex(/^[A-Za-z0-9][A-Za-z0-9 ._\-/:#]*$/, "External reference contains invalid characters.");

export const purposeSchema = z
  .string({ required_error: "Purpose is required." })
  .trim()
  .min(3, "Purpose must be at least 3 characters.")
  .max(200, "Purpose must be at most 200 characters.");

export const noteSchema = z
  .string()
  .trim()
  .max(500, "Note must be at most 500 characters.")
  .optional();

export const pinSchema = z
  .string({ required_error: "PIN is required." })
  .regex(/^\d{4}$/, "PIN must be exactly 4 digits.");

export function readIdempotencyKey(header: string | undefined) {
  const parsed = idempotencyKeySchema.safeParse(header);
  if (!parsed.success) {
    throw new ApiError(400, "IDEMPOTENCY_KEY_REQUIRED", parsed.error.issues[0]?.message ?? "Send a valid Idempotency-Key header.");
  }
  return parsed.data;
}
