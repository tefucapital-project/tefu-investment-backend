import { createHmac, timingSafeEqual } from "node:crypto";
import { env } from "../config.ts";
import { ApiError } from "../http.ts";

type PaystackEnvelope<T> = {
  status: boolean;
  message: string;
  data: T;
};

export type PaystackInitResult = {
  authorizationUrl: string;
  accessCode: string;
  reference: string;
};

function secret() {
  if (!env.paystackSecretKey) {
    throw new ApiError(503, "PAYMENTS_NOT_CONFIGURED", "Paystack is not configured. Set PAYSTACK_SECRET_KEY.");
  }
  return env.paystackSecretKey;
}

async function paystackFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${env.paystackBaseUrl}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${secret()}`,
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  const body = (await response.json()) as PaystackEnvelope<T>;
  if (!response.ok || !body.status) {
    throw new ApiError(502, "PAYSTACK_ERROR", body.message || "Paystack request failed.");
  }
  return body.data;
}

export function paystackConfigured() {
  return Boolean(env.paystackSecretKey);
}

export function verifyPaystackSignature(rawBody: Buffer, signature: string) {
  const hash = createHmac("sha512", secret()).update(rawBody).digest("hex");
  const left = Buffer.from(signature);
  const right = Buffer.from(hash);
  return left.length === right.length && timingSafeEqual(left, right);
}

export async function initializePaystackPayment(input: {
  email: string;
  amountKobo: number;
  reference: string;
  purpose: string;
  callbackPath: string;
}) {
  const callbackUrl = `${env.appFrontendUrl.replace(/\/$/, "")}${input.callbackPath.startsWith("/") ? input.callbackPath : `/${input.callbackPath}`}`;
  const data = await paystackFetch<{
    authorization_url: string;
    access_code: string;
    reference: string;
  }>("/transaction/initialize", {
    method: "POST",
    body: JSON.stringify({
      email: input.email,
      amount: input.amountKobo,
      reference: input.reference,
      currency: env.currency,
      callback_url: callbackUrl,
      metadata: {
        purpose: input.purpose,
        custom_fields: [{ display_name: "Purpose", variable_name: "purpose", value: input.purpose }],
      },
    }),
  });
  return {
    authorizationUrl: data.authorization_url,
    accessCode: data.access_code,
    reference: data.reference,
  } satisfies PaystackInitResult;
}

export async function verifyPaystackTransaction(reference: string) {
  return paystackFetch<{
    status: string;
    reference: string;
    amount: number;
    currency: string;
    paid_at: string | null;
  }>(`/transaction/verify/${encodeURIComponent(reference)}`);
}

export function mapPaystackStatus(status: string): "SUCCESSFUL" | "FAILED" | "PENDING" {
  const value = status.toLowerCase();
  if (value === "success") return "SUCCESSFUL";
  if (value === "failed" || value === "abandoned" || value === "reversed") return "FAILED";
  return "PENDING";
}
