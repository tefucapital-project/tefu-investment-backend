import "dotenv/config";

function required(name: string) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}. Copy .env.example to .env.`);
  return value;
}

const paymentsMode = process.env.PAYMENTS_MODE ?? (process.env.PAYSTACK_SECRET_KEY ? "paystack" : "demo");

export const env = {
  databaseUrl: required("DATABASE_URL"),
  jwtSecret: required("JWT_SECRET"),
  jwtRefreshSecret: required("JWT_REFRESH_SECRET"),
  port: Number(process.env.PORT ?? 4000),
  userOrigin: process.env.USER_ORIGIN ?? process.env.APP_FRONTEND_URL ?? "http://127.0.0.1:5173",
  adminOrigin: process.env.ADMIN_ORIGIN ?? "http://127.0.0.1:5174",
  appFrontendUrl: process.env.APP_FRONTEND_URL ?? process.env.USER_ORIGIN ?? "http://127.0.0.1:5173",
  publicApiUrl: process.env.PUBLIC_API_URL ?? `http://127.0.0.1:${process.env.PORT ?? 4000}`,
  currency: process.env.CURRENCY ?? "NGN",
  paymentsMode,
  paymentWebhookSecret:
    process.env.PAYSTACK_WEBHOOK_SECRET ||
    process.env.PAYMENT_WEBHOOK_SECRET ||
    process.env.PAYSTACK_SECRET_KEY ||
    "",
  paystackSecretKey: process.env.PAYSTACK_SECRET_KEY ?? "",
  paystackPublicKey: process.env.PAYSTACK_PUBLIC_KEY ?? "",
  paystackWebhookSecret: process.env.PAYSTACK_WEBHOOK_SECRET || process.env.PAYSTACK_SECRET_KEY || "",
  paystackBaseUrl: process.env.PAYSTACK_BASE_URL ?? "https://api.paystack.co",
  identityMode: process.env.IDENTITY_MODE ?? "demo",
  otobillApiKey: process.env.OTOBILL_API_KEY ?? "",
  otobillBaseUrl: process.env.OTOBILL_BASE_URL ?? "https://api.otobill.com",
  exposeOtp: process.env.EXPOSE_OTP === "true",
  storageDir: process.env.STORAGE_DIR ?? "storage",
  rateLimitEnabled: process.env.RATE_LIMIT_ENABLED !== "false",
  rateLimitPerUser: Number(process.env.RATE_LIMIT_PER_USER ?? 30),
  rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW_MS ?? 60_000),
  rateLimitMoneyMax: Number(process.env.RATE_LIMIT_MONEY_MAX ?? 10),
  rateLimitAuthMax: Number(process.env.RATE_LIMIT_AUTH_MAX ?? 20),
};
