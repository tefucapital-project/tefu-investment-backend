import "dotenv/config";

function required(name: string) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}. Copy .env.example to .env.`);
  return value;
}

export const env = {
  databaseUrl: required("DATABASE_URL"),
  jwtSecret: required("JWT_SECRET"),
  jwtRefreshSecret: required("JWT_REFRESH_SECRET"),
  port: Number(process.env.PORT ?? 4000),
  userOrigin: process.env.USER_ORIGIN ?? "http://127.0.0.1:5173",
  adminOrigin: process.env.ADMIN_ORIGIN ?? "http://127.0.0.1:5174",
  currency: process.env.CURRENCY ?? "NGN",
  paymentsMode: process.env.PAYMENTS_MODE ?? "demo",
  paymentWebhookSecret: required("PAYMENT_WEBHOOK_SECRET"),
  identityMode: process.env.IDENTITY_MODE ?? "demo",
  otobillApiKey: process.env.OTOBILL_API_KEY ?? "",
  otobillBaseUrl: process.env.OTOBILL_BASE_URL ?? "https://api.otobill.com",
  exposeOtp: process.env.EXPOSE_OTP === "true",
  storageDir: process.env.STORAGE_DIR ?? "storage",
};
