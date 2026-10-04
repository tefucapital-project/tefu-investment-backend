import { createHmac, timingSafeEqual } from "node:crypto";
import cors from "cors";
import express, { type Request } from "express";
import helmet from "helmet";
import { z } from "zod";
import { env } from "./config.ts";
import { ApiError, errorHandler, fail, ok } from "./http.ts";
import { requireKind, requireUser } from "./middleware.ts";
import { admin } from "./routes/admin.ts";
import { client } from "./routes/client.ts";
import { applyProviderResult } from "./services.ts";

const docs = {
  openapi: "3.0.3",
  info: { title: "Tefu Investment API", version: "1.0.0" },
  servers: [{ url: "/api/v1" }],
  components: {
    securitySchemes: { bearer: { type: "http", scheme: "bearer", bearerFormat: "JWT" } },
  },
  paths: {
    "/auth/register": { post: { tags: ["Client"] } },
    "/auth/login": { post: { tags: ["Client"] } },
    "/auth/verify-otp": { post: { tags: ["Client"] } },
    "/auth/resend-otp": { post: { tags: ["Client"] } },
    "/auth/forgot-password": { post: { tags: ["Client"] } },
    "/auth/reset-password": { post: { tags: ["Client"] } },
    "/auth/refresh": { post: { tags: ["Client"] } },
    "/auth/logout": { post: { tags: ["Client"], security: [{ bearer: [] }] } },
    "/account": { get: { tags: ["Client"], security: [{ bearer: [] }] } },
    "/onboarding-fee/initialize": { post: { tags: ["Client"], security: [{ bearer: [] }] } },
    "/kyc": { get: { tags: ["Client"], security: [{ bearer: [] }] } },
    "/wallet/deposit": { post: { tags: ["Client"], security: [{ bearer: [] }] } },
    "/wallet/withdraw": { post: { tags: ["Client"], security: [{ bearer: [] }] } },
    "/mudarabah/{id}/invest": { post: { tags: ["Client"], security: [{ bearer: [] }] } },
    "/ijarah/{id}/invest": { post: { tags: ["Client"], security: [{ bearer: [] }] } },
    "/admin/auth/login": { post: { tags: ["Admin"] } },
    "/admin/kyc/{id}/approve": { post: { tags: ["Admin"], security: [{ bearer: [] }] } },
    "/admin/withdrawals/{id}/approve": { post: { tags: ["Admin"], security: [{ bearer: [] }] } },
    "/admin/distributions/{id}/execute": { post: { tags: ["Admin"], security: [{ bearer: [] }] } },
  },
};

export function createApp() {
  const app = express();
  app.disable("x-powered-by");
  app.use(helmet());
  app.use(cors({ origin: [env.userOrigin, env.adminOrigin, "http://localhost:5173", "http://localhost:5174"] }));
  app.use(express.json({
    limit: "2mb",
    verify: (req, _res, buf) => {
      (req as Request).rawBody = buf;
    },
  }));
  app.use((req, res, next) => {
    const started = Date.now();
    res.on("finish", () => {
      console.log(JSON.stringify({ requestId: req.header("x-request-id") ?? "", method: req.method, path: req.path, status: res.statusCode, ms: Date.now() - started }));
    });
    next();
  });

  app.get("/api/v1/health", (_req, res) => {
    res.json(ok("Tefu Investment API is running.", { service: "tefu-investment-backend", currency: env.currency }));
  });

  app.get("/api/docs", requireUser, requireKind("ADMIN"), (_req, res) => {
    res.json(docs);
  });

  app.post("/api/v1/webhooks/payment", async (req, res) => {
    const provided = req.header("x-tefu-signature") ?? "";
    const expected = createHmac("sha256", env.paymentWebhookSecret).update(req.rawBody ?? Buffer.from("")).digest("hex");
    const left = Buffer.from(provided);
    const right = Buffer.from(expected);
    if (left.length !== right.length || !timingSafeEqual(left, right)) {
      throw new ApiError(401, "INVALID_SIGNATURE", "Webhook signature is invalid.");
    }
    const body = z.object({
      reference: z.string(),
      status: z.enum(["SUCCESSFUL", "FAILED"]),
      eventId: z.string(),
    }).parse(req.body);
    const result = await applyProviderResult(body.reference, body.status, body.eventId);
    res.json(ok(result.duplicate ? "Webhook already processed." : "Webhook processed.", result));
  });

  app.use("/api/v1/admin", admin);
  app.use("/api/v1", client);
  app.use((_req, res) => {
    res.status(404).json(fail("This endpoint does not exist.", "NOT_FOUND"));
  });
  app.use(errorHandler);
  return app;
}
