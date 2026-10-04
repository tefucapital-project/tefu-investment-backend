import type { NextFunction, Request, Response } from "express";
import { readAccess } from "./auth.ts";
import { roleHas, type PermissionName } from "./domain/rbac.ts";
import { prisma } from "./db.ts";
import { ApiError } from "./http.ts";

export async function requireUser(req: Request, _res: Response, next: NextFunction) {
  const header = req.header("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return next(new ApiError(401, "UNAUTHENTICATED", "Sign in to continue."));
  try {
    const claims = readAccess(token);
    const user = await prisma.user.findUnique({ where: { id: claims.sub } });
    if (!user) return next(new ApiError(401, "UNAUTHENTICATED", "Sign in to continue."));
    if (user.kind === "ADMIN" && !user.adminActive) return next(new ApiError(403, "ADMIN_DISABLED", "This admin account is disabled."));
    if (user.accountStatus === "SUSPENDED" && user.kind === "CLIENT") {
      return next(new ApiError(403, "ACCOUNT_SUSPENDED", "This account is suspended."));
    }
    req.user = { id: user.id, kind: user.kind, role: user.role };
    next();
  } catch {
    next(new ApiError(401, "INVALID_TOKEN", "The session token is invalid."));
  }
}

export function requireKind(kind: "CLIENT" | "ADMIN") {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (req.user?.kind !== kind) return next(new ApiError(403, "WRONG_AUDIENCE", "This API is not available to this account."));
    next();
  };
}

export function requirePermission(permission: PermissionName) {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!roleHas(req.user?.role, permission)) {
      return next(new ApiError(403, "FORBIDDEN", "Your role cannot perform this action."));
    }
    next();
  };
}

declare global {
  namespace Express {
    interface Request {
      user?: { id: string; kind: "CLIENT" | "ADMIN"; role: string | null };
      rawBody?: Buffer;
    }
  }
}
