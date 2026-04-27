import type { NextFunction, Request, Response } from "express";
import { timingSafeEqual } from "node:crypto";
import { logger } from "../lib/logger";

const ADMIN_TOKEN_ENV = "ADMIN_TOKEN";

let warnedDevAuthDisabled = false;

function getAdminToken(): string | null {
  const value = process.env[ADMIN_TOKEN_ENV];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function constantTimeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  try {
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

export function requireAdmin(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const expected = getAdminToken();
  const isProduction = process.env["NODE_ENV"] === "production";

  if (!expected) {
    if (isProduction) {
      res.status(503).json({
        message:
          "Admin auth is not configured on the server. Set the ADMIN_TOKEN environment variable to enable token administration.",
      });
      return;
    }

    if (!warnedDevAuthDisabled) {
      logger.warn(
        { route: req.originalUrl },
        "ADMIN_TOKEN is not set; admin endpoints are unauthenticated in development. Set ADMIN_TOKEN before deploying.",
      );
      warnedDevAuthDisabled = true;
    }

    res.setHeader("X-Admin-Auth", "disabled-dev-mode");
    next();
    return;
  }

  const presentedRaw = req.headers["x-admin-token"];
  const presented = typeof presentedRaw === "string" ? presentedRaw.trim() : "";

  if (!presented || !constantTimeStringEqual(presented, expected)) {
    res.status(401).json({
      message:
        "Missing or invalid admin token. Send the admin token as the 'X-Admin-Token' header.",
    });
    return;
  }

  next();
}

export function isAdminAuthConfigured(): boolean {
  return getAdminToken() !== null;
}
