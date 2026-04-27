import type { NextFunction, Request, Response } from "express";
import { db, projectTokens } from "@workspace/db";
import { eq, sql } from "drizzle-orm";
import { extractBearerToken, hashToken } from "../lib/tokens";
import { checkRateLimit } from "../lib/rateLimit";

export type ProjectTokenRow = typeof projectTokens.$inferSelect;

declare module "express-serve-static-core" {
  interface Request {
    tokenRow?: ProjectTokenRow;
  }
}

export async function requireToken(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const presented = extractBearerToken(
    req as unknown as { headers: Record<string, string | string[] | undefined> },
  );

  if (!presented) {
    res.status(401).json({
      message:
        "Missing API token. Send 'Authorization: Bearer <token>' or 'X-API-Key: <token>'.",
    });
    return;
  }

  const presentedHash = hashToken(presented);
  const [tokenRow] = await db
    .select()
    .from(projectTokens)
    .where(eq(projectTokens.tokenHash, presentedHash))
    .limit(1);

  if (!tokenRow || tokenRow.revokedAt) {
    res.status(401).json({ message: "Invalid or revoked API token." });
    return;
  }

  const limit = checkRateLimit(`token:${tokenRow.id}`);
  res.setHeader("X-RateLimit-Limit", String(limit.limit));
  res.setHeader("X-RateLimit-Remaining", String(limit.remaining));
  res.setHeader("X-RateLimit-Reset", String(Math.floor(limit.resetAtMs / 1000)));

  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSec));
    res.status(429).json({
      message: `Rate limit exceeded for this token. Limit ${limit.limit} requests per hour.`,
      retryAfter: limit.retryAfterSec,
    });
    return;
  }

  req.tokenRow = tokenRow;
  next();
}

export async function recordTokenUse(tokenId: number): Promise<void> {
  await db
    .update(projectTokens)
    .set({
      lastUsedAt: new Date(),
      requestCount: sql`${projectTokens.requestCount} + 1`,
    })
    .where(eq(projectTokens.id, tokenId));
}
