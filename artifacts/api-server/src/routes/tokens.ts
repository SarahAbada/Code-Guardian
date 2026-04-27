import { Router, type IRouter } from "express";
import { db, projectTokens } from "@workspace/db";
import { desc, eq } from "drizzle-orm";
import {
  CreateProjectTokenBody,
  ListProjectTokensResponse,
  RevokeProjectTokenParams,
  RevokeProjectTokenResponse,
  type CreateProjectTokenResponse,
} from "@workspace/api-zod";
import { generateToken } from "../lib/tokens";
import { requireAdmin } from "../middleware/requireAdmin";

const router: IRouter = Router();

router.use("/tokens", requireAdmin);

router.get("/tokens", async (_req, res) => {
  const rows = await db
    .select({
      id: projectTokens.id,
      name: projectTokens.name,
      prefix: projectTokens.prefix,
      createdAt: projectTokens.createdAt,
      lastUsedAt: projectTokens.lastUsedAt,
      requestCount: projectTokens.requestCount,
      revokedAt: projectTokens.revokedAt,
    })
    .from(projectTokens)
    .orderBy(desc(projectTokens.createdAt));

  res.json(
    ListProjectTokensResponse.parse({
      tokens: rows.map((row) => ({
        id: row.id,
        name: row.name,
        prefix: row.prefix,
        createdAt: row.createdAt,
        lastUsedAt: row.lastUsedAt,
        requestCount: row.requestCount,
        revoked: row.revokedAt !== null,
      })),
    }),
  );
});

router.post("/tokens", async (req, res) => {
  const validation = CreateProjectTokenBody.safeParse(req.body);

  if (!validation.success) {
    res
      .status(400)
      .json({ message: "Provide a project name (1-100 characters)." });
    return;
  }

  const rawName = validation.data.name.trim();
  if (!rawName) {
    res
      .status(400)
      .json({ message: "Provide a project name (1-100 characters)." });
    return;
  }

  const { raw, prefix, hash } = generateToken();

  const [created] = await db
    .insert(projectTokens)
    .values({ name: rawName, prefix, tokenHash: hash })
    .returning({
      id: projectTokens.id,
      name: projectTokens.name,
      prefix: projectTokens.prefix,
      createdAt: projectTokens.createdAt,
    });

  if (!created) {
    res.status(500).json({ message: "Could not provision token." });
    return;
  }

  const responsePayload = {
    id: created.id,
    name: created.name,
    prefix: created.prefix,
    createdAt: created.createdAt.toISOString(),
    token: raw,
    notice:
      "Copy this token now. It is shown once and stored only as a SHA-256 hash on the server.",
  } satisfies Omit<CreateProjectTokenResponse, "createdAt"> & {
    createdAt: string;
  };

  res.status(201).json(responsePayload);
});

router.delete("/tokens/:id", async (req, res) => {
  const paramValidation = RevokeProjectTokenParams.safeParse(req.params);
  if (!paramValidation.success) {
    res.status(400).json({ message: "Invalid token id." });
    return;
  }
  const id = paramValidation.data.id;

  const [updated] = await db
    .update(projectTokens)
    .set({ revokedAt: new Date() })
    .where(eq(projectTokens.id, id))
    .returning({ id: projectTokens.id });

  if (!updated) {
    res.status(404).json({ message: "Token not found." });
    return;
  }

  res.json(RevokeProjectTokenResponse.parse({ id: updated.id, revoked: true }));
});

export default router;
