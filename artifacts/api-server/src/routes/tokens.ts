import { Router, type IRouter } from "express";
import { db, projectTokens } from "@workspace/db";
import { desc, eq, isNull } from "drizzle-orm";
import { generateToken } from "../lib/tokens";

const router: IRouter = Router();

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

  res.json({
    tokens: rows.map((row) => ({
      id: row.id,
      name: row.name,
      prefix: row.prefix,
      createdAt: row.createdAt.toISOString(),
      lastUsedAt: row.lastUsedAt ? row.lastUsedAt.toISOString() : null,
      requestCount: row.requestCount,
      revoked: row.revokedAt !== null,
    })),
  });
});

router.post("/tokens", async (req, res) => {
  const body = req.body as { name?: unknown };
  const rawName = typeof body.name === "string" ? body.name.trim() : "";

  if (!rawName || rawName.length > 100) {
    res.status(400).json({ message: "Provide a project name (1-100 characters)." });
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

  res.status(201).json({
    id: created.id,
    name: created.name,
    prefix: created.prefix,
    createdAt: created.createdAt.toISOString(),
    token: raw,
    notice:
      "Copy this token now. It is shown once and stored only as a SHA-256 hash on the server.",
  });
});

router.delete("/tokens/:id", async (req, res) => {
  const id = Number.parseInt(req.params.id ?? "", 10);
  if (!Number.isFinite(id)) {
    res.status(400).json({ message: "Invalid token id." });
    return;
  }

  const [updated] = await db
    .update(projectTokens)
    .set({ revokedAt: new Date() })
    .where(eq(projectTokens.id, id))
    .returning({ id: projectTokens.id });

  if (!updated) {
    res.status(404).json({ message: "Token not found." });
    return;
  }

  res.json({ id: updated.id, revoked: true });
});

export const _internalActiveTokenCount = async () => {
  const rows = await db
    .select({ id: projectTokens.id })
    .from(projectTokens)
    .where(isNull(projectTokens.revokedAt));
  return rows.length;
};

export default router;
