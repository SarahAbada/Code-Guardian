import { integer, pgTable, serial, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";

export const projectTokens = pgTable(
  "project_tokens",
  {
    id: serial("id").primaryKey(),
    name: text("name").notNull(),
    prefix: text("prefix").notNull(),
    tokenHash: text("token_hash").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    requestCount: integer("request_count").notNull().default(0),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => ({
    tokenHashIdx: uniqueIndex("project_tokens_token_hash_idx").on(table.tokenHash),
  }),
);

export type ProjectToken = typeof projectTokens.$inferSelect;
export type InsertProjectToken = typeof projectTokens.$inferInsert;
