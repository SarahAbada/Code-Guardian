# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.

Sentinel is a web-based Security Logic Auditor available at the root preview path. It lets users paste code, run an LLM-backed security audit, and review severity scoring, line-specific vulnerabilities, remediation steps, and vulnerable-vs-hardened code rewrites.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)
- **AI**: Replit OpenAI integration via `@workspace/integrations-openai-ai-server`

## Artifacts

- `artifacts/sentinel` — React + Vite frontend for Sentinel.
- `artifacts/api-server` — shared Express API, including `POST /api/audits` and `GET /api/audit-rules`.

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.
