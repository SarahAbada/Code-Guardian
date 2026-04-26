# Sentinel

Sentinel is a security-first code auditor with a dark terminal UI and a CLI-friendly API. Paste raw source or a dependency manifest, and Sentinel returns a severity score, line-specific vulnerabilities, an attacker walkthrough with a runnable proof-of-concept, a hardened rewrite, and a chat console grounded in the current scan.

## What you get

- **Code Audit** — line-numbered vulnerability findings (SQL injection, XSS, broken auth, command injection, secret exposure, DoS, hardening gaps), severity score, and side-by-side vulnerable-vs-hardened rewrite.
- **Dependency Audit** — paste `package.json`, `requirements.txt`, `Cargo.toml`, `go.mod`, etc. Sentinel flags vulnerable versions, lists known CVEs, and recommends safe versions to upgrade to.
- **Attack Vector** — exploit narrative, attacker profile, kill chain, and a runnable PoC script (bash / curl / python / javascript) demonstrating how the vulnerability is weaponized.
- **Sentinel Console** — chat below the results that always carries the full scan context (code, vulnerabilities, dependencies) so follow-up questions like *"Why is line 12 a risk?"* or *"Give me a fix that doesn't use external libraries"* stay grounded.
- **CLI / API** — `POST /api/audit-cli` for headless integration with git hooks, CI pipelines, and editor extensions, with hashed project tokens, per-token rate limiting, and prompt-injection hardening.

## Project layout

This is a pnpm monorepo.

```
artifacts/
  api-server/     Express API (audit, dependencies, chat, CLI, tokens)
  sentinel/       React + Vite frontend (terminal UI)
  mockup-sandbox/ Component preview sandbox (design only)
lib/
  api-spec/       OpenAPI spec (source of truth for typed schemas)
  api-zod/        Generated zod request/response schemas
  api-client-react/ Generated React Query hooks
  db/             Drizzle ORM + Postgres schema (project_tokens)
  integrations/   Replit AI integrations bridge
```

## Running locally

The workflows are wired up automatically:

| Workflow | Command |
| --- | --- |
| `artifacts/api-server: API Server` | `pnpm --filter @workspace/api-server run dev` |
| `artifacts/sentinel: web` | `pnpm --filter @workspace/sentinel run dev` |

The API server uses Replit's built-in OpenAI integration (`AI_INTEGRATIONS_OPENAI_*` env vars) and the Replit-managed Postgres database (`DATABASE_URL`). No external keys are needed.

After modifying `lib/api-spec/openapi.yaml`, run:

```bash
pnpm --filter @workspace/api-spec run codegen
```

After modifying `lib/db/src/schema/`, push the schema:

```bash
cd lib/db && pnpm exec drizzle-kit push --config ./drizzle.config.ts
```

## CLI / API

### Authentication

Sentinel uses **per-project tokens** stored as SHA-256 hashes in Postgres — there is no single shared master key. Each token has a project name so you can tell `github-actions-ci` apart from `local-pre-commit-hook`, and revocation is one click in the UI (or `DELETE /api/tokens/{id}`).

1. Open the Sentinel UI and find the **CLI / API Project Tokens** card on the left.
2. Type a project name (e.g. `github-actions-ci`) and click **+ Token**.
3. Copy the raw `sntl_…` token immediately — it is shown once and only its hash is persisted.
4. Send it on every CLI request via either header:

```http
Authorization: Bearer sntl_…
X-API-Key: sntl_…
```

Tokens that are missing, mistyped, or revoked return `401`. Token rows show their prefix, request count, and last-used timestamp so you can spot stale or suspicious keys.

### Rate limiting

Each token is limited to **60 requests per hour**. Every response includes:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1777233865
```

Exceeding the limit returns `429 Too Many Requests` with a `Retry-After` header (seconds).

### `POST /api/audit-cli`

Headless audit endpoint designed for CLI tools, git hooks, and CI pipelines. Returns only the numeric `security_score` and a short list of **high or critical** vulnerabilities.

**Request body** (JSON):

| Field | Type | Notes |
| --- | --- | --- |
| `code` | `string` | Required (or send `file`). Source code or manifest contents, max 20,000 chars. |
| `file` | `string` | Alias for `code`. Use whichever your CLI prefers. |
| `filename` | `string` | Optional. For context (e.g. `app.js`). |
| `language` | `string` | Optional language hint (e.g. `python`, `package.json`). |

**Response** (`200 OK`):

```json
{
  "security_score": 15,
  "critical_vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "critical",
      "line": 1,
      "evidence": "db.query(\"SELECT * FROM users WHERE id=\" + req.query.id)",
      "remediation": "Use parameterized queries..."
    }
  ]
}
```

`security_score` is an integer 0–100 (100 = hardened, 0 = catastrophic). `critical_vulnerabilities` contains at most 8 entries with severity `high` or `critical`.

**Error responses:**

| Status | Meaning |
| --- | --- |
| `400` | Missing `code`/`file`. |
| `401` | Missing, invalid, or revoked token. |
| `413` | Payload over 20,000 chars. |
| `429` | Rate limit exceeded for this token. |
| `500` | Audit could not complete. |

### curl example

```bash
export SENTINEL_TOKEN=sntl_…
curl -sS -X POST https://your-app.replit.app/api/audit-cli \
  -H "Authorization: Bearer $SENTINEL_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "filename": "handlers.js",
    "language": "javascript",
    "code": "app.get(\"/u\", (req,res) => db.query(\"SELECT * FROM users WHERE id=\" + req.query.id))"
  }' | jq
```

### Pre-commit hook example

`.git/hooks/pre-commit`:

```bash
#!/usr/bin/env bash
set -e
[ -z "$SENTINEL_TOKEN" ] && { echo "SENTINEL_TOKEN not set"; exit 0; }

for file in $(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(js|ts|py|go|rs)$'); do
  payload=$(jq -nR --arg code "$(cat "$file")" --arg name "$file" \
    '{filename:$name, code:$code}')
  resp=$(curl -sS -X POST "$SENTINEL_API/api/audit-cli" \
    -H "Authorization: Bearer $SENTINEL_TOKEN" \
    -H 'Content-Type: application/json' -d "$payload")
  score=$(echo "$resp" | jq -r '.security_score')
  if [ "$score" -lt 70 ]; then
    echo "Sentinel blocked $file (score $score):"
    echo "$resp" | jq '.critical_vulnerabilities'
    exit 1
  fi
done
```

### GitHub Actions example

```yaml
- name: Audit changed files with Sentinel
  env:
    SENTINEL_TOKEN: ${{ secrets.SENTINEL_TOKEN }}
    SENTINEL_API: https://your-app.replit.app
  run: |
    for file in $(git diff --name-only origin/main...HEAD | grep -E '\.(js|ts|py)$'); do
      payload=$(jq -nR --arg code "$(cat $file)" --arg name "$file" \
        '{filename:$name, code:$code}')
      curl -sS -X POST "$SENTINEL_API/api/audit-cli" \
        -H "Authorization: Bearer $SENTINEL_TOKEN" \
        -H 'Content-Type: application/json' -d "$payload" \
        | tee "sentinel-$(basename $file).json"
    done
```

Store `SENTINEL_TOKEN` in **GitHub Actions Secrets**, never in plain text.

## Browser API

The Sentinel UI uses these endpoints for the rich audit experience. They do not require an API token (they ship with the bundled UI):

- `POST /api/audits` — full audit (`mode: "code" | "dependency"`), returns vulnerabilities, hardened rewrite, attack vector, and dependency findings.
- `POST /api/audits/chat` — grounded chat about the current scan.
- `GET /api/audit-rules` — the active analysis rulesets shown in the sidebar.
- `GET /api/tokens`, `POST /api/tokens`, `DELETE /api/tokens/{id}` — token management used by the **CLI / API Project Tokens** card.

## Security model

- **No master key.** Every CLI integration uses its own token, scoped by project name and individually revocable.
- **Hashed at rest.** Only SHA-256 hashes are stored in Postgres. The raw token is shown to the user once at provisioning time.
- **Constant-time lookup.** Tokens are matched by SHA-256 hash, not the raw string, so timing attacks against the comparison cannot leak the secret.
- **Per-token rate limit.** 60 requests / hour / token using a sliding-window in-memory bucket. `Retry-After` and `X-RateLimit-*` headers expose remaining quota.
- **Prompt-injection hardening.** Code submitted to `/api/audit-cli` is scanned for known prompt-injection patterns (e.g. *"ignore previous instructions"*, fake `system:` headers, score-override commands). Detected patterns are redacted in-flight, the model is told to treat the payload as untrusted input only, and any injection attempt is reported as a critical finding rather than allowed to bias the score.
- **HTTPS only in production.** Replit terminates TLS for deployed apps, so tokens travel encrypted on the wire.
- **No token logging.** Raw tokens are never written to logs or echoed back in API responses (except the one-time creation response).

## Going further

- Wire `audit-cli` into your editor's "save" hook.
- Pair the dependency mode with `npm outdated` / `pip-audit` for a defence-in-depth report.
- Use the chat console to draft framework-specific remediations in plain English before opening a PR.
