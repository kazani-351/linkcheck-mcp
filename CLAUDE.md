# CLAUDE.md — linkcheck-mcp

A remote, stateless MCP server that lets an agent inspect a URL before it's opened:
resolve redirects, strip trackers, detect phishing structure, check threat feeds →
return a tiered verdict + evidence. Full design in **[SPEC.md](SPEC.md)** — read it before changing behavior.

## Stack
- Cloudflare Worker, TypeScript.
- `createMcpHandler` (stateless) from `agents/mcp/server`, MCP **SDK v2** (`@modelcontextprotocol/server@2.0.0`), `zod`.
- Bindings: **D1** (feeds), **KV** (verdict cache), **Cron** (daily diff-refresh).
- Deploys to `*.kazani.workers.dev`.

## Architecture constraints (don't violate without updating SPEC.md)
- **Stateless.** A fresh `McpServer` per request via a factory. NO McpAgent, NO Durable Object. Durable data lives in D1/KV, never an MCP session.
- **Never false-SAFE.** A check that couldn't run may return SUSPICIOUS/degraded — never SAFE (anti-criterion §13). Fail LOUD, surface `degraded[]`.
- **HEAD-first, GET-headers-only fallback.** Resolve redirects without downloading/executing bodies. Never full-GET a target's body.
- **Domain matching walks parent labels** (`a.b.evil.com` → `b.evil.com` → `evil.com`), not exact-match — else subdomains evade the blocklist.
- **Verdict cache is keyed on the normalized INPUT url**, not the resolved URL (a hit must skip resolution).
- **URLhaus:** exact-URL hit → DANGEROUS; domain-only hit → SUSPICIOUS (compromised-legit-host nuance).
- **check_text:** cap 20 URLs/blob (`truncated` flag), TLD-suffix gate on bare domains, VT off in batch (worst-candidate only).
- **Auth:** bearer token checked in the Worker `fetch()` wrapper before the handler. Handler does not verify tokens.

## Secrets
- `MCP_BEARER_TOKEN` (+ optional `VIRUSTOTAL_API_KEY`) via `wrangler secret` in prod, `.dev.vars` locally.
- `.dev.vars` / `.env*` / `.mcp.json` are gitignored. Never commit a secret; halt if one appears in a diff.

## Run / test (filled in at build)
- Local dev: `wrangler dev` → MCP endpoint at `http://localhost:8788/mcp`.
- Test with MCP Inspector: `npx @modelcontextprotocol/inspector@latest`.
- Golden acceptance set: SPEC.md §12.

## Definition of done (binding — SPEC.md SC10)
Code working is NOT done. v1 is done only when: **repo public + a BlogChain post about building it is published.** This is the conversion guardrail from the premise grill — not optional, not "someday."

## Gotchas
- (Add one-line gotchas here as real bugs are hit — guardrail, not knowledge base.)
