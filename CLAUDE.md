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

## Run / test
- **`wrangler dev` does NOT work on this machine** (macOS 12.6; workerd needs 13.5+). Do not rely on it locally.
- **Local testing = `node --test 'src/*.test.ts'`** — Node runs the resolver and drives the web-standard `createMcpHandler` directly (synthetic `Request`s), no workerd. This is the primary local loop.
- **Real Workers-runtime verification = deploy** (`wrangler deploy`, uploads to the edge — works on 12.6) then curl the live `*.kazani.workers.dev` URL.
- Golden acceptance set: SPEC.md §12.

## Definition of done (binding — SPEC.md SC10)
Code working is NOT done. v1 is done only when: **repo public + a BlogChain post about building it is published.** This is the conversion guardrail from the premise grill — not optional, not "someday."

## Gotchas
- **workerd needs macOS 13.5+**; this machine is 12.6, so `wrangler dev` errors out. Test via `node --test` (handler runs in Node) or deploy. See Run/test.
- **`createMcpHandler` rejects requests with a 403 "Missing Host header"** — its DNS-rebinding guard. When driving it directly in Node tests, set a `host: "localhost"` header on the synthetic `Request`.
- **Import shared modules with the `.ts` extension** (`from "./resolver.ts"`) — Node's native type-stripping requires it; `tsconfig` has `allowImportingTsExtensions`. `*.test.ts`/`*.probe.ts` are excluded from `tsc` (Node-runtime, not Workers-typed).
- **JSON import attributes** (`import x from "./y.json" with { type: "json" }`) need `"module": "esnext"` (or node18+/nodenext) in tsconfig — `es2022` rejects the syntax. Harmless since wrangler's esbuild does the real bundling; `tsc` here is typecheck-only (`noEmit`).
- **ClearURLs `globalRules` has real per-domain exceptions** — e.g. github.com is deliberately exempted from the broad utm_*/fbclid stripping in favor of its own narrow provider (only `email_token`/`email_source`). Not a bug if a "known tracker" param survives on such a domain — check `data/clearurls-rules.json` for an exception before assuming cleaner.ts is broken.
- **`resolveUrl`'s `finalUrl` is pre-cleaning** — it's the raw resolved destination (redirects followed, nothing stripped). Tracker-stripping only shows up in `cleanedUrl`/`removedParams` from `cleanUrl()`. Don't expect `finalUrl` to be tracker-free.
