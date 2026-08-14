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
- **D1's real limit is 100 bound parameters per query — not SQLite's 999 default.** A batch-write chunk size sized against vanilla SQLite will pass every test with small diffs and then fail live the first time a feed actually has real churn (silent until then — this bit `refresh.ts` in production). `CHUNK = 40` in `refresh.ts` stays under it (80/41 params for INSERT/DELETE). If you touch batch writes, verify against the real Cloudflare limit, not assumed SQLite defaults, and test with a diff bigger than one chunk, not a token 1-2-row diff.
- **KV-blob module-scope caches (`feeds.ts`) need a TTL, not "load once forever."** A cron refresh writes from a different Worker isolate than the ones serving requests — there's no way for application code to invalidate another isolate's cache. `BLOB_CACHE_TTL_MS` (15 min) bounds staleness; don't remove it without another way to bound it.
- **`t.mock.timers.enable({ apis: ["Date"] })` (Node's built-in test-runner mock) works for testing TTL/cache-expiry logic deterministically** — no need to skip a time-based test or actually wait real minutes.
- **VirusTotal free tier is 4 req/min.** `check_url` always VT-checks; `check_text` deliberately does NOT (would blow the limit on any multi-link blob) — it scores every URL first without VT, then VT-checks only the single worst candidate. If you touch the worst-candidate selector, test with realistic bindings (`fakeEnv()`, not bare `ENV`) — a missing-binding env artificially ties every verdict at SUSPICIOUS (via AC1), which silently breaks tie-break selection in a way that only shows up with 2+ URLs. Real bug hit exactly this way.
- **VT's URL identifier is `base64url(url)` with padding stripped**, not the raw URL or a hash — `GET /api/v3/urls/{id}` with header `x-apikey`. A 404 means "VT has never scanned this URL," a valid non-error outcome — do not treat it as degraded.
- **VT's own docs page (`docs.virustotal.com/reference/url-info`) is a JS-rendered SPA** — fetching it as markdown returns no useful schema. Verify the API shape with a live call instead (worked immediately, gave the exact response structure).
- **`wrangler deploy` / `wrangler secret put` propagate across Cloudflare's edge over a few seconds, not instantly.** A curl immediately after either can transiently 404 (deploy) or bypass a just-set secret (auth no-op on a stale edge node). Retry 3-5x with a short delay before treating a post-deploy/post-secret security check as final — a single spot-check right after a mutation is not verification.
- **D1's `rows_written` in query results counts index writes too** — e.g. 445 inserted rows on a table with a PK shows `rows_written: 890` (2x). Not a bug; verify actual row count with `SELECT COUNT(*)` if the number looks off, don't assume corruption from the meta field alone.
- **A large HaGeZi/threat-feed list ("mini"/"small" in its own name) can still be 100K+ entries** — TIF-mini alone is 166,581 domains, TIF-IPs 62,236, Entropy-NRD (smallest 7-day window) 582,153. All three blow D1's ~100K-row-write/day ceiling if stored one-row-per-entry. Pattern used instead: one KV value per feed (newline-joined blob), one PUT per refresh regardless of size, parsed into an in-memory `Set` cached at module scope. Small feeds (abused-TLDs, URL-shortener, URLhaus exact-URL — all under 16K) stay in D1 as row-per-entry; see `src/feeds.ts`.
- **Workers has no raw DNS API.** Resolving a hostname to an IP (needed for IP-reputation feed checks) goes through DNS-over-HTTPS via plain `fetch()` to `cloudflare-dns.com/dns-query` — see `src/dns.ts`. The resolver's SSRF guard only catches *literal* IP hostnames already in a URL; it never resolves a domain name, so don't assume "we already have the IP" anywhere else in the codebase.
- **Cross-domain-hop detection compares registrable domain (last-2-labels), never full hostname.** Apex↔www and same-domain subdomain moves are common, benign redirect patterns — exact-hostname comparison false-flagged real production sites (anthropic.com → www.anthropic.com). If you touch this logic, regression-test against a *different* real site than whatever broke it, not just the one example.
- **When several unrelated checks fail identically (same error, same position), suspect the test harness before the product.** A shell `sed`/`echo` pipeline mangled an SSE+JSON response the same way across 7 different URLs — the tell was that the failure didn't vary with the input. Parse responses directly (Python `json.loads`, no intermediate shell text processing) when a curl pipeline result looks suspicious.
- **`createMcpHandler`'s factory has no access to `env`/bindings** — only `{era, authInfo, requestInfo}`. To reach D1/KV from tool handlers, build the handler fresh inside `fetch()` with `createServer(env)` closing over `env`, not at module scope. This is the documented tradeoff for skipping `notify()`/list-changed support, which this project doesn't use.
- **workerd needs macOS 13.5+**; this machine is 12.6, so `wrangler dev` errors out. Test via `node --test` (handler runs in Node) or deploy. See Run/test.
- **`createMcpHandler` rejects requests with a 403 "Missing Host header"** — its DNS-rebinding guard. When driving it directly in Node tests, set a `host: "localhost"` header on the synthetic `Request`.
- **Import shared modules with the `.ts` extension** (`from "./resolver.ts"`) — Node's native type-stripping requires it; `tsconfig` has `allowImportingTsExtensions`. `*.test.ts`/`*.probe.ts` are excluded from `tsc` (Node-runtime, not Workers-typed).
- **JSON import attributes** (`import x from "./y.json" with { type: "json" }`) need `"module": "esnext"` (or node18+/nodenext) in tsconfig — `es2022` rejects the syntax. Harmless since wrangler's esbuild does the real bundling; `tsc` here is typecheck-only (`noEmit`).
- **ClearURLs `globalRules` has real per-domain exceptions** — e.g. github.com is deliberately exempted from the broad utm_*/fbclid stripping in favor of its own narrow provider (only `email_token`/`email_source`). Not a bug if a "known tracker" param survives on such a domain — check `data/clearurls-rules.json` for an exception before assuming cleaner.ts is broken.
- **`agents` requires `nodejs_compat`** (imports `node:async_hooks`) — non-optional, set in `wrangler.jsonc`'s `compatibility_flags`. Given that's already required, `node:url` (e.g. `domainToUnicode`) is fair game elsewhere too — no need to hand-roll what Node compat already provides.
- **WHATWG `URL` silently IDNA-encodes non-ASCII hostnames to punycode** — `new URL("https://аpple.com/").hostname` is `"xn--pple-43d.com"`, not the Cyrillic original. Any homograph/script-mixing check MUST decode via `domainToUnicode()` first, or it's checking already-ASCII'd text and can never fire (real bug hit building the SC4 test).
- **`resolveUrl`'s `finalUrl` is pre-cleaning** — it's the raw resolved destination (redirects followed, nothing stripped). Tracker-stripping only shows up in `cleanedUrl`/`removedParams` from `cleanUrl()`. Don't expect `finalUrl` to be tracker-free.
