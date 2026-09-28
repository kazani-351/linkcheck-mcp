# linkcheck-mcp

> Status: **v1 live**. A remote MCP server for safe URL inspection.

An MCP server that lets an AI agent (Claude) check where a link *actually* goes and
whether it's safe — **before** anyone opens it. It resolves redirects, strips tracking
parameters, detects phishing structure (homographs, `@`-authority tricks, IP-literal
hosts…), and checks the destination against live threat-intelligence feeds, returning a
tiered verdict (`SAFE` / `SUSPICIOUS` / `DANGEROUS`) plus the evidence behind it.

Inspired by the Android app [URLCheck](https://github.com/TrianguloY/URLCheck), re-shaped
for an AI agent instead of a human tap.

The live reference deployment has a browsable homepage at
[linkcheck-mcp.kazani.workers.dev](https://linkcheck-mcp.kazani.workers.dev/).

## Tools (v1)
- `check_url(url, compact?)` — resolve + clean + heuristics + threat-feed verdict with evidence. `compact: true` returns just `{verdict, verdictReason, resolvedUrl, degraded}`.
- `check_text(text, compact?)` — extract every URL in a blob (standard, bare, and defanged forms like `hxxp://evil[.]com`), check each, and return a `worstVerdict` summary. Also surfaces content hidden from a human reader (Unicode tag text, zero-width characters, sentences in `id` attributes, base64 text as strong signals; HTML comments and hidden elements as weak ones) and checks URLs found only in decoded form.

## Endpoints
- `GET /` — human landing page (served for `text/html` requests; never shadows the MCP transport on the same origin).
- `GET /health` — per-feed `last_status` / `last_refresh`.
- `GET /.well-known/mcp/server-card.json` — machine-readable server descriptor for MCP discovery.
- `POST /mcp` — the MCP transport.
- `POST /check` — plain-HTTP verdict (`{url, compact?}`) for non-MCP clients, e.g. a shell pre-flight hook that checks links before an agent acts on them. Same logic and bearer gate as `check_url`.

## Stack
Cloudflare Worker · stateless `createMcpHandler` (MCP SDK v2) · D1 (small feeds) + KV (large feeds + verdict cache) · daily Cron Trigger for feed refresh.

## Feed refresh
Threat feeds refresh daily via a Cloudflare Cron Trigger (`17 6 * * *` UTC). Small feeds (URLhaus, HaGeZi Shortener/Abused-TLD, all in D1) are diffed — only added/removed rows are written, chunked to stay under D1's 100-bound-parameter-per-query limit. Large feeds (HaGeZi TIF-domains/TIF-IPs/Entropy-NRD, all in KV) are fully overwritten each refresh — one `PUT` regardless of list size. A failed source doesn't block the others; check `/health` for per-feed `last_status`/`last_refresh`.

To trigger a refresh manually (local `wrangler dev` can't fire a real cron tick on macOS < 13.5, so this is also how the refresh logic is verified against production):
```bash
curl -X POST https://<your-worker>.workers.dev/admin/refresh-feeds \
  -H "authorization: Bearer <token>"
```

## Run

### Local development / testing
`wrangler dev` does **not** work on macOS < 13.5 (workerd requirement) — verify locally with the real test suite instead, which drives the actual web-standard MCP handler in plain Node:

```bash
npm install
npm test          # node --test 'src/**/*.test.ts'
npm run typecheck # tsc --noEmit
```

### Deploy

1. Create the D1 database and KV namespace (one-time), then wire their IDs into `wrangler.jsonc`'s `d1_databases`/`kv_namespaces`:
   ```bash
   npx wrangler d1 create linkcheck-mcp-feeds
   npx wrangler kv namespace create linkcheck-mcp-cache
   ```
2. Apply the schema and seed the feeds (see `migrations/*.sql` for schema; feed data is fetched fresh from HaGeZi/URLhaus/ClearURLs upstream sources — see Sources below — and loaded via `wrangler d1 execute --remote --file=...` for the small feeds and `wrangler kv key put --path=... --remote` for the large ones as single blobs).
3. **Auth (optional):** the Worker supports a bearer-token gate (`if (token && ...)` in `src/index.ts` — set once, it's enforced; unset, it no-ops):
   ```bash
   npx wrangler secret put MCP_BEARER_TOKEN
   ```
   The reference deployment currently runs **without** this set — Claude's native "Add custom connector" UI only supports OAuth or `static_headers` (beta, not yet exposed there) for remote MCP servers, not a plain bearer header, so connecting via that UI meant dropping the gate rather than standing up a full OAuth server (see SPEC §11 for the reasoning and the reversal path). If you connect via `mcp-remote` (below) instead, you can keep the token.

   Optional: `npx wrangler secret put VIRUSTOTAL_API_KEY` for VT-augmented checks (degrades cleanly if unset).
4. Deploy:
   ```bash
   npx wrangler deploy
   ```
5. Verify:
   ```bash
   curl https://<your-worker>.workers.dev/health
   curl -X POST https://<your-worker>.workers.dev/mcp \
     -H "content-type: application/json" -H "accept: application/json, text/event-stream" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check_url","arguments":{"url":"https://example.com"}}}'
   ```
   (Add `-H "authorization: Bearer <token>"` if you set `MCP_BEARER_TOKEN`.)

### Connect a client

**Claude Desktop / Cowork (native connector, no CLI):** Settings → Connectors → Add custom connector → paste the server URL (`https://<your-worker>.workers.dev/mcp`), leave OAuth fields blank if running authless. This is the path used for the reference deployment.

**Any MCP client, with a bearer token preserved:** via [`mcp-remote`](https://www.npmjs.com/package/mcp-remote):
```json
{
  "mcpServers": {
    "linkcheck": {
      "command": "npx",
      "args": ["mcp-remote", "https://<your-worker>.workers.dev/mcp", "--header", "Authorization: Bearer <token>"]
    }
  }
}
```

Either way, install `skills/check-url-safety.md` to `~/.claude/skills/check-url-safety/SKILL.md` — it teaches Claude to call these tools proactively on untrusted links, rather than waiting to be asked. (Do this *after* connecting — the skill references tools that don't exist until the connector is live.)

## Sources & attribution
- Threat intel: [HaGeZi dns-blocklists](https://github.com/hagezi/dns-blocklists) (TIF, Entropy-NRD/DGA, Abused-TLDs, TIF-IPs, URL-Shortener), [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch).
- Tracker rules: [ClearURLs](https://docs.clearurls.xyz/) catalog.
- Design inspiration: [URLCheck](https://github.com/TrianguloY/URLCheck) (CC BY 4.0).
- Optional: [VirusTotal](https://www.virustotal.com/) — active when `VIRUSTOTAL_API_KEY` is set; degrades cleanly if absent.

Commercial/redistribution terms of each source must be verified before any public/commercial use (see SPEC.md §15, §18).

## Design
Full spec: [SPEC.md](SPEC.md).

Built by [kazani](https://kazani.pages.dev).
