# linkcheck-mcp

> Status: **v1 live**. A remote MCP server for safe URL inspection.

An MCP server that lets an AI agent (Claude) check where a link *actually* goes and
whether it's safe — **before** anyone opens it. It resolves redirects, strips tracking
parameters, detects phishing structure (homographs, `@`-authority tricks, IP-literal
hosts…), and checks the destination against live threat-intelligence feeds, returning a
tiered verdict (`SAFE` / `SUSPICIOUS` / `DANGEROUS`) plus the evidence behind it.

Inspired by the Android app [URLCheck](https://github.com/TrianguloY/URLCheck), re-shaped
for an AI agent instead of a human tap.

## Tools (v1)
- `check_url(url, compact?)` — resolve + clean + heuristics + threat-feed verdict with evidence. `compact: true` returns just `{verdict, verdictReason, resolvedUrl, degraded}`.
- `check_text(text, compact?)` — extract every URL in a blob (standard, bare, and defanged forms like `hxxp://evil[.]com`), check each, and return a `worstVerdict` summary.

## Stack
Cloudflare Worker · stateless `createMcpHandler` (MCP SDK v2) · D1 (small feeds) + KV (large feeds + verdict cache).

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
3. Set the bearer token that gates the MCP endpoint:
   ```bash
   npx wrangler secret put MCP_BEARER_TOKEN
   ```
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
     -H "authorization: Bearer <token>" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check_url","arguments":{"url":"https://example.com"}}}'
   ```

### Connect a client
Add to Claude Desktop / Claude Code via [`mcp-remote`](https://www.npmjs.com/package/mcp-remote):
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
See `skills/check-url-safety.md` for a companion Skill that teaches Claude to call these tools proactively on untrusted links, rather than waiting to be asked.

## Sources & attribution
- Threat intel: [HaGeZi dns-blocklists](https://github.com/hagezi/dns-blocklists) (TIF, Entropy-NRD/DGA, Abused-TLDs, TIF-IPs, URL-Shortener), [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch).
- Tracker rules: [ClearURLs](https://docs.clearurls.xyz/) catalog.
- Design inspiration: [URLCheck](https://github.com/TrianguloY/URLCheck) (CC BY 4.0).
- Optional: [VirusTotal](https://www.virustotal.com/).

Commercial/redistribution terms of each source must be verified before any public/commercial use (see SPEC.md §15, §18).

## Design
Full spec: [SPEC.md](SPEC.md).

Built by [kazani](https://kazani.pages.dev).
