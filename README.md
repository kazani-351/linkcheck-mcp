<p align="center"><img src="brand/logo.svg" width="96" alt="linkcheck logo"></p>

<h1 align="center">linkcheck</h1>

<p align="center"><b>Know where a link actually goes, before anyone clicks it.</b><br>
A free MCP server that lets an AI agent check a link before it opens, follows, or recommends it.</p>

<p align="center"><a href="https://linkcheck-mcp.kazani.workers.dev/">Try it in the browser</a> · <a href="#connect-in-30-seconds">Connect</a> · <a href="SPEC.md">Design spec</a></p>

---

Give linkcheck a link and it:

1. **Follows the redirects** with HEAD requests only, so the page never loads and nothing runs.
2. **Strips trackers** like `utm_*` and `fbclid`, and lists what it removed.
3. **Inspects the shape** for phishing tricks: lookalike characters, `@` tricks, raw IP hosts, abused domain endings.
4. **Checks the destination** against URLhaus and five HaGeZi lists (threat intel, newly registered domains, shorteners, abused domain endings), refreshed daily.

Then it returns `SAFE`, `SUSPICIOUS` or `DANGEROUS` with the evidence. If any check can't finish, the verdict can only get stricter. It never falls back to `SAFE`.

Verdicts are a best-effort signal, not a guarantee. A `SAFE` link can still turn out to be malicious, and a `SUSPICIOUS` one can be fine. Use it as one input, not the final word.

**Privacy:** linkcheck does not store the links you check. To resolve a link, it sends HEAD requests to that link's servers from Cloudflare, with a user agent that names this project.

## Connect in 30 seconds

The public instance is free and needs no account or key.

**Claude:** Settings → Connectors → Add custom connector. Paste the URL below and pick **No sign-in**.

```
https://linkcheck-mcp.kazani.workers.dev/mcp
```

**Other MCP clients:**

```json
{
  "mcpServers": {
    "linkcheck": { "type": "http", "url": "https://linkcheck-mcp.kazani.workers.dev/mcp" }
  }
}
```

Public checks use the threat feeds and structural checks. VirusTotal is reserved for the maintainer's own key; self-host with your own key to get it.

## Tools

- **`check_url(url, compact?)`**: one link in, a verdict out, with the redirect chain, removed trackers, and every feed hit. `compact: true` returns just `{verdict, verdictReason, resolvedUrl, degraded}`.
- **`check_text(text, compact?)`**: finds every link in an email, message or page (including defanged ones like `hxxp://evil[.]com`), checks each, and returns a `worstVerdict`. It also surfaces text hidden from a human reader: Unicode tag text, zero-width characters, sentences in `id` attributes and base64 text as strong signals, and HTML comments and hidden elements as weak ones.
- **`check_skill(files | github_url)`**: scans an agent skill before you install it. It flags risky patterns in the files, pins GitHub sources to a commit, and checks every link inside. The best verdict is `NO_FLAGS`, never `SAFE`.

Inspired by the Android app [URLCheck](https://github.com/TrianguloY/URLCheck), reshaped for an AI agent instead of a human tap.

## Endpoints
- `GET /` — human landing page (served for `text/html` requests; never shadows the MCP transport on the same origin).
- `GET /health` — per-feed `last_status` / `last_refresh`.
- `GET /.well-known/mcp/server-card.json` — machine-readable server descriptor for MCP discovery.
- `POST /mcp` — the MCP transport.
- `POST /check` — plain-HTTP verdict (`{url, compact?}`) for non-MCP clients, e.g. a shell pre-flight hook that checks links before an agent acts on them. Same logic as `check_url`.

## Stack
Cloudflare Worker · stateless `createMcpHandler` (MCP SDK v2) · D1 (small feeds) + KV (large feeds + verdict cache) · daily Cron Trigger for feed refresh.

## Feed refresh
Threat feeds refresh daily via a Cloudflare Cron Trigger (`17 6 * * *` UTC). Small feeds (URLhaus, HaGeZi Shortener/Abused-TLD, all in D1) are diffed — only added/removed rows are written, chunked to stay under D1's 100-bound-parameter-per-query limit. Large feeds (HaGeZi TIF-domains/TIF-IPs/Entropy-NRD, all in KV) are fully overwritten each refresh — one `PUT` regardless of list size. A failed source doesn't block the others; check `/health` for per-feed `last_status`/`last_refresh`.

To trigger a refresh manually (local `wrangler dev` can't fire a real cron tick on macOS < 13.5, so this is also how the refresh logic is verified against production):
```bash
curl -X POST https://<your-worker>.workers.dev/admin/refresh-feeds \
  -H "authorization: Bearer <token>"
```

## Self-host

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
3. **Secrets (optional):**
   - `npx wrangler secret put VIRUSTOTAL_API_KEY` adds VirusTotal lookups.
   - `npx wrangler secret put OWNER_TOKEN` decides who gets them. VirusTotal runs **only for the owner**: requests carrying `Authorization: Bearer <OWNER_TOKEN>` (in Claude's Add custom connector dialog: No sign-in, then a request header `authorization` = `Bearer <OWNER_TOKEN>`). Everyone else gets the same checks without VT, and the full result shows `"virusTotalChecked": false`. Without `OWNER_TOKEN`, nobody gets VT and `/admin/refresh-feeds` is refused.
   - `npx wrangler secret put MCP_BEARER_TOKEN` locks the whole server to one token, for a private instance. The public instance leaves it unset.
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

**Claude:** Settings → Connectors → Add custom connector → paste the server URL (`https://<your-worker>.workers.dev/mcp`) and choose No sign-in. If you set a token, add it as a request header in the same dialog.

**Any other MCP client, with a bearer token:** via [`mcp-remote`](https://www.npmjs.com/package/mcp-remote):
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

## Sources and licenses

- Code: [MIT](LICENSE).
- Tracker rules: a snapshot of the [ClearURLs rules](https://github.com/ClearURLs/Rules) ships in `src/data/clearurls-rules.json` under its own license, LGPL-3.0 (see `src/data/NOTICE.md`).
- Threat intel, downloaded at runtime and not stored in this repo: [HaGeZi dns-blocklists](https://github.com/hagezi/dns-blocklists) and [HaGeZi nrd](https://github.com/hagezi/nrd) (GPL-3.0), and [URLhaus](https://urlhaus.abuse.ch/) under the [abuse.ch terms](https://abuse.ch/terms-of-use/).
- Optional: [VirusTotal](https://www.virustotal.com/), owner requests only.
- Design inspiration: [URLCheck](https://github.com/TrianguloY/URLCheck) (CC BY 4.0).

Built by [kazani](https://kazani.pages.dev).
