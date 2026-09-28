# SPEC.md — Link-Safety MCP Server

**Status:** v1 spec, locked via spec-interview (~48 questions).
**Working name:** `linkcheck-mcp` (final name TBD — shortlist in §16).
**Owner:** kazani
**Date:** 2026-08-12

---

## 1. Overview & Goal

A **remote MCP server** that lets an AI agent (Claude) safely inspect a URL *before* anyone opens it: resolve where a link actually goes, strip tracking junk, detect phishing structure, and check it against live threat-intelligence feeds — returning a clear verdict plus the evidence behind it.

Inspired by the Android app **URLCheck** (TrianguloY), but re-shaped for an agent: URLCheck is a human-tap interceptor; this is an agent-callable service. The design deliberately exceeds a "wrap one API" MCP — it composes a safe resolver, a heuristic engine, and a multi-source verdict, which is the "MCP does real work" shape that survives community scrutiny.

**Root problem it solves:** the owner's standing rule is *never click links from untrusted content; verify unfamiliar URLs first.* Today that's manual. This makes it a callable reflex any Claude session can invoke.

**Prime-directive fit:** small, solo, $0, on the owner's existing Cloudflare stack. Ship v1, validate the core, then extend.

---

## 2. Success Criteria (each names its falsifier — see §12 for full probes)

- **SC1 — Real destination:** `check_url` on a shortened link returns the true final URL + full redirect chain. *Falsifier:* feed a known `bit.ly`/controlled 302 → if resolved_url ≠ true destination, FAIL.
- **SC2 — Catches known-bad:** a current URLhaus malware URL → verdict `DANGEROUS`. *Falsifier:* if it returns `SAFE`/`SUSPICIOUS`, FAIL.
- **SC3 — Catches phishing structure:** `google.com@evil.ru` and `http://192.0.2.1/paypal` → `SUSPICIOUS`+ (heuristic hit). *Falsifier:* if verdict is `SAFE`, FAIL.
- **SC4 — Catches homograph:** `аpple.com` (Cyrillic а) → `SUSPICIOUS`+ (mixed-script hit). *Falsifier:* if `SAFE`, FAIL.
- **SC5 — Clean passes:** `https://anthropic.com` → `SAFE`. *Falsifier:* if `SUSPICIOUS`/`DANGEROUS` with no degraded reason, FAIL.
- **SC6 — Strips + decodes trackers:** URL with `utm_*`, `fbclid` → params removed from clean URL, all params enumerated in evidence. *Falsifier:* if a tracker survives in `cleaned_url`, FAIL.
- **SC7 — Text extraction:** `check_text` on a blob with a normal URL, a bare domain, and a defanged `hxxp://evil[.]com` extracts and checks all three. *Falsifier:* if any of the three is missed, FAIL.
- **SC8 — Never false-safe on failure (anti-criterion, see §13):** a check that couldn't run never yields `SAFE`.
- **SC9 — Performance:** p95 `check_url` < 2s uncached, < 100ms cached (§12). *Cache is keyed on the normalized **input** URL (not resolved) so a hit short-circuits resolution — see §6.*
- **SC10 — Conversion output (binding, from premise grill):** v1 is **not "done"** until (a) the repo is public and (b) a BlogChain post about building it is published. *Falsifier:* code shipped + working but repo private or no post = NOT done. This is what keeps the build from being a strategically-inert desktop tool (see §17). Anti-avoidance guard: the write-up is a ship requirement, not a "someday." **Status (2026-08-14): DEFERRED, not met, not dropped** — the Worker was deployed and shipped live without making the repo public yet, on explicit owner instruction ("only ship, no public repo for now"). SC10 remains open and binding; this is a scope pause, not a decision to skip it. Revisit before calling v1 fully "done."

---

## 3. Users & Context of Use

- **Primary (v1):** the owner's own Claude sessions (desktop, web, mobile, Claude Code) — hence a **remote** server, not stdio.
- **Secondary (future):** a free public good / portfolio artifact once validated (see §15, §18).
- **Consumer is always an LLM agent**, not a human UI — so responses are structured DTOs the agent can reason over and explain, not rendered pages.

---

## 4. Scope

### IN — v1 (ship first)
- Tools: `check_url`, `check_text`.
- Redirect resolution: HEAD-only, hop-capped, private-IP/SSRF-blocked.
- Tracker/param cleaning (ClearURLs catalog) **+ full query decode** (enumerate every param).
- Blocklist signals: **HaGeZi TIF (Mini)**, **URLhaus**, **HaGeZi Most-Abused-TLDs**, **HaGeZi NRD** (newly-registered), **HaGeZi TIF-IPs** (IP reputation on the resolved IP), **HaGeZi URL-Shortener** (explicit shortener flag).
- Heuristic pattern engine: `@`-in-authority, IP-literal host, embedded credentials, deceptive/excessive subdomains, insecure `http://`, `javascript:`/`data:` schemes, homograph (mixed-script + confusables).
- Cross-domain hop flag: warn when redirect chain jumps domains/TLDs.
- Optional **VirusTotal** lookup (owner-supplied free key; degrades cleanly if absent/rate-limited).
- Verdict: tiered `SAFE` / `SUSPICIOUS` / `DANGEROUS` + evidence DTO (`compact` param for terse).
- Degraded/stale handling; verdict cache (1h, keyed on resolved URL).
- Bearer-token auth (single token). `/health` endpoint.
- D1 storage; daily **diff-based** Cron refresh of all feeds + ClearURLs rules; manual seed on deploy.

### IN — v1.1 (fast follow)
- Personal allowlist/blocklist + `manage_list` tool (one tool, `action` param) — allowlist wins but warns on conflict.
- Check-history log (full URL + verdict, 90-day auto-purge) + **privacy controls** (`no_log` per-call flag for ephemeral checks; query-strings redacted in stored history).
- Typosquat/bitsquat detection (curated brand list).
- RDAP exact domain-age (only if NRD proves too coarse).
- Google Safe Browsing (bigger phishing coverage; needs key).
- **Signal candidates validated by comparable (`unphurl-mcp`, a shipped paid product that converged on ~our signal set):** parked-domain detection, MX-record existence check, URL-entropy scoring, and a **Tranco-top-100k known-good fast-path** (instant SAFE, skip resolution+feeds — latency win + load reduction). Add on evidence, not spec-time.
- **Companion Skill (at ship):** model ours on unphurl's `check-url-safety` skill pattern — trigger list (about-to-follow/recommend/output, user asks to open/evaluate, URLs in reviewed code, URL from external source), verdict-tiered response (SAFE silent / SUSPICIOUS mention / DANGEROUS flag+breakdown), and "what not to check" (well-known + allowlisted + own-dev + internal IPs).

### OUT (explicitly not building)
- Full-GET/body fetch or page rendering of targets (exploit surface — HEAD only).
- Certificate/TLS inspection (awkward in Workers `fetch`; weak signal — free DV certs are universal).
- Full DNS analysis (fast-flux/NS) beyond the IP-reputation lookup.
- Human UI / browser-extension / Android intent interception (URLCheck's medium, not ours).
- QR **decode in the server** — the calling model has vision and decodes it, then calls `check_url` (documented usage, not code).
- Multi-token auth, rate limiting, billing (public-phase scope).

---

## 5. Architecture

```
Claude (any surface)
   │  MCP over streamable HTTP  (bearer token)
   ▼
Cloudflare Worker  ── createMcpHandler(() => createServer(env)), built fresh per
   │                  fetch() call so tool handlers close over env/bindings —
   │                  factory itself has no env access (§20 bug #7 finding)
   │  fetch() wrapper verifies bearer token, then delegates to handler
   ├─ check_url(url, {compact?})            request path
   ├─ check_text(text, {compact?})          request path
   ├─ /health                               surfaces feed_meta freshness, all 6 feeds
   ├─ resolver: HEAD hops, cap, SSRF guard (literal IPs only)
   ├─ dns.ts: DNS-over-HTTPS (fetch to cloudflare-dns.com) — resolves a domain to
   │          an IP for the TIF-IPs check; skipped entirely for already-literal
   │          IP hosts (§20 bug #12)
   ├─ heuristics: pattern engine (pure logic)
   ├─ cleaner: ClearURLs rules + query decode
   ├─ feeds.ts: D1 lookups (exact-URL, shortener, abused-TLD) +
   │            KV-blob lookups (TIF-domains, TIF-IPs, Entropy-NRD),
   │            in-memory Set cached at module scope per blob
   ├─ scorer.ts: tiered rules → verdict + evidence (SPEC §8) — BUILT + deployed,
   │             verified against the full live golden set (§12)
   └─ virustotal.ts: real VT client (degradeable) — BUILT + live
   ▲
   │  bindings
   ▼
D1 "linkcheck-mcp-feeds" ── feed_urls_exact (15,870), feed_domains/shortener-only
   (9,815), feed_tlds (445), feed_meta (all 6 feeds' freshness)
KV "linkcheck-mcp-cache" ── feed:tif-domains (166,569, 3.0MB blob),
   feed:tif-ips (62,236, 0.9MB), feed:entropy-nrd (582,153, 13.8MB) —
   one PUT per refresh; verdict:<hash> cache keys land here too [NOT YET BUILT]
Cron Trigger (17 6 * * * daily) — refresh.ts: BUILT + live. D1 feeds
   diffed (added/removed only, chunked at 40 rows/statement — D1's real
   bound-parameter ceiling is 100, not SQLite's 999 default); KV feeds
   full-overwrite (one PUT). Promise.allSettled isolates failures per
   source; feed_meta records "error: <msg>" rather than silently
   skipping a dead upstream. POST /admin/refresh-feeds (bearer-gated,
   same token) triggers it manually — needed because wrangler dev can't
   fire a real cron tick on this machine, doubles as a real "refresh now."
```

- **Framework:** **`createMcpHandler`** (stateless) from `agents/mcp/server`, on **MCP SDK v2** (`@modelcontextprotocol/server@2.0.0`). Cloudflare's officially recommended path for new stateless tools — no Durable Object, simplest setup. A fresh `McpServer` is built per request via a factory; durable data lives in D1/KV (not an MCP session). *Rejected:* **McpAgent** — now deprecated/feature-frozen, Durable-Object-backed (stateful machinery we don't need; `check_url`/`check_text` hold zero session state). *Rejected:* raw `WebStandardStreamableHTTPServerTransport` / raw `@modelcontextprotocol/sdk` — full control but owns Workers-execution-model handling the wrapper gives free (raw transport is known to hang on Workers).
- **Transport:** remote streamable HTTP (`legacy: "stateless"` accepts older clients too). *Rejected:* stdio — desktop-locked, the #1 complaint in research.
- **Stack/deps:** `agents`, `@modelcontextprotocol/server@2.0.0`, `zod`; bindings for D1 + KV + Cron. Tools registered via `server.registerTool(name, {description, inputSchema}, handler)`. Handler at `route: "/mcp"`.
- **Language:** TypeScript.
- **Hosting:** `*.kazani.workers.dev` (free namespace).

---

## 6. Data Model (D1)

**Real architecture (verified + deployed, §20 bug-fix log has the full story) — a two-tier split, not the originally-drafted single D1 design:**

**Tier 1 — small feeds → D1 row-per-entry** (all comfortably under the ~100k-writes/day ceiling, confirmed by real download):
- `feed_domains(domain TEXT PRIMARY KEY, source TEXT)` — **HaGeZi URL-Shortener domains only** (9,815 rows). *(Originally drafted to also hold TIF/NRD — moved out once real sizes were known; see Tier 2.)*
- `feed_urls_exact(url TEXT PRIMARY KEY, source TEXT)` — URLhaus **exact-URL** entries (15,870 rows).
- `feed_tlds(tld TEXT PRIMARY KEY, source TEXT)` — HaGeZi Most-Abused-TLDs (445 rows). New table, not in the original draft — abused-TLD is a suffix match, a different shape than domain matching.
- `feed_meta(source TEXT PRIMARY KEY, last_refresh INTEGER, last_status TEXT, entry_count INTEGER)` — freshness + observability, covers **all six** feeds (both tiers), surfaced at `/health`.
- ~~`feed_ips`~~ — dropped (migration 0003); superseded by Tier 2.
- **v1.1:** `allowlist(domain, note)`, `blocklist(domain, note)`, `history(id, resolved_url_or_redacted, verdict, ts)`.

**Tier 2 — large feeds → one KV blob per feed, not D1 rows.** Real download sizes made the original "TIF-Mini + diff-refresh" D1 plan infeasible before any code was written: TIF-domains is **166,569** entries, TIF-IPs **62,236**, and even the smallest Entropy-NRD/DGA window (7-day) is **582,153** — combined, over 2× the daily D1 write ceiling in a single seed, let alone ongoing diffs. Fix: store each as **one KV value** (newline-joined domain/IP list; sizes 3.0MB / 0.9MB / 13.8MB respectively, all well under KV's 25MB/value cap) — **one `PUT` per refresh regardless of list size**, which also means diff-based refresh logic is unnecessary for these three (a full-blob overwrite *is* the cheap operation here, unlike D1 rows). Parsed into an in-memory `Set` and **cached at module scope** so a 582k-entry blob isn't re-parsed on every request within a warm isolate (`src/feeds.ts`, `loadBlobSet`).
- `feed:tif-domains`, `feed:tif-ips`, `feed:entropy-nrd` (KV keys under the `VERDICT_CACHE` namespace, same namespace as the verdict cache below — one KV namespace, prefixed keys, not a separate namespace per concern).

**Verdict cache:** KV (`verdict:<sha256(NORMALIZED_INPUT_url)>` → JSON, TTL 3600). **Keyed on the input URL, not the resolved URL** — so a cache hit skips the expensive HEAD resolution entirely (the whole point of the cache; see bug-fix log §20). *(Not yet implemented — feed lookups ship in this slice, verdict caching is a later slice once scoring exists.)*

**Domain matching = parent-label walk (not exact match)**, both tiers: every domain lookup checks the full host AND each parent domain — `login.evil.com` → `evil.com` → matches if any listed. Exact-PK match alone would let any subdomain evade the blocklist. (No public-suffix-list dependency in v1 — floor is "≥2 labels," so a bare TLD can never match; a rare over-broad match on a two-label TLD like `co.uk` is a missed edge case, not a false-safe.)

**URLhaus is split by precision:** an **exact-URL** hit (`feed_urls_exact`) → DANGEROUS-tier signal. A **domain-only** hit (via `feed_domains`/TIF-domains blob) → SUSPICIOUS-tier — URLhaus frequently lists malware URLs on *compromised-but-legit* hosts, so flagging the whole domain as dangerous would false-positive legitimate sites.

**IP-reputation requires a real DNS lookup — Workers has no raw DNS API.** The original draft assumed "the resolved IP" was already available from the SSRF guard; it wasn't — the resolver's guard only catches *literal* IP hostnames already in a URL, it never resolves a domain name. Fixed via DNS-over-HTTPS (`src/dns.ts`, plain `fetch()` to `cloudflare-dns.com/dns-query`) — one extra network hop per check, not "free" as first assumed. **Real bug caught in production testing:** an IP-literal URL (e.g. `http://27.215.181.39/x`) was unconditionally sent through DoH resolution, which correctly finds no A record for something that's already an IP — silently skipping the TIF-IPs feed check entirely for every IP-literal URL. Fixed: `isIpLiteral()` check skips DoH and looks the literal IP up directly (§20).

**NRD:** HaGeZi's **Entropy-NRD/DGA, 7-day window** (smallest available; 14/30-day windows are 2×/4×+ bigger) — confirmed via §20 as the smallest viable cut, handled via the Tier-2 KV-blob pattern like the other large feeds.

---

## 7. Tools (MCP surface — `check_url` + `check_text` in v1; `check_skill` added 2026-09-27, 3 total)

### `check_url`
- **Input:** `{ url: string (http/https only), compact?: boolean }`
- **Behavior:** validate scheme → resolve (HEAD hops, SSRF guard, DNS→IP) → clean+decode params → run heuristics → blocklist/IP/shortener lookups → (optional) VirusTotal → score → cache → return DTO.
- **Output DTO (rich):**
```json
{
  "verdict": "SAFE | SUSPICIOUS | DANGEROUS",
  "verdict_reason": "one-line human explanation",
  "input_url": "...",
  "resolved_url": "...",
  "cleaned_url": "... (trackers removed)",
  "redirect_chain": ["url1","url2","..."],
  "cross_domain_hops": true,
  "resolved_ip": "...",
  "is_shortener": false,
  "query_params": [{"key":"utm_source","value":"x","tracker":true}],
  "signals": [
    {"source":"URLhaus","hit":true,"severity":"danger"},
    {"source":"HaGeZi-TIF","hit":false},
    {"source":"heuristic:auth-@","hit":false},
    {"source":"homograph","hit":true,"severity":"suspicious"}
  ],
  "virustotal": {"available": true, "malicious": 0, "suspicious": 0} ,
  "feed_ages": {"TIF":"6h","URLhaus":"6h"},
  "degraded": []   // e.g. ["URLhaus feed unavailable"]
}
```
  `compact:true` → `{verdict, verdict_reason, resolved_url, degraded}`.

### `check_text`
- **Input:** `{ text: string, compact?: boolean }`
- **Behavior:** extract URLs — standard, **bare domains**, and **defanged** (`hxxp://`, `x[.]com`, `x(dot)com`); refang; dedupe; run each through `check_url`; return array + summary (`worst_verdict`, counts).
- **URL cap:** extract at most **20** URLs per blob; if more are present, process the first 20 and return `truncated: true` with the count dropped (fail-loud, never silent). Prevents a crafted blob from amplifying into hundreds of outbound HEADs through the Worker.
- **Bare-domain guard:** a bare token only counts as a domain if its suffix is on a real public-suffix (TLD) list — avoids treating `report.final`, `e.g.`, version strings as URLs.
- **VirusTotal in batch:** OFF by default. Only after cheaper signals mark a URL SUSPICIOUS+ is that single worst candidate VT-checked (stays under VT's 4/min free limit). Single-URL `check_url` may VT normally.

### `check_skill` (added 2026-09-27)
- **Input:** `{ files?: [{path, content}], github_url?: string, compact?: boolean }` — exactly one of `files` / `github_url`.
- **Why here:** scanning a skill is a URL-safety problem one level up — a skill is model input that tells an agent what to fetch and run. linkcheck adds what a plain static scanner can't: every URL the skill references goes through `checkOneUrl` (feeds, heuristics, no VT).
- **Behavior:** (github_url) resolve ref (or `HEAD` for the default branch) → commit SHA → recursive tree → fetch blobs under the skill path from `raw.githubusercontent.com` at that SHA. Then `src/skillscan.ts`: per-file sha256 + size (SEP-2640 `resources` shape), `digestSetHash` over sorted `path\0digest`, line-level rule findings (remote-exec, secret-exfil, credential-path, destructive, git-push, install-hook, hidden-text, injection-phrasing = high; self-modification, code-execution, network = medium), URL extraction. Then up to 10 URLs → `checkOneUrl(url, env, false)`.
- **Two verdicts, kept apart:** `scan.verdict` is deterministic (same files + same `scanner.version`/`rulesHash` → same result; this is what skill-attest re-runs). `overallVerdict` = worst of scan + live URL checks, and is time-varying.
- **Never false-SAFE:** best verdict is `NO_FLAGS`, never `SAFE`. Missing SKILL.md, binary/oversize files, fetch failures, truncation, or a failed URL check → at least SUSPICIOUS.
- **Body-GET exception (§11):** the only place the Worker GETs file bodies — GitHub's own hosts only, skill source text only, never executed. Target URLs stay HEAD-only.
- **Limits:** scanner caps 200 files / 512 KB per file / 2 MB total (`files` input). The GitHub path fetches at most **20** files and checks at most **5** URLs, because a free-plan Worker invocation gets ~50 subrequests: 2 API calls (`commits/{ref|HEAD}` → SHA, then the tree) + 20 raw fetches (pool of 6) + 5 URL checks (each HEAD hops + DoH) has to fit. Over either cap → `degraded` + SUSPICIOUS floor, and a fetch that throws (e.g. the subrequest cap) is recorded per file, never silent. Public repos only; unauthenticated GitHub API (60 req/h per egress IP) → 403/429 fails loud with "pass files directly". Every GitHub fetch uses `redirect: "manual"`, so a 3xx fails loud instead of being followed off `api.github.com` / `raw.githubusercontent.com`, and the commit id must be a 40-hex SHA before it's put in a URL.
- **`hiddenContent`** on `check_text` (added 2026-09-28, branch `feat/hidden-content`, `src/hidden.ts`): deterministic, no-model surfacing of text an agent reads but a human doesn't see. Strong: Unicode tag chars (decoded), zero-width/bidi chars (emoji ZWJ, Indic ZWNJ, leading BOM exempt), sentences in `id` attributes (ids can't contain spaces), base64 decoding to non-JSON text. Weak: HTML comments, `display:none`/`hidden`/zero-size/`opacity:0` elements. `found` = any strong finding; strong sort first; capped at 20 (excerpts quote untrusted input). Decoded text feeds URL extraction. Reports only, never changes URL verdicts. Checked against 6 real pages (GitHub, Wikipedia, BBC, HN, CF docs, simonwillison.net): all `found:false`; two FPs found and fixed that way (Wikipedia underscore anchors, GitHub base64 analytics JSON). Pattern: juraj.bednar.io hermes-firewall extraction layer. **Review fixes 2026-09-28** (/code-review found a CPU DoS: 8–57 s on ~300 KB crafted input vs Workers' ~2 s): `text` capped at `MAX_TEXT_CHARS` (1M); every scan bounded to `MAX_SPAN` (4096) past its start, comments via `indexOf` not a lazy regex, hidden-element windows never overlap — all adversarial shapes ≤ ~220 ms at 1 MB, guarded by a test. Decoded text is extracted BEFORE visible text so a hidden URL can't be pushed out by the 20-URL cap. Subdivision flag emoji (U+1F3F4 + tag letters + CANCEL TAG) exempt. Tool description states `worstVerdict` covers URLs only and excerpts are data. Known gaps (not fixed): only `id` attributes checked (not title/alt/aria-label); `width:0;height:0`, off-screen positioning and quoted-font styles not detected as hiding; unquoted `id=` not parsed; base64 inside `data-*` is flagged.
- **`compact: true`** → `{overallVerdict, overallReason, source, digestSetHash, findings, findingsTotal, degraded}`.
- **Returned findings capped at 50** (`findingsTotal` gives the real count; the verdict uses all). Excerpts quote untrusted skill text into the caller's model context, so a skill that matches on every line can't flood it. The tool description tells the caller to treat excerpts as data (security-audit-static, 2026-09-27).
- **Scanner version:** `skillscan@0.2.0` (0.1.0 never left the machine). Bump on any change to rules OR hashing — `rulesHash` only catches rule changes.
- **Shared code:** `src/skillscan.ts` is vendored byte-for-byte into the skill-attest CLI (~/Desktop/skill-attest). Change it in one place, copy, and bump `SCANNER_VERSION`.

### v1.1 tools
- `manage_list({action:"add_allow|remove_allow|add_block|remove_block|list", domain?})`
- `get_history({limit?, since?})`

---

## 8. Scoring (tiered rules — transparent, no magic numbers) — BUILT, `src/scorer.ts`

- **DANGEROUS:** URLhaus **exact-URL** hit / HaGeZi-TIF (domain or IP) / VirusTotal-malicious / `javascript:`|`data:` scheme / embedded-credentials `@`-authority.
- **SUSPICIOUS:** URLhaus **domain-only** hit (compromised-host nuance) / homograph (mixed-script/confusable) / abused-TLD / Entropy-NRD/DGA / IP-literal host / deceptive-subdomain / cross-domain hops / insecure `http://` / shortener-with-unresolvable-target / VirusTotal-suspicious.
- **SAFE:** none of the above **and** all checks ran (AC1, §13: a degraded check can only push toward SUSPICIOUS, enforced in `computeVerdict`, never silently SAFE).
- **Combination:** worst tier wins; multiple SUSPICIOUS signals stay SUSPICIOUS (not auto-escalated) but all are listed in `verdictReason`, joined by `; `.
- *Rejected:* weighted-score thresholds (magic numbers, hard to explain) and strictest-signal-only (can't express corroboration in evidence).
- **`compact: true`** on `check_url`/`check_text` trims the DTO to `{verdict, verdictReason, resolvedUrl, degraded}` (§7 design, implemented this slice). `check_text` additionally returns `worstVerdict` (max severity across all checked URLs).
- **Verified against the full live golden set (§12) on production**, not just unit tests: clean domain → SAFE, real active URLhaus malware URL → DANGEROUS, embedded-credentials → DANGEROUS, IP-literal → SUSPICIOUS, homograph → SUSPICIOUS, abused-TLD → SUSPICIOUS. All 7 pass on `https://linkcheck-mcp.kazani.workers.dev`.

---

## 9. Key Flows, States, Edge Cases

- **Shortened link:** resolve hops (cap ~10) → verdict on final. Chain returned regardless.
- **HEAD unsupported (405 / no-redirect-on-HEAD):** fall back to a GET whose body read is aborted at the headers (stream, cancel before body) — preserves "never download/execute the body" while still resolving. Prevents a false `unresolvable` that would look like the §17 kill signal.
- **Hanging target / slow feed:** every outbound `fetch` (each redirect hop, each feed pull, VT) runs under an explicit `AbortController` timeout (~3–5s per hop, hard overall budget for the whole check). A dead server must never wedge a request — a timeout becomes a `degraded` note, not a hang. *(Field lesson: "put real timeouts around every tool call; a command must not be able to sit." A missing timeout would masquerade as the §17 HEAD-unreliable kill signal.)*
- **Redirect loop / excess hops:** stop at cap → `SUSPICIOUS` (`degraded: hop cap reached`).
- **NXDOMAIN / unresolvable:** distinct `unresolvable` state → mildly `SUSPICIOUS`, never a crash.
- **Non-HTTP scheme** (`ftp:`, `mailto:`): rejected with clear error. `javascript:`/`data:` → flagged DANGEROUS (not a fetch).
- **Private/internal IP target** (SSRF attempt): resolution refused → `SUSPICIOUS` (`degraded: target resolves to private range`). Never fetched.
- **Allowlisted but feed-listed** (v1.1): `SAFE` + loud warning note (allowlist wins, conflict surfaced).
- **Feed stale (cron failed):** serve last-good + `feed_ages` shows age; verdict may downgrade to include `degraded`.
- **Cold start (fresh deploy, D1 empty):** manual seed run post-deploy; until populated, checks return `degraded: feeds not yet loaded` — never false `SAFE`.

---

## 10. Failure Modes → all fail LOUD, never silent-safe

- Any feed/VirusTotal/resolution step that can't run → append to `degraded[]`; that check contributes **no** SAFE evidence.
- A degraded check can yield `SUSPICIOUS` but **never** `SAFE` (anti-criterion §13).
- Cron failure → structured log + `/health` shows stale `last_refresh`; data served stale with age surfaced.

---

## 11. Security Posture

- **HEAD-first** resolution (GET-headers-only fallback per §9); never downloads/executes target bodies. **One exception (2026-09-27):** `check_skill` GETs skill source files from `api.github.com` / `raw.githubusercontent.com` only, pinned to a commit SHA, redirects refused, never executed (§7). These are the skill's own text, not a target being inspected.
- **SSRF guard (right-sized for Workers):** a Worker runs at Cloudflare's edge with no adjacent private network, so classic private-IP SSRF is largely moot here (no localhost/RFC1918 neighbor to pivot to). Keep a *lightweight* guard — reject obvious private/loopback/link-local ranges + cloud-metadata IPs as defense-in-depth — but do not over-invest; verify Workers `fetch` egress behavior at build rather than assuming a self-hosted threat model.
- **Auth:** bearer token via `wrangler secret`. `createMcpHandler` does **not** verify tokens itself — the Worker `fetch()` wrapper checks the token and returns 401 *before* delegating to the handler (still true — the code is unchanged). Nothing secret in repo; `.env`/`.dev.vars`/`.mcp.json` gitignored before first commit; `.dev.vars` for local. **Public-phase upgrade path:** swap the token gate for `@cloudflare/workers-oauth-provider` / Cloudflare Access (first-class in the Agents SDK) — the seam is the `fetch()` wrapper, so no handler rewrite.
  - **Status (2026-08-15): running AUTHLESS by deliberate choice, not oversight.** Real-world blocker: Claude's native "Add custom connector" UI only supports OAuth (DCR/CIMD) or `static_headers` (currently beta, not exposed in this UI) for remote MCP servers — a plain bearer-token header isn't an available option today (confirmed against Anthropic's own connector-auth docs and a matching open GitHub issue). Rather than build a full OAuth authorization server just to connect the tool for personal use, `MCP_BEARER_TOKEN` was deleted (`wrangler secret delete`) so the existing `if (token && ...)` gate naturally no-ops — zero code change, fully reversible by re-running `wrangler secret put`. Risk accepted deliberately: the tool is read-only (no destructive actions, no PII), so real exposure is quota abuse (D1/VT rate limits), not a data breach — but this is a genuine security-posture reversal made consciously, the same day the repo goes public, not a silent regression. Revisit with real OAuth (DCR/CIMD) if `static_headers` doesn't leave beta and quota abuse becomes a real problem.
- **No `run_any_sql`-style tool.** Inputs validated (scheme allowlist, size caps).
- Repo can be **public** (secrets are in Worker secrets, not code).

---

## 12. Verification & Acceptance (probes)

- **Golden set (run before v1 "done"):**
  1. Fresh URLhaus malware URL → `DANGEROUS`. *(SC2)*
  2. `аpple.com` homograph → `SUSPICIOUS`. *(SC4)*
  3. `google.com@evil.ru` and `http://192.0.2.1/paypal` → `SUSPICIOUS`+. *(SC3)*
  4. `https://anthropic.com` → `SAFE`. *(SC5)*
  5. URL with `utm_*`/`fbclid` → stripped in `cleaned_url`, all enumerated in `query_params`. *(SC6)*
  6. `check_text` blob w/ normal + bare + defanged URL → all three checked. *(SC7)*
- **Performance probe:** time 20 mixed uncached calls; p95 < 2s. Repeat cached; p95 < 100ms. *(SC9)*
- **Safe testing:** redirect hops tested against a **controlled 302 Worker route** + benign public shorteners; feed logic tested with **static known-listed** domains — never by visiting live malware. Unit tests mock the fetch layer; one live e2e against the controlled redirect.
- **Prod verify (each deploy):** poll `/health` to green (all feeds fresh) → run golden clean + golden bad in prod.
- **Auth-compat check (field lesson — top remote-MCP failure mode):** connect from the **real Claude client** via `mcp-remote` (not just MCP Inspector) and confirm the bearer-token flow authenticates and a tool call round-trips. Client/server auth mismatch is a common silent failure.

---

## 13. Anti-Criteria (testable must-not-happens)

- **AC1 (primary):** `check_url` MUST NOT return `verdict:"SAFE"` when any signal check failed to run. *Probe:* disable the URLhaus fetch, check any URL → assert verdict ≠ SAFE and `degraded` non-empty.
- **AC2:** server MUST NOT issue a full-GET/body fetch of a target. *Probe:* inspect outbound requests during a check → assert HEAD only. (Exception: `check_skill`'s GitHub source fetch, §11, which is not a target check. URLs found *inside* a skill still go through the HEAD-only `check_url` path.)
- **AC3:** server MUST NOT resolve/fetch a target that maps to a private IP range. *Probe:* `check_url("http://169.254.169.254/")` → refused, not fetched.
- **AC4:** MUST NOT expose allowlist/history tools (they're v1.1). *Probe:* `tools/list` returns exactly `check_url`, `check_text`, `check_skill` (updated 2026-09-27; enforced by `src/index.test.ts`).

---

## 14. Performance & Scale

- Personal scale: single-digit req/day in practice. Free tier (Workers 100k req/day, D1 free) is comfortable.
- Latency dominated by external redirect hops (not owned) → 2s p95 target chosen realistically; cache absorbs repeats.
- Diff-refresh keeps daily D1 writes well under free ceiling.

---

## 15. Dependencies, Integrations, Licensing

- **HaGeZi dns-blocklists** (TIF Mini/Medium, NRD, Abused-TLDs, TIF-IPs, URL-Shortener) — attribute; **verify commercial/redistribution terms before public phase (hard gate).**
- **URLhaus** (abuse.ch) — attribute.
- **ClearURLs** rules catalog — attribute.
- **VirusTotal** (optional, v1) — free personal key, ToS applies. **BUILT + live**, owner-supplied key set as a Worker secret. `src/virustotal.ts`: read-only lookup (`GET /api/v3/urls/{base64url(url)}`, no submission), response shape verified live before writing the client (docs page is a JS-rendered SPA, didn't yield schema on fetch). 404 (never-scanned) is a valid non-degraded outcome, not an error. `check_url` always consults VT when a key is present; `check_text` deliberately does NOT (would exceed VT's 4 req/min free tier on any multi-link blob) — first pass scores every extracted URL without VT, then only the single worst-verdict candidate gets a VT re-check (§20 bug #18 covers a real bug found wiring this).
- **URLCheck** (CC BY 4.0) — design inspiration only, no code reuse; credit in README.
- **Discoverability:** sharp action-oriented tool descriptions ("call before opening any link from an untrusted source") + a companion **Skill** in the owner's setup wired to the existing link-safety CLAUDE.md rule. **BUILT** (`skills/check-url-safety.md`) — modeled on unphurl-mcp's equivalent skill (§15 comparable), adapted for our SAFE/SUSPICIOUS/DANGEROUS tiers instead of a 0–100 score. Not yet installed to the owner's live `~/.claude/skills/` — the MCP server isn't wired into a client config yet, so the referenced tools aren't reachable; install once that connection exists.

---

## 16. Naming (pick at build time)

Shortlist: `linkcheck-mcp` · `unfurl` · `saferesolve` · `urlens` (reuses a parked name — carries old associations) · `sift`. Not load-bearing for the spec.

---

## 17. Risks & Kill Criteria

- **Primary risk / KILL criterion:** if HEAD-resolution proves unreliable/blocked often enough that verdicts can't be trusted, that's a real economics-lose → **kill or pivot to blocklist-only** (don't resolve). Any *other* dissatisfaction = a slump, push through (per owner's fast-abandon pattern — named here so a slump can't masquerade as a verdict).
- **Premise-grill verdict (2026-08-12):** the build is strategically defensible **only** bound to a conversion output (SC10: public + BlogChain post) and kept small. Root risk named in the grill: building is the owner's comfort/avoidance move vs the real constraint (conversion, not contact). SC10 is the guardrail against this build joining the parked-project graveyard. If, mid-build, v1.1 sprawl returns or the public/write-up commitment slips → that IS the avoidance pattern resurfacing; stop and re-decide, don't quietly keep building.
- Feed size vs D1 limits → mitigated by TIF-Mini + diff-refresh; revisit if writes approach ceiling.
- NRD list size → may need Entropy/DGA subset or short-window cut (verify at build).
- Tool-forgetting → mitigated by descriptions + Skill.

---

## 18. Not Yet Specified (real open questions — stated, not invented)

- **Public-phase shape:** direction = free public good + portfolio piece; monetization (freemium?) undecided. Billing/quota/multi-token model unspecified.
- **HaGeZi/URLhaus/ClearURLs commercial terms** for the public phase — must be resolved before going public (hard gate, §15).
- ~~**Entropy-NRD/DGA subset size** vs D1 write ceiling~~ — **RESOLVED (§6, §20):** real sizes forced the KV-blob pivot for all three large feeds; no longer a D1 concern.
- ~~**Cron diff-refresh for the Tier-2 KV blobs**~~ — **RESOLVED:** built as full-overwrite (no diff needed, confirmed simpler as predicted). `refresh.ts`, live and verified against production.
- **VirusTotal rate-limit strategy** under any future shared use (fine for personal; unspecified for public).
- **Cron cadence tuning** — daily assumed; may tighten if feeds update faster and budget allows.
- **RDAP necessity** — only revisited if NRD proves too coarse in practice.

---

## 19. Decision Log (rejected options + why) — condensed

| Decision | Chosen | Rejected (why) |
|---|---|---|
| Transport | Remote streamable HTTP | stdio (desktop-locked) |
| Framework | `createMcpHandler` stateless (MCP SDK v2) | McpAgent (deprecated, DO-backed, stateful — unneeded); raw transport (hangs on Workers) |
| Primary threat feed | HaGeZi TIF | StevenBlack-only (ad/tracker-oriented, not threat) |
| Domain-age | HaGeZi NRD list | live RDAP in v1 (fragile per-TLD, redundant) |
| Output | Verdict + evidence (+compact) | neutral-only (caller re-implements); minimal (can't audit) |
| Scoring | Tiered rules | weighted score (magic numbers); strictest-only (no corroboration) |
| List conflict | Allowlist wins + warn | silent (hides signal); feed-wins (allowlist useless) |
| Store | D1 (+KV for cache) | KV-only (SQL history painful; write limits) |
| Redirect | HEAD + SSRF guard | full-GET (exploit surface); no-resolve (defeats purpose) |
| Feed refresh | Diff-based daily | full-replace (write budget) |
| Text extract | standard+bare+defanged | strict-only (misses obfuscated threats) |
| Stale feeds | serve + surface age | silent-stale; hard-fail (infra hiccup kills tool) |
| QR | model decodes (doc) | server-side decode (image dep + SSRF) |
| Cert/DNS-deep | out | awkward in Workers / weak signal / low ROI |
| Large-feed storage | One KV blob per feed, in-memory Set, module-scope cache | D1 row-per-entry (original plan — real sizes made it infeasible: 166K/62K/582K rows vs ~100K/day ceiling) |
| IP resolution | DNS-over-HTTPS via fetch() to cloudflare-dns.com | node:dns (unavailable in Workers without extra compat surface); assuming "free" from SSRF guard (wrong — guard never resolves domains) |
| Abused-TLD storage | New `feed_tlds` table, suffix match | Reusing `feed_domains` (wrong shape — TLDs aren't domains, suffix match ≠ parent-label walk) |

---

## 20. Bug-Fix Log (pre-build adversarial review of the spec)

Seven design bugs caught reviewing the spec *before* the premise grill:

1. **Cache couldn't save resolution cost** — was keyed on resolved URL (only known *after* the expensive resolution). Re-keyed on normalized **input** URL. (§6, SC9)
2. **URLhaus matched wrong** — it's URL-level; exact-match rarely hits and domain-match false-flags compromised legit hosts. Split: exact-URL → DANGEROUS, domain-only → SUSPICIOUS. (§6, §8)
3. **Subdomain evasion** — exact-domain PK lookup missed `sub.evil.com`. Now walks parent labels with a public-suffix boundary. (§6)
4. **check_text × VirusTotal rate-limit blowup** — 4/min vs a 10-link email. VT off in batch; worst-candidate-only. (§7)
5. **check_text amplification / bare-domain FPs** — no URL cap + loose bare-domain match. Cap 20 (+`truncated`), TLD-suffix gate. (§7)
6. **HEAD-only would trip its own kill criterion** — many hosts 405 or only redirect on GET. Added GET-headers-only fallback. (§9, §11)
7. **NRD would blow D1 write ceiling** — rolling-window daily diff is inherently huge. Switched to Entropy-NRD/DGA subset. (§6)

Plus one scope-*reducing* correction: the **SSRF guard was over-built for the Workers edge** (no adjacent private network) — right-sized to a lightweight defense-in-depth check. (§11)

### Slice 6 (feeds/D1/KV) — bugs and real findings, caught during build + production testing

8. **SQL generator produced one value per character, not per row** — the default `transform=lambda x: [x]` returned a bare string; iterating a Python string yields its characters. Caught immediately (SQLite's own "all VALUES must have the same number of terms" check failed loud before any bad data was written — no corruption occurred). Fixed the generator, not a database.
9. **D1's original single-tier design was infeasible before any code ran** — real downloads showed TIF-domains (166,569), TIF-IPs (62,236), and even the smallest Entropy-NRD window (582,153) all dwarf D1's ~100k-writes/day ceiling, both combined AND individually for the two biggest. Pivoted to a KV-blob tier for large feeds (§6) — a mid-build architecture change, confirmed with the user before implementing (AskUserQuestion, not silent).
10. **Abused-TLD data isn't domain-shaped** — it's bare TLD suffixes (`actor`, `africa`, ...), not full domains; storing it in `feed_domains` and parent-label-walking it would have been semantically wrong even though it wouldn't have errored. Caught before writing the ingestion code, not after — added `feed_tlds` with suffix-match semantics instead.
11. **IP-reputation assumed "the resolved IP" already existed for free** — it didn't. The resolver's SSRF guard only recognizes literal IPs already in a URL; nothing in the codebase resolved a domain name to an IP. DNS-over-HTTPS via `fetch()` closes the gap (verified live before committing to it), but this is a real extra network hop, not the zero-cost reuse originally assumed.
12. **IP-literal URLs silently skipped IP-reputation checking** — found via a *live production probe* against a real URLhaus IP-literal URL, not a unit test: `resolvedIp` came back `null` with `degraded: ["no A record found"]`, because DoH was called unconditionally even when the host was already a bare IP (there's nothing to resolve). Fixed by checking `isIpLiteral()` first and looking the literal IP up directly. This one would have shipped invisibly — no test had exercised an IP-literal URL against a live feed before the prod probe caught it.
13. **Module-scope blob cache leaked between tests** — `blobSetCache` is keyed only by blob-key string, correct for production (one KV binding per isolate) but wrong for tests using different fake KV instances under the same key name. An earlier test's empty-KV fake poisoned the cache for a later test expecting real data. `_resetBlobCacheForTests()` existed for this exact reason and was simply forgotten on a new test — added it, and to the other KV-touching tests for order-independence.
14. **A bad test IP (`203.0.113.5`, RFC 5737 TEST-NET-3) caused a real 10-second hang** — unroutable but outside the SSRF guard's blocked ranges, so `resolveUrl` actually attempted a live fetch and waited out the timeout. Switched to a link-local address the guard short-circuits instantly — the lesson: a "safe-sounding" test IP still needs to be one your own code actually recognizes as unsafe, or it just hits the network.
15. **Cloudflare deploy/secret propagation is not instant** — a curl immediately after `wrangler deploy` returned a transient 404; a curl immediately after `wrangler secret put` transiently bypassed the just-set auth gate (hit a stale edge node still running the pre-secret Worker version). Both resolved within seconds on retry. Real risk: trusting a single post-mutation security check as final. Now a standing CLAUDE.md gotcha — retry 3-5x before concluding a post-deploy auth check failed or passed.

### Slice 7 (scoring) — bugs and real findings

16. **Cross-domain-hop detection false-flagged the single most common redirect pattern on the web** — exact-hostname comparison meant `anthropic.com → www.anthropic.com` (apex↔www canonicalization) counted as "jumping domains," pushing a completely clean, top-tier site to SUSPICIOUS. Found via the live golden-set run against production (`SC5` failed), not a unit test — the original test suite had encoded the *same wrong assumption* the code did ("subdomain change should count as suspicious"), so nothing caught it until real-world data did. Fixed by comparing a crude registrable-domain proxy (last-2-labels, same no-PSL precedent as `feeds.ts`) instead of the full hostname — `bit.ly → evil.ru` still flags correctly, `login.x.com → account.x.com` and apex↔www no longer do. Regression-checked against a second real site (`github.com`) before considering it closed, not just the one example that broke.
17. **A shell test-harness bug masqueraded as 7 simultaneous product failures** — `sed`/`echo` mangled the SSE response body identically across every golden-set case, producing a JSON parse error at the same byte offset regardless of which URL was checked. The tell that it was harness, not product: identical failure mode across *unrelated* requests. Resolved by parsing the raw response directly (Python `subprocess` + `json.loads`, no intermediate shell text processing) rather than trusting a shell pipeline with an SSE/JSON payload. Lesson banked: when N unrelated checks fail identically, suspect the test rig before the code under test.

### VirusTotal integration — bug and a known limitation

18. **`check_text`'s worst-candidate selector picked the wrong URL when severities tied** — the selector uses strict `>` (first-among-equals wins). In a test using an incomplete env (missing D1/KV bindings), *every* URL degraded under AC1 to at least SUSPICIOUS, tying a genuinely clean URL with a genuinely malicious one — and the clean one, appearing first in the text, won the tie and got the VT re-check instead of the real threat. Root cause was a test-setup bug (bare `ENV` instead of `fakeEnv()`, an artificial degradation-driven tie), not a fundamental code defect — with real bindings, only genuine signal ties are possible. **Known, accepted limitation left as-is:** under a real feed outage in production, two URLs could still tie at SUSPICIOUS purely from degradation, and the arbitrary first-wins tiebreak could pick the less-interesting one for the scarce VT call. Not fixed — doesn't compromise the safety property (the non-VT-checked URL still surfaces at its correct minimum severity via AC1), and richer tie-break logic wasn't judged worth the complexity for v1. Revisit if it proves wrong in practice.

### Cron feed refresh — bug found live in production, plus a design addition

19. **D1's real bound-parameter limit (100) is far stricter than SQLite's default (999), and the failure is silent until a feed actually has diff churn** — the initial chunk size (400 rows/statement, 800 params for INSERT) passed every test, because the test diffs were tiny (1-2 rows) and the first two production feeds checked (`HaGeZi-Shortener`, `HaGeZi-AbusedTLD`) both happened to have *zero* diff that run — their batch-write code path never executed at all. Only `URLhaus` — the one live, continuously-updated feed — had real churn, and only it hit `D1_ERROR: too many SQL variables`. Found via the manual `/admin/refresh-feeds` trigger against real production data, not a unit test. Verified the correct limit against Cloudflare's own docs (100 bound params/query) before picking a fix, then reduced `CHUNK` to 40 (80/41 params for INSERT/DELETE respectively). Added a test that forces a 90-row diff specifically to exercise multi-chunk writes — the class of test the original tiny-diff tests couldn't have caught — **and enforced the same 100-param ceiling inside the test fake itself**, so a future regression to an oversized `CHUNK` fails in `npm test`, not in production against a live feed with real churn.
20. **A cron refresh writes new KV data from a different Worker isolate than the ones serving live requests — there is no cross-isolate cache-invalidation signal available to application code.** The module-scope blob `Set` cache (added in Slice 6 as a plain "load once per isolate" cache, no expiry) would have made a refresh invisible to already-warm isolates for however long they stayed alive. Added a 15-minute TTL as part of building the refresh feature — not a separate fix, but a real correctness requirement for the feature to actually do what it claims. Verified deterministically with Node's built-in `t.mock.timers` (mocking `Date`) rather than left untested for being awkward to test with real wall-clock waits: within-TTL cache hit, past-TTL refetch, refetch correctly observes a same-key value change (simulating the cron-writes/isolate-reads split).
```
