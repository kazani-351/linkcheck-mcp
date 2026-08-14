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
- **SC10 — Conversion output (binding, from premise grill):** v1 is **not "done"** until (a) the repo is public and (b) a BlogChain post about building it is published. *Falsifier:* code shipped + working but repo private or no post = NOT done. This is what keeps the build from being a strategically-inert desktop tool (see §17). Anti-avoidance guard: the write-up is a ship requirement, not a "someday."

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
   ├─ scorer: tiered rules → verdict + evidence          [NOT YET BUILT — next slice]
   └─ (optional) VirusTotal client (degradeable)          [NOT YET BUILT]
   ▲
   │  bindings
   ▼
D1 "linkcheck-mcp-feeds" ── feed_urls_exact (15,870), feed_domains/shortener-only
   (9,815), feed_tlds (445), feed_meta (all 6 feeds' freshness)
KV "linkcheck-mcp-cache" ── feed:tif-domains (166,569, 3.0MB blob),
   feed:tif-ips (62,236, 0.9MB), feed:entropy-nrd (582,153, 13.8MB) —
   one PUT per refresh; verdict:<hash> cache keys land here too [NOT YET BUILT]
Cron Trigger (daily refresh)                                    [NOT YET BUILT]
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

## 7. Tools (MCP surface — kept to 2 in v1 per tool-count discipline)

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

### v1.1 tools
- `manage_list({action:"add_allow|remove_allow|add_block|remove_block|list", domain?})`
- `get_history({limit?, since?})`

---

## 8. Scoring (tiered rules — transparent, no magic numbers)

- **DANGEROUS:** URLhaus **exact-URL** hit / HaGeZi-TIF (domain or IP) / VirusTotal-malicious / `javascript:`|`data:` scheme / embedded-credentials `@`-authority.
- **SUSPICIOUS:** URLhaus **domain-only** hit (compromised-host nuance) / homograph (mixed-script/confusable) / abused-TLD / Entropy-NRD/DGA / IP-literal host / deceptive-subdomain / cross-domain hops / insecure `http://` / shortener-with-unresolvable-target / VirusTotal-suspicious.
- **SAFE:** none of the above **and** all checks ran.
- **Combination:** worst tier wins; multiple SUSPICIOUS signals stay SUSPICIOUS (not auto-escalated) but all are listed.
- *Rejected:* weighted-score thresholds (magic numbers, hard to explain) and strictest-signal-only (can't express corroboration in evidence).

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

- **HEAD-first** resolution (GET-headers-only fallback per §9); never downloads/executes target bodies.
- **SSRF guard (right-sized for Workers):** a Worker runs at Cloudflare's edge with no adjacent private network, so classic private-IP SSRF is largely moot here (no localhost/RFC1918 neighbor to pivot to). Keep a *lightweight* guard — reject obvious private/loopback/link-local ranges + cloud-metadata IPs as defense-in-depth — but do not over-invest; verify Workers `fetch` egress behavior at build rather than assuming a self-hosted threat model.
- **Auth:** bearer token via `wrangler secret`. `createMcpHandler` does **not** verify tokens itself — the Worker `fetch()` wrapper checks the token and returns 401 *before* delegating to the handler. Nothing secret in repo; `.env`/`.dev.vars`/`.mcp.json` gitignored before first commit; `.dev.vars` for local. **Public-phase upgrade path:** swap the token gate for `@cloudflare/workers-oauth-provider` / Cloudflare Access (first-class in the Agents SDK) — the seam is the `fetch()` wrapper, so no handler rewrite.
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
- **AC2:** server MUST NOT issue a full-GET/body fetch of a target. *Probe:* inspect outbound requests during a check → assert HEAD only.
- **AC3:** server MUST NOT resolve/fetch a target that maps to a private IP range. *Probe:* `check_url("http://169.254.169.254/")` → refused, not fetched.
- **AC4:** v1 MUST NOT expose allowlist/history tools (they're v1.1). *Probe:* `tools/list` returns exactly `check_url`, `check_text`.

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
- **VirusTotal** (optional, v1) — free personal key, ToS applies.
- **URLCheck** (CC BY 4.0) — design inspiration only, no code reuse; credit in README.
- **Discoverability:** sharp action-oriented tool descriptions ("call before opening any link from an untrusted source") + a companion **Skill** in the owner's setup wired to the existing link-safety CLAUDE.md rule.

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
- **Cron diff-refresh for the Tier-2 KV blobs** — not yet built. Since a full-blob overwrite is cheap (one PUT), this is likely simpler than originally planned (no diff logic needed, just refetch-and-replace on schedule) — but the cron itself, and its failure/staleness handling for KV blobs specifically, is unbuilt.
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
```
