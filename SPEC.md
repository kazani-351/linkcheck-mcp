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
Cloudflare Worker  ── createMcpHandler (stateless, MCP SDK v2)
   │  fetch() wrapper verifies bearer token, then delegates to handler
   ├─ check_url(url, {compact?})            request path
   ├─ check_text(text, {compact?})          request path
   ├─ /health                               ops/smoke
   ├─ resolver: HEAD hops, cap, SSRF guard, DNS→IP
   ├─ heuristics: pattern engine (pure logic)
   ├─ cleaner: ClearURLs rules + query decode
   ├─ scorer: tiered rules → verdict + evidence
   ├─ cache: verdict by resolved URL, 1h TTL      → KV or D1 (see §6)
   └─ (optional) VirusTotal client (degradeable)
   ▲
   │  bindings
   ▼
D1 (SQLite)  ── feeds (domains, IPs, shorteners, abused-TLDs, NRD, clearurls rules), meta (per-feed last_refresh)
Cron Trigger (daily) ── diff-refresh each feed into D1; purge/update meta; (v1.1) purge history >90d
```

- **Framework:** **`createMcpHandler`** (stateless) from `agents/mcp/server`, on **MCP SDK v2** (`@modelcontextprotocol/server@2.0.0`). Cloudflare's officially recommended path for new stateless tools — no Durable Object, simplest setup. A fresh `McpServer` is built per request via a factory; durable data lives in D1/KV (not an MCP session). *Rejected:* **McpAgent** — now deprecated/feature-frozen, Durable-Object-backed (stateful machinery we don't need; `check_url`/`check_text` hold zero session state). *Rejected:* raw `WebStandardStreamableHTTPServerTransport` / raw `@modelcontextprotocol/sdk` — full control but owns Workers-execution-model handling the wrapper gives free (raw transport is known to hang on Workers).
- **Transport:** remote streamable HTTP (`legacy: "stateless"` accepts older clients too). *Rejected:* stdio — desktop-locked, the #1 complaint in research.
- **Stack/deps:** `agents`, `@modelcontextprotocol/server@2.0.0`, `zod`; bindings for D1 + KV + Cron. Tools registered via `server.registerTool(name, {description, inputSchema}, handler)`. Handler at `route: "/mcp"`.
- **Language:** TypeScript.
- **Hosting:** `*.kazani.workers.dev` (free namespace).

---

## 6. Data Model (D1)

- `feed_domains(domain TEXT PRIMARY KEY, source TEXT)` — TIF, **Entropy-NRD/DGA subset** (not full NRD — see below), abused-TLD, shortener, and URLhaus **host-level** domains. Indexed on `domain`.
- `feed_ips(ip TEXT PRIMARY KEY, source TEXT)` — TIF-IPs.
- `feed_urls_exact(url TEXT PRIMARY KEY)` — URLhaus **exact-URL** entries (rare-hit but high-confidence when they do).
- `clearurls_rules(...)` — parsed ClearURLs param/redirect rules.
- `feed_meta(source TEXT PRIMARY KEY, last_refresh INTEGER, last_status TEXT, entry_count INTEGER)` — freshness + observability.
- **v1.1:** `allowlist(domain, note)`, `blocklist(domain, note)`, `history(id, resolved_url_or_redacted, verdict, ts)`.
- **Verdict cache:** KV (`verdict:<sha256(NORMALIZED_INPUT_url)>` → JSON, TTL 3600). **Keyed on the input URL, not the resolved URL** — so a cache hit skips the expensive HEAD resolution entirely (the whole point of the cache; see bug-fix log §20). KV chosen over D1 to avoid write churn; feeds stay in D1 for indexed lookups + SQL. This is the one place two stores are used, deliberately.

**Domain matching = parent-label walk (not exact match).** Every domain lookup checks the full host AND each parent domain against `feed_domains`: `login.evil.com` → `evil.com` → matches if any listed. Exact-PK match alone would let any subdomain evade the blocklist. (Registrable-domain boundary via a public-suffix check to avoid matching bare TLDs.)

**URLhaus is split by precision:** an **exact-URL** hit (`feed_urls_exact`) → DANGEROUS. A **domain-only** URLhaus/host hit → SUSPICIOUS, not DANGEROUS — URLhaus frequently lists malware URLs on *compromised-but-legit* hosts, so flagging the whole domain as dangerous would false-positive legitimate sites.

**NRD:** use HaGeZi's **Entropy-NRD/DGA subset**, not full NRD. Full NRD is a rolling window whose *daily diff* is inherently huge (large add + large drop-off), which would blow D1's ~100k-writes/day ceiling on its own — defeating diff-refresh. The Entropy/DGA cut is far smaller and targets the algorithmically-generated domains that are the actual threat-actor signal.

**Diff-refresh:** each daily cron pulls the source, computes added/removed vs current D1 rows, writes only the delta → stays under D1's ~100k-writes/day free ceiling. Full-replace rejected (blows write budget). Feed sizes (esp. Entropy-NRD, TIF-Mini) verified against the ceiling at build.

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
- **Entropy-NRD/DGA subset size** vs D1 write ceiling — decided to use the subset (§6); still verify its real daily-diff size against the ~100k-writes ceiling at build, and confirm TIF-Mini + all feeds together fit.
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
```
