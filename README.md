# linkcheck-mcp

> Status: **in development** (v1). A remote MCP server for safe URL inspection.

An MCP server that lets an AI agent (Claude) check where a link *actually* goes and
whether it's safe — **before** anyone opens it. It resolves redirects, strips tracking
parameters, detects phishing structure (homographs, `@`-authority tricks, IP-literal
hosts…), and checks the destination against live threat-intelligence feeds, returning a
tiered verdict (`SAFE` / `SUSPICIOUS` / `DANGEROUS`) plus the evidence behind it.

Inspired by the Android app [URLCheck](https://github.com/TrianguloY/URLCheck), re-shaped
for an AI agent instead of a human tap.

## Tools (v1)
- `check_url(url)` — resolve + clean + heuristics + threat-feed verdict with evidence.
- `check_text(text)` — extract every URL in a blob (incl. bare/defanged) and check each.

## Stack
Cloudflare Worker · stateless `createMcpHandler` (MCP SDK v2) · D1 + KV + Cron.

## Run
_TBD — filled in during build (Stage 4)._

## Sources & attribution
- Threat intel: [HaGeZi dns-blocklists](https://github.com/hagezi/dns-blocklists) (TIF, Entropy-NRD/DGA, Abused-TLDs, TIF-IPs, URL-Shortener), [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch).
- Tracker rules: [ClearURLs](https://docs.clearurls.xyz/) catalog.
- Design inspiration: [URLCheck](https://github.com/TrianguloY/URLCheck) (CC BY 4.0).
- Optional: [VirusTotal](https://www.virustotal.com/).

Commercial/redistribution terms of each source must be verified before any public/commercial use (see SPEC.md §15, §18).

## Design
Full spec: [SPEC.md](SPEC.md).

Built by [kazani](https://kazani.pages.dev).
