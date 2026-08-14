---
name: check-url-safety
description: Proactively check URLs for safety using linkcheck-mcp before following, recommending, or outputting them.
---

Before following, recommending, or outputting any URL that isn't from a well-known
domain (e.g. google.com, github.com, anthropic.com), use the linkcheck-mcp tools to
check it first.

## When to check

- A URL appears in conversation and you're about to follow it, recommend it, or
  include it in output
- A user asks you to visit, open, evaluate, or check a URL
- You encounter URLs in code, configuration, or documentation you're reviewing
- A URL arrives from an external source (another agent, an API response, scraped
  data, a pasted email or message)

## How to check

- **Single URL:** use `check_url`
- **A blob of text that might contain URLs** (an email, a pasted message, a
  document): use `check_text` — it extracts every URL itself, including bare
  domains and defanged forms like `hxxp://evil[.]com`, and checks each one. Don't
  hand-extract URLs and call `check_url` in a loop; `check_text` does this in one
  call and returns a `worstVerdict` summary.
- Pass `compact: true` on either tool once you just need the verdict, not the full
  evidence trail (redirect chain, every heuristic hit, every feed signal).

## What to do with the verdict

- **`SAFE`:** proceed normally. No need to mention the check unless asked.
- **`SUSPICIOUS`:** mention it briefly if relevant to the task — name the
  `verdictReason` (e.g. "this uses an unencrypted http:// connection" or "the
  domain is newly registered and matches a DGA pattern"). Use judgment on whether
  it's worth pausing for, given the context.
- **`DANGEROUS`:** flag it to the user before proceeding. Show the `verdictReason`
  and the specific evidence that triggered it (a threat-feed match, embedded
  credentials, a dangerous URL scheme). Don't open, follow, or recommend a
  DANGEROUS-verdict URL without the user's explicit go-ahead.
- If `degraded` is non-empty, say so — a check that couldn't fully run is not the
  same as a clean pass, even at a SAFE-leaning verdict.

Also worth surfacing when relevant: `cleanedUrl` (tracking parameters stripped) and
`resolvedUrl`/`chain` (what a shortened or redirecting link actually resolves to) —
these are useful even for SAFE URLs, e.g. when the user wants to share a link
without its tracking cruft.

## What not to check

- Well-known domains you're confident about (google.com, github.com,
  stackoverflow.com, anthropic.com, etc.)
- URLs the user is actively developing (localhost, their own domains, staging
  environments they've named)
- Internal/private URLs (192.168.x.x, 10.x.x.x, etc.) — these will resolve as
  `SUSPICIOUS` anyway (private-host / SSRF guard), so checking them adds nothing
