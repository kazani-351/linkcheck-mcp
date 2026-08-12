// URL extraction from free text for check_text (SPEC §4, §7). Finds standard URLs,
// bare domains, and defanged forms (hxxp://, x[.]com, x(dot)com) — phishing emails
// routinely obfuscate links this way specifically to dodge naive URL scanners.
//
// Scope guards (SPEC §20 bug #5 — amplification + false positives):
// - cap MAX_URLS per call, report `truncated` rather than silently processing all
// - bare-domain matches gated on a real public-suffix list, not "looks domain-shaped"

export const MAX_URLS = 20;

// A deliberately small, common-TLD allowlist — not the full IANA/PSL list (that's
// a v1.1-scale data dependency). Covers the overwhelming majority of real links;
// false negatives here just mean a bare domain isn't extracted, which is a missed
// check, not a false "safe" claim about a URL we did check.
const COMMON_TLDS = new Set([
  "com", "net", "org", "io", "co", "info", "biz", "dev", "app", "xyz", "top", "site",
  "online", "shop", "store", "club", "live", "vip", "icu", "cn", "ru", "uk", "de",
  "fr", "jp", "in", "us", "ca", "au", "br", "nl", "es", "it", "me", "tv", "cc", "ai",
  "gov", "edu", "mil", "int", "id", "sms", "link", "click", "buzz", "work", "email",
]);

// Refang the WHOLE text before matching (not per-token) — defanged brackets like
// evil[.]com are literal chars in the un-refanged text, and excluding `]` from a
// URL-body char class (to dodge markdown-link trailing brackets) would truncate
// the match right at the defanging syntax itself if we tried to match first.
function refang(s: string): string {
  return s
    .replace(/hxxps?/gi, (m) => (m.toLowerCase() === "hxxps" ? "https" : "http"))
    .replace(/\[\.\]|\(dot\)/gi, ".")
    .replace(/\[:\]/g, ":");
}

// Matched against already-refanged text: standard http(s) URLs, and bare
// domain-looking tokens (word.word[.word...]), each with an optional path/query.
// Deliberately conservative — see COMMON_TLDS gate below.
const CANDIDATE_RE =
  /\bhttps?:\/\/[^\s<>"')\]]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[/?][^\s<>"')\]]*)?/gi;

export interface ExtractResult {
  urls: string[];
  truncated: boolean;
  droppedCount: number;
}

export function extractUrls(text: string): ExtractResult {
  const found: string[] = [];
  const seen = new Set<string>();
  const refangedText = refang(text);

  for (const candidate of refangedText.match(CANDIDATE_RE) ?? []) {
    let normalized: string;

    if (/^https?:\/\//i.test(candidate)) {
      normalized = candidate;
    } else {
      // bare domain form — gate on a real TLD so "report.final" / "e.g." / "v1.2.3"
      // don't get treated as URLs.
      const hostPart = candidate.split(/[/?]/)[0];
      const tld = hostPart.split(".").pop()?.toLowerCase();
      if (!tld || !COMMON_TLDS.has(tld)) continue;
      normalized = `http://${candidate}`;
    }

    try {
      const u = new URL(normalized);
      const key = u.toString();
      if (!seen.has(key)) {
        seen.add(key);
        found.push(key);
      }
    } catch {
      // unparseable candidate — skip, don't crash the whole extraction
    }
  }

  const truncated = found.length > MAX_URLS;
  return {
    urls: found.slice(0, MAX_URLS),
    truncated,
    droppedCount: truncated ? found.length - MAX_URLS : 0,
  };
}
