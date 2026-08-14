// Heuristic phishing-structure detector (SPEC §4, §7, §8). Pure logic, no external
// data. Each check is a pattern real phishing kits rely on — not a threat feed.
//
// Scope (v1, per §4/§20): @-authority, IP-literal host, embedded credentials,
// deceptive/excessive subdomains, insecure http://, javascript:/data: schemes,
// homograph via mixed-script + confusables (NOT flagging every punycode domain —
// that would false-positive legitimate IDNs like münchen.de, per SPEC §9).

import { domainToUnicode } from "node:url";

export type Severity = "dangerous" | "suspicious";

export interface HeuristicHit {
  id: string;
  severity: Severity;
  detail: string;
}

// A small, deliberately conservative confusable-character map: Cyrillic/Greek
// letters that are visually near-identical to Latin letters and show up in real
// homograph attacks (аpple.com, gооgle.com). Not exhaustive — a full Unicode
// confusables table is a v1.1-scale undertaking; this covers the common cases.
const CONFUSABLES: Record<string, string> = {
  а: "a", е: "e", о: "o", р: "p", с: "c", у: "y", х: "x", і: "i", ѕ: "s", // Cyrillic
  ԁ: "d", ɡ: "g", // extended Cyrillic/Latin lookalikes
  α: "a", ο: "o", ρ: "p", // Greek
};

function scriptsInHost(host: string): Set<string> {
  const scripts = new Set<string>();
  for (const ch of host) {
    if (/[a-z]/i.test(ch)) scripts.add("latin");
    else if (ch in CONFUSABLES) scripts.add("confusable");
    else if (/[Ѐ-ӿ]/.test(ch)) scripts.add("cyrillic");
    else if (/[Ͱ-Ͽ]/.test(ch)) scripts.add("greek");
  }
  return scripts;
}

/** True if the hostname is a bare IPv4 or IPv6 literal (no domain name at all).
 *  Exported: index.ts also needs this to skip a pointless DoH lookup on an
 *  already-literal IP and check it against the IP-reputation feed directly. */
export function isIpLiteral(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, "");
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (h.includes(":") && /^[0-9a-f:]+$/i.test(h)) return true; // IPv6
  return false;
}

/** Registrable-domain-ish subdomain count (rough — no PSL dependency in v1). */
function subdomainDepth(hostname: string): number {
  const parts = hostname.split(".");
  return Math.max(0, parts.length - 2); // e.g. a.b.example.com -> 2
}

export function runHeuristics(rawUrl: string): HeuristicHit[] {
  const hits: HeuristicHit[] = [];
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return hits; // caller already validates scheme elsewhere; nothing to add here
  }

  if (u.protocol === "javascript:" || u.protocol === "data:") {
    hits.push({
      id: "dangerous_scheme",
      severity: "dangerous",
      detail: `${u.protocol} URLs execute/embed content directly`,
    });
  }

  if (u.protocol === "http:") {
    hits.push({ id: "insecure_http", severity: "suspicious", detail: "unencrypted http:// transport" });
  }

  if (u.username || u.password) {
    hits.push({
      id: "embedded_credentials",
      severity: "dangerous",
      detail: "URL authority contains embedded credentials (user:pass@ or user@) — classic disguise for the real host",
    });
  }

  if (isIpLiteral(u.hostname)) {
    hits.push({ id: "ip_literal_host", severity: "suspicious", detail: `host is a bare IP literal (${u.hostname}), not a domain name` });
  }

  if (subdomainDepth(u.hostname) >= 4) {
    hits.push({
      id: "deceptive_subdomain_depth",
      severity: "suspicious",
      detail: `${subdomainDepth(u.hostname)} subdomain levels — often used to bury a fake brand name (e.g. paypal.com.evil.ru)`,
    });
  }

  // WHATWG URL silently IDNA-encodes non-ASCII hostnames to punycode (xn--...) —
  // decode back to Unicode first, or every homograph attempt would be invisible
  // to a raw script-mixing check on u.hostname.
  const unicodeHost = domainToUnicode(u.hostname);
  const scripts = scriptsInHost(unicodeHost);
  const nonLatinScripts = [...scripts].filter((s) => s !== "latin");
  if (scripts.has("latin") && nonLatinScripts.length > 0) {
    hits.push({
      id: "homograph_mixed_script",
      severity: "suspicious",
      detail: `hostname mixes Latin with ${nonLatinScripts.join("/")} characters — classic homograph/confusable attack shape`,
    });
  }

  return hits;
}
