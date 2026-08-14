// Threat-feed lookups against D1 (SPEC §6, §20 bug #3). Domain matching walks
// parent labels (a.b.evil.com -> b.evil.com -> evil.com) rather than exact match —
// an exact-PK lookup alone would let any subdomain evade the blocklist.
//
// Typed against a minimal slice of D1Database's real shape (prepare/bind/all) so
// the same code runs against a live Cloudflare binding in prod and a lightweight
// in-memory fake in Node tests — no adapter layer needed either side.

export interface MinimalD1 {
  prepare(sql: string): {
    bind(...values: unknown[]): {
      all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
    };
  };
}

/** Write-capable D1 slice — used by refresh.ts (cron ingestion), not the
 *  read-only lookup functions below. Kept separate so lookupX() signatures
 *  stay obviously read-only. */
export interface WritableD1 extends MinimalD1 {
  prepare(sql: string): {
    bind(...values: unknown[]): {
      all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
      run(): Promise<{ success: boolean }>;
    };
  };
}

export interface FeedHit {
  matchedValue: string; // the exact row that matched (e.g. "evil.com" for a lookup on "login.evil.com")
  source: string;
}

/** Registrable-ish parent-label chain: login.evil.com -> [login.evil.com, evil.com].
 *  Deliberately stops one level short of a bare TLD (needs >=2 labels to match),
 *  so we never accidentally match on "com" itself. No public-suffix-list dependency
 *  in v1 (SPEC §20) — a rare over-broad match (e.g. a two-label "co.uk"-style TLD)
 *  is a missed edge case, not a false-safe. */
function parentChain(hostname: string): string[] {
  const labels = hostname.toLowerCase().split(".");
  const chain: string[] = [];
  for (let i = 0; i < labels.length - 1; i++) {
    chain.push(labels.slice(i).join("."));
  }
  return chain;
}

/** Domain lookup, walking from the full host up through parent domains. Returns
 *  the FIRST (most specific) match, or null if nothing in the chain is listed. */
export async function lookupDomain(db: MinimalD1, hostname: string): Promise<FeedHit | null> {
  const chain = parentChain(hostname);
  if (chain.length === 0) return null;

  const placeholders = chain.map(() => "?").join(",");
  const { results } = await db
    .prepare(`SELECT domain, source FROM feed_domains WHERE domain IN (${placeholders})`)
    .bind(...chain)
    .all<{ domain: string; source: string }>();

  if (results.length === 0) return null;

  // Prefer the most specific (longest / earliest-in-chain) match.
  for (const candidate of chain) {
    const hit = results.find((r) => r.domain === candidate);
    if (hit) return { matchedValue: hit.domain, source: hit.source };
  }
  return null;
}

export async function lookupIp(db: MinimalD1, ip: string): Promise<FeedHit | null> {
  const { results } = await db
    .prepare("SELECT ip, source FROM feed_ips WHERE ip = ?")
    .bind(ip)
    .all<{ ip: string; source: string }>();
  const hit = results[0];
  return hit ? { matchedValue: hit.ip, source: hit.source } : null;
}

/** URLhaus precision split (SPEC §6/§8): exact-URL match is the high-confidence
 *  signal (DANGEROUS-worthy); a bare domain hit is handled separately by
 *  lookupDomain and scored as SUSPICIOUS (compromised-legit-host nuance). */
export async function lookupExactUrl(db: MinimalD1, url: string): Promise<FeedHit | null> {
  const { results } = await db
    .prepare("SELECT url, source FROM feed_urls_exact WHERE url = ?")
    .bind(url)
    .all<{ url: string; source: string }>();
  const hit = results[0];
  return hit ? { matchedValue: hit.url, source: hit.source } : null;
}

/** Abused-TLD check: matches the resolved hostname's final label against
 *  HaGeZi's Most-Abused-TLDs list. Suffix match, not the parent-label domain
 *  walk — a TLD list has no "subdomain evasion" concern of its own. */
export async function lookupTld(db: MinimalD1, hostname: string): Promise<FeedHit | null> {
  const labels = hostname.toLowerCase().split(".");
  const tld = labels[labels.length - 1];
  if (!tld) return null;
  const { results } = await db
    .prepare("SELECT tld, source FROM feed_tlds WHERE tld = ?")
    .bind(tld)
    .all<{ tld: string; source: string }>();
  const hit = results[0];
  return hit ? { matchedValue: hit.tld, source: hit.source } : null;
}

// --- Large feeds (SPEC §6/§18/§20 KV-blob pivot) ---
// TIF domains (166K), TIF-IPs (62K), and Entropy-NRD/DGA (582K) don't fit D1's
// row-write budget as one-row-per-entry tables. Each is stored as ONE KV value
// (newline-joined) — a single PUT per refresh regardless of list size — and
// parsed into an in-memory Set once per isolate, cached at module scope so a
// 582K-entry blob isn't re-parsed on every request within a warm isolate.

export interface MinimalKV {
  get(key: string): Promise<string | null>;
}

/** Write-capable KV slice — used by refresh.ts, not the read-only lookups. */
export interface WritableKV extends MinimalKV {
  put(key: string, value: string): Promise<void>;
}

// TTL, not "forever" — a cron refresh writes new KV data from a DIFFERENT
// Worker isolate than the ones serving live requests (Workers run many
// parallel isolates across the edge; there's no cross-isolate cache-clear
// signal available to application code). Without a TTL, a refreshed blob
// could stay invisible to a given isolate indefinitely. 15 min bounds the
// worst-case staleness to well under the daily refresh cadence itself.
const BLOB_CACHE_TTL_MS = 15 * 60 * 1000;
const blobSetCache = new Map<string, { set: Set<string>; loadedAt: number }>();

async function loadBlobSet(kv: MinimalKV, key: string): Promise<Set<string>> {
  const cached = blobSetCache.get(key);
  if (cached && Date.now() - cached.loadedAt < BLOB_CACHE_TTL_MS) return cached.set;

  const raw = await kv.get(key);
  const set = new Set(raw ? raw.split("\n").filter(Boolean) : []);
  blobSetCache.set(key, { set, loadedAt: Date.now() });
  return set;
}

/** Clears the module-scope blob cache — for tests only, so fixtures in one test
 *  don't leak into the next via a shared Set keyed by the same blob name. */
export function _resetBlobCacheForTests(): void {
  blobSetCache.clear();
}

export async function lookupInBlob(kv: MinimalKV, blobKey: string, value: string, source: string): Promise<FeedHit | null> {
  const set = await loadBlobSet(kv, blobKey);
  return set.has(value) ? { matchedValue: value, source } : null;
}

/** TIF domains use the same parent-label walk as lookupDomain (evasion-proof),
 *  but against the in-memory blob Set instead of a D1 query. */
export async function lookupDomainInBlob(kv: MinimalKV, blobKey: string, hostname: string, source: string): Promise<FeedHit | null> {
  const set = await loadBlobSet(kv, blobKey);
  for (const candidate of parentChain(hostname)) {
    if (set.has(candidate)) return { matchedValue: candidate, source };
  }
  return null;
}
