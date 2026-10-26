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
 *  is a missed edge case, not a false-safe.
 *  Capped to the MAX_CHAIN shortest suffixes: lookupDomain binds one SQL param
 *  per entry and D1 allows 100 per query, so an attacker hostname with 110+
 *  labels made the lookup throw. Feed entries are registrable domains or a few
 *  labels deeper; the shortest suffixes are the ones that match. */
const MAX_CHAIN = 10;

function parentChain(hostname: string): string[] {
  const labels = hostname.toLowerCase().split(".");
  const chain: string[] = [];
  for (let i = Math.max(0, labels.length - 1 - MAX_CHAIN); i < labels.length - 1; i++) {
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
// TIF domains (166K), TIF-IPs (62K), Entropy-NRD/DGA (582K) and URLhaus exact
// URLs (60K+; exact-match only, SPEC §6/§8 precision split) don't fit D1's
// row-write budget as one-row-per-entry tables. Each is stored as ONE KV value
// (newline-joined) — a single PUT per refresh regardless of list size.
// Blobs are written SORTED behind a header line and looked up by binary search
// over the raw string, with no parse. Building a Set from them cost ~650 ms CPU
// per cold isolate against Free's 10 ms, so ~1 in 10 requests died with
// Cloudflare error 1102 (2026-10-24). The raw string is cached at module scope.

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
// Caches the in-flight PROMISE, not the finished Set: concurrent lookups on a
// cold isolate (check_text/check_skill check several URLs in parallel) must
// share one KV read + parse. Caching only the result let every caller miss and
// parse a 100K–580K-line blob itself — 5 URLs × 3 blobs blew the Worker CPU
// limit in production (exceededCpu, 2026-09-27). A failed load is evicted so
// the next lookup retries instead of replaying the error for 15 minutes.
/** First line of every blob refresh.ts writes. Every blob has carried it since
 *  2026-10-24, so a blob without it is not ours to binary-search (an unsorted
 *  body would miss entries — a false-safe) and is rejected as unusable. */
export const SORTED_BLOB_HEADER = "#sorted-v1";
/** Header plus its newline: where a blob's entries start. */
const HEADER_LINE_LEN = SORTED_BLOB_HEADER.length + 1;

/** Same rules as toBlobIndex, on just the blob's first bytes: null if usable,
 *  else the reason. Shared with /health, which must not read whole blobs. */
function blobProblem(head: string | null): string | null {
  if (head === null) return "missing";
  if (!head.startsWith(`${SORTED_BLOB_HEADER}\n`)) return "unparseable (no sorted header)";
  if (head.length === HEADER_LINE_LEN) return "empty";
  return null;
}

/** The on-KV format: header, then entries in ascending code-unit order, unique.
 *  Feeds that arrive sorted (HaGeZi NRD, 765K lines) skip the sort. */
export function toSortedBlob(lines: string[]): string {
  let sorted = true;
  for (let i = 1; i < lines.length; i++) {
    if (!(lines[i - 1] < lines[i])) {
      sorted = false;
      break;
    }
  }
  const body = sorted ? lines : [...new Set(lines)].sort();
  return `${SORTED_BLOB_HEADER}\n${body.join("\n")}`;
}

interface BlobIndex {
  has(value: string): boolean;
}

/** Binary search over the raw sorted blob: O(log n) slices, no split. */
function sortedBlobIndex(raw: string): BlobIndex {
  return {
    has(value: string): boolean {
      let lo = HEADER_LINE_LEN;
      let hi = raw.length;
      while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        const start = raw.lastIndexOf("\n", mid - 1) + 1;
        let end = raw.indexOf("\n", start);
        if (end === -1) end = raw.length;
        const line = raw.slice(start, end);
        if (line === value) return true;
        if (line < value) lo = end + 1;
        else hi = start;
      }
      return false;
    },
  };
}

function toBlobIndex(raw: string | null): BlobIndex {
  // A missing or empty blob used to read as an empty Set — "not listed" — so a
  // lost feed silently turned matches into SAFE. Throw; callers degrade.
  const problem = blobProblem(raw);
  if (problem) throw new Error(problem);
  return sortedBlobIndex(raw!);
}

const blobSetCache = new Map<string, { set: Promise<BlobIndex>; loadedAt: number }>();

function loadBlobSet(kv: MinimalKV, key: string): Promise<BlobIndex> {
  const cached = blobSetCache.get(key);
  if (cached && Date.now() - cached.loadedAt < BLOB_CACHE_TTL_MS) return cached.set;

  const set = kv.get(key).then(toBlobIndex);
  const entry = { set, loadedAt: Date.now() };
  blobSetCache.set(key, entry);
  set.catch(() => {
    if (blobSetCache.get(key) === entry) blobSetCache.delete(key);
  });
  return set;
}

/** Clears the module-scope blob cache — for tests only, so fixtures in one test
 *  don't leak into the next via a shared Set keyed by the same blob name. */
export function _resetBlobCacheForTests(): void {
  blobSetCache.clear();
}

/** First of `values` found in the blob, in order — one blob load for all of them. */
export async function lookupFirstInBlob(kv: MinimalKV, blobKey: string, values: string[], source: string): Promise<FeedHit | null> {
  const set = await loadBlobSet(kv, blobKey);
  const hit = values.find((v) => set.has(v));
  return hit === undefined ? null : { matchedValue: hit, source };
}

export const lookupInBlob = (kv: MinimalKV, blobKey: string, value: string, source: string) =>
  lookupFirstInBlob(kv, blobKey, [value], source);

/** TIF domains use the same parent-label walk as lookupDomain (evasion-proof),
 *  but against the KV blob instead of a D1 query. */
export const lookupDomainInBlob = (kv: MinimalKV, blobKey: string, hostname: string, source: string) =>
  lookupFirstInBlob(kv, blobKey, parentChain(hostname), source);

/** KV slice that can stream a value — real Workers KV does. Lets /health check a
 *  blob from its first chunk instead of reading 17 MB (NRD) on every ping. */
export interface StreamKV {
  get(key: string, options: { type: "stream" }): Promise<ReadableStream<Uint8Array> | null>;
}

/** "ok" or why the blob is unusable, from its first bytes only. */
export async function probeBlob(kv: StreamKV, key: string): Promise<string> {
  try {
    const stream = await kv.get(key, { type: "stream" });
    if (!stream) return "missing";
    const reader = stream.getReader();
    const decoder = new TextDecoder();
    let head = "";
    // Chunks can split anywhere; stop once one byte past the header line is in.
    while (head.length <= HEADER_LINE_LEN) {
      const { value, done } = await reader.read();
      if (done) break;
      head += decoder.decode(value, { stream: true });
    }
    await reader.cancel();
    return blobProblem(head) ?? "ok";
  } catch (e) {
    return `error: ${(e as Error).message}`;
  }
}
