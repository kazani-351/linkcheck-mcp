// Cron feed refresh (SPEC §6, §9, §18). Two shapes, matching the storage tier
// each feed lives in:
//   - D1 (small feeds): diff against current rows, apply only the delta
//     (INSERT the added, DELETE the removed) — a full replace would blow the
//     ~100k-writes/day free-tier ceiling on repeated runs even though each
//     individual feed is small.
//   - KV (large feeds): one full-blob overwrite per refresh — a single PUT is
//     cheap regardless of list size, and diffing 166K-582K entries in a Worker
//     just to save one KV write isn't worth the complexity (SPEC §6).
import { toSortedBlob, type WritableD1, type WritableKV } from "./feeds.ts";

const FETCH_TIMEOUT_MS = 30_000;
// D1's real limit is 100 bound parameters per query (verified against docs AND
// hit live in production — a prior guess of 400 rows/statement, based on
// vanilla SQLite's much higher 999-variable default, failed for real on
// URLhaus with "too many SQL variables"). INSERT uses 2 params/row (value +
// source); DELETE uses 1/row + 1 for the source clause. 40 rows keeps both
// comfortably under 100 (80 and 41 respectively) with headroom.
const CHUNK = 40;

export interface FeedSource {
  name: string; // matches feed_meta.source
  url: string;
  kind: "d1" | "kv";
  table?: "feed_domains" | "feed_urls_exact" | "feed_tlds"; // d1 only
  column?: "domain" | "url" | "tld"; // d1 only
  kvKey?: string; // kv only
}

export const FEED_SOURCES: FeedSource[] = [
  { name: "URLhaus", url: "https://urlhaus.abuse.ch/downloads/text_online/", kind: "d1", table: "feed_urls_exact", column: "url" },
  {
    name: "HaGeZi-Shortener",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/urlshortener-onlydomains.txt",
    kind: "d1",
    table: "feed_domains",
    column: "domain",
  },
  {
    name: "HaGeZi-AbusedTLD",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/spam-tlds-onlydomains.txt",
    kind: "d1",
    table: "feed_tlds",
    column: "tld",
  },
  {
    name: "HaGeZi-TIF-domains",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
    kind: "kv",
    kvKey: "feed:tif-domains",
  },
  {
    name: "HaGeZi-TIF-ips",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt",
    kind: "kv",
    kvKey: "feed:tif-ips",
  },
  {
    name: "HaGeZi-Entropy-NRD-7d",
    url: "https://raw.githubusercontent.com/hagezi/nrd/main/domains/dga7.txt",
    kind: "kv",
    kvKey: "feed:entropy-nrd",
  },
];

export interface FetchFn {
  (url: string): Promise<string>;
}

/** Default fetcher: real network, strips comment/blank lines. Injectable so
 *  diff/write logic below can be unit-tested without hitting the internet. */
export const defaultFetchFeedText: FetchFn = async (url: string): Promise<string> => {
  const res = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`fetch ${url} -> HTTP ${res.status}`);
  return res.text();
};

function parseLines(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
}

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

export interface RefreshOutcome {
  source: string;
  status: "ok" | "error";
  entryCount: number;
  added?: number;
  removed?: number;
  error?: string;
}

/** Diff a D1 feed's current rows against a fresh fetch, apply only the delta. */
async function refreshD1Feed(db: WritableD1, src: FeedSource, freshLines: string[], now: number): Promise<RefreshOutcome> {
  const table = src.table!;
  const column = src.column!;
  const fresh = new Set(freshLines);

  const { results } = await db.prepare(`SELECT ${column} AS v FROM ${table} WHERE source = ?`).bind(src.name).all<{ v: string }>();
  const current = new Set(results.map((r) => r.v));

  const added = [...fresh].filter((v) => !current.has(v));
  const removed = [...current].filter((v) => !fresh.has(v));

  for (const batch of chunk(added, CHUNK)) {
    const placeholders = batch.map(() => "(?, ?)").join(",");
    const values = batch.flatMap((v) => [v, src.name]);
    await db.prepare(`INSERT OR IGNORE INTO ${table} (${column}, source) VALUES ${placeholders}`).bind(...values).run();
  }
  for (const batch of chunk(removed, CHUNK)) {
    const placeholders = batch.map(() => "?").join(",");
    await db
      .prepare(`DELETE FROM ${table} WHERE source = ? AND ${column} IN (${placeholders})`)
      .bind(src.name, ...batch)
      .run();
  }

  await db
    .prepare("INSERT OR REPLACE INTO feed_meta (source, last_refresh, last_status, entry_count) VALUES (?, ?, 'ok', ?)")
    .bind(src.name, now, fresh.size)
    .run();

  return { source: src.name, status: "ok", entryCount: fresh.size, added: added.length, removed: removed.length };
}

/** Large feeds: one full-blob overwrite, no diff (SPEC §6). */
async function refreshKvFeed(db: WritableD1, kv: WritableKV, src: FeedSource, freshLines: string[], now: number): Promise<RefreshOutcome> {
  await kv.put(src.kvKey!, toSortedBlob(freshLines));
  await db
    .prepare("INSERT OR REPLACE INTO feed_meta (source, last_refresh, last_status, entry_count) VALUES (?, ?, 'ok', ?)")
    .bind(src.name, now, freshLines.length)
    .run();
  return { source: src.name, status: "ok", entryCount: freshLines.length };
}

/** Refreshes all feeds. Each source is isolated (Promise.allSettled) — one
 *  dead upstream must not block the other five, and feed_meta is updated with
 *  an "error" status (not silently skipped) so staleness is visible at /health,
 *  never silently masked as still-fresh (SPEC's fail-loud pattern, §10). */
export async function refreshAllFeeds(db: WritableD1, kv: WritableKV, now: number, fetchText: FetchFn = defaultFetchFeedText): Promise<RefreshOutcome[]> {
  const results = await Promise.allSettled(
    FEED_SOURCES.map(async (src): Promise<RefreshOutcome> => {
      const text = await fetchText(src.url);
      const lines = parseLines(text);
      return src.kind === "d1" ? refreshD1Feed(db, src, lines, now) : refreshKvFeed(db, kv, src, lines, now);
    }),
  );

  return Promise.all(
    results.map(async (r, i) => {
      if (r.status === "fulfilled") return r.value;
      const src = FEED_SOURCES[i];
      const message = r.reason instanceof Error ? r.reason.message : String(r.reason);
      // Record the failure in feed_meta too — a source that's been failing for
      // days should be visible at /health, not indistinguishable from "fresh".
      try {
        await db
          .prepare("INSERT OR REPLACE INTO feed_meta (source, last_refresh, last_status, entry_count) VALUES (?, ?, ?, COALESCE((SELECT entry_count FROM feed_meta WHERE source = ?), 0))")
          .bind(src.name, now, `error: ${message}`, src.name)
          .run();
      } catch {
        /* feed_meta write itself failed — the allSettled result below still surfaces the original error */
      }
      return { source: src.name, status: "error" as const, entryCount: 0, error: message };
    }),
  );
}
