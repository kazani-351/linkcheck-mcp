import { test } from "node:test";
import assert from "node:assert/strict";
import { refreshAllFeeds, FEED_SOURCES, type FetchFn } from "./refresh.ts";
import type { WritableD1, WritableKV } from "./feeds.ts";

// In-memory fake that understands the exact SQL shapes refresh.ts issues —
// real diff/write semantics, not a generic SQL engine (mirrors the fakeDb
// pattern already used in feeds.test.ts).
function fakeD1(seed: { feed_domains?: Row[]; feed_urls_exact?: Row[]; feed_tlds?: Row[]; feed_meta?: Row[] } = {}): WritableD1 & {
  tables: Record<string, Row[]>;
} {
  const tables: Record<string, Row[]> = {
    feed_domains: seed.feed_domains ?? [],
    feed_urls_exact: seed.feed_urls_exact ?? [],
    feed_tlds: seed.feed_tlds ?? [],
    feed_meta: seed.feed_meta ?? [],
  };

  // D1's real, hard limit — enforced here too so a regression to an oversized
  // CHUNK is caught by the test suite itself, not just discovered live in
  // production (which is exactly how this bug was originally found).
  const D1_MAX_BOUND_PARAMS = 100;

  return {
    tables,
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          if (values.length > D1_MAX_BOUND_PARAMS) {
            throw new Error(`D1_ERROR: too many SQL variables (${values.length} > ${D1_MAX_BOUND_PARAMS}): SQLITE_ERROR`);
          }
          return {
            async all<T>() {
              const sel = sql.match(/SELECT (\w+) AS v FROM (\w+) WHERE source = \?/);
              if (sel) {
                const [, col, table] = sel;
                const source = values[0];
                return { results: tables[table].filter((r) => r.source === source).map((r) => ({ v: r[col] })) as T[] };
              }
              return { results: [] as T[] };
            },
            async run() {
              const ins = sql.match(/INSERT OR IGNORE INTO (\w+) \((\w+), source\) VALUES/);
              if (ins) {
                const [, table, col] = ins;
                for (let i = 0; i < values.length; i += 2) {
                  const v = values[i], source = values[i + 1];
                  if (!tables[table].some((r) => r[col] === v && r.source === source)) {
                    tables[table].push({ [col]: v, source } as Row);
                  }
                }
                return { success: true };
              }
              const del = sql.match(/DELETE FROM (\w+) WHERE source = \? AND (\w+) IN/);
              if (del) {
                const [, table, col] = del;
                const source = values[0];
                const toDelete = new Set(values.slice(1));
                tables[table] = tables[table].filter((r) => !(r.source === source && toDelete.has(r[col])));
                return { success: true };
              }
              if (sql.includes("INSERT OR REPLACE INTO feed_meta")) {
                const [source, lastRefresh, ...rest] = values as [string, number, ...unknown[]];
                const lastStatus = sql.includes("COALESCE") ? (rest[0] as string) : (rest[0] as string);
                const entryCount = sql.includes("COALESCE")
                  ? tables.feed_meta.find((r) => r.source === source)?.entry_count ?? 0
                  : rest[1];
                tables.feed_meta = tables.feed_meta.filter((r) => r.source !== source);
                tables.feed_meta.push({ source, last_refresh: lastRefresh, last_status: lastStatus, entry_count: entryCount } as Row);
                return { success: true };
              }
              return { success: true };
            },
          };
        },
      };
    },
  };
}

type Row = Record<string, unknown>;

function fakeKv(): WritableKV & { store: Map<string, string> } {
  const store = new Map<string, string>();
  return {
    store,
    async get(key: string) {
      return store.get(key) ?? null;
    },
    async put(key: string, value: string) {
      store.set(key, value);
    },
  };
}

// Matches a fetched URL back to its source. Keyed sources (URLhaus) carry a
// "{secret}" placeholder, so match on the part before it.
function srcFor(url: string) {
  return FEED_SOURCES.find((s) => url.startsWith(s.url.split("{secret}")[0]))!;
}

// "+" and "/" change under encodeURIComponent, so both scrub forms get exercised.
const SECRETS = { URLHAUS_AUTH_KEY: "test+key/123" };

// Canned text per source URL — order-independent, keyed by source name via FEED_SOURCES.
function fetchTextFor(overrides: Record<string, string> = {}): FetchFn {
  return async (url: string) => {
    const src = srcFor(url);
    if (overrides[src.name] !== undefined) return overrides[src.name];
    return "# comment\nexample-a.com\nexample-b.com\n";
  };
}

test("D1 feed: diffs current rows against fresh fetch, applies only the delta", async () => {
  const db = fakeD1({
    feed_domains: [
      { domain: "stays.com", source: "HaGeZi-Shortener" },
      { domain: "gone.com", source: "HaGeZi-Shortener" },
    ],
  });
  const kv = fakeKv();
  const fetchText = fetchTextFor({
    "HaGeZi-Shortener": "stays.com\nnew.com\n", // gone.com dropped, new.com added
  });

  const results = await refreshAllFeeds(db, kv, 1000, fetchText, SECRETS);
  const outcome = results.find((r) => r.source === "HaGeZi-Shortener")!;

  assert.equal(outcome.status, "ok");
  assert.equal(outcome.added, 1);
  assert.equal(outcome.removed, 1);
  assert.equal(outcome.entryCount, 2);

  const finalDomains = db.tables.feed_domains.filter((r) => r.source === "HaGeZi-Shortener").map((r) => r.domain);
  assert.deepEqual(finalDomains.sort(), ["new.com", "stays.com"]);
});

test("D1 feed: a diff larger than one chunk applies correctly across multiple statements (real prod bug, SPEC §20 bug #19 — D1's 100-bound-param limit)", async () => {
  // 90 rows added + 90 removed forces at least 3 chunked INSERT/DELETE
  // statements at CHUNK=40. The original CHUNK=400 (800 params for INSERT)
  // silently exceeded D1's real 100-bound-parameter limit — but only feeds
  // with actual diff churn ever hit it, so a tiny 1-2-row test diff never
  // caught it. This test exists specifically to keep that class of bug caught.
  const staying = Array.from({ length: 10 }, (_, i) => ({ domain: `stays-${i}.com`, source: "HaGeZi-Shortener" }));
  const going = Array.from({ length: 90 }, (_, i) => ({ domain: `gone-${i}.com`, source: "HaGeZi-Shortener" }));
  const db = fakeD1({ feed_domains: [...staying, ...going] });
  const kv = fakeKv();
  const freshLines = [
    ...staying.map((r) => r.domain),
    ...Array.from({ length: 90 }, (_, i) => `new-${i}.com`),
  ].join("\n");
  const fetchText = fetchTextFor({ "HaGeZi-Shortener": freshLines });

  const results = await refreshAllFeeds(db, kv, 1000, fetchText, SECRETS);
  const outcome = results.find((r) => r.source === "HaGeZi-Shortener")!;

  assert.equal(outcome.status, "ok", `expected success, got: ${outcome.error}`);
  assert.equal(outcome.added, 90);
  assert.equal(outcome.removed, 90);

  const finalDomains = new Set(db.tables.feed_domains.filter((r) => r.source === "HaGeZi-Shortener").map((r) => r.domain));
  assert.equal(finalDomains.size, 100); // 10 staying + 90 new
  assert.ok(staying.every((r) => finalDomains.has(r.domain)));
  assert.ok(going.every((r) => !finalDomains.has(r.domain)));
});

test("D1 feed: no-op diff when nothing changed (zero writes needed)", async () => {
  const db = fakeD1({ feed_tlds: [{ tld: "actor", source: "HaGeZi-AbusedTLD" }] });
  const kv = fakeKv();
  const fetchText = fetchTextFor({ "HaGeZi-AbusedTLD": "actor\n" });

  const results = await refreshAllFeeds(db, kv, 1000, fetchText, SECRETS);
  const outcome = results.find((r) => r.source === "HaGeZi-AbusedTLD")!;
  assert.equal(outcome.added, 0);
  assert.equal(outcome.removed, 0);
});

test("KV feed: full-blob overwrite, no diff logic", async () => {
  const db = fakeD1();
  const kv = fakeKv();
  const fetchText = fetchTextFor({ "HaGeZi-TIF-domains": "evil-c.com\nevil-a.com\nevil-b.com\n" });

  const results = await refreshAllFeeds(db, kv, 1000, fetchText, SECRETS);
  const outcome = results.find((r) => r.source === "HaGeZi-TIF-domains")!;

  assert.equal(outcome.status, "ok");
  assert.equal(outcome.entryCount, 3);
  // Written sorted with the header, so lookups binary-search it instead of parsing it (1102 fix).
  assert.equal(kv.store.get("feed:tif-domains"), "#sorted-v1\nevil-a.com\nevil-b.com\nevil-c.com");
});

test("one failing source does not block the other five (Promise.allSettled isolation)", async () => {
  const db = fakeD1();
  const kv = fakeKv();
  const fetchText: FetchFn = async (url) => {
    const src = srcFor(url);
    if (src.name === "URLhaus") throw new Error("upstream is down");
    return "example.com\n";
  };

  const results = await refreshAllFeeds(db, kv, 1000, fetchText, SECRETS);
  assert.equal(results.length, FEED_SOURCES.length);

  const failed = results.find((r) => r.source === "URLhaus")!;
  assert.equal(failed.status, "error");
  assert.match(failed.error!, /upstream is down/);

  const others = results.filter((r) => r.source !== "URLhaus");
  assert.ok(others.every((r) => r.status === "ok"), "every other source should still succeed");
});

test("a failed source writes an error status to feed_meta, not silently skipped", async () => {
  const db = fakeD1({ feed_meta: [{ source: "URLhaus", last_refresh: 1, last_status: "ok", entry_count: 99 }] });
  const kv = fakeKv();
  const fetchText: FetchFn = async (url) => {
    const src = srcFor(url);
    if (src.name === "URLhaus") throw new Error("timeout");
    return "example.com\n";
  };

  await refreshAllFeeds(db, kv, 2000, fetchText, SECRETS);
  const meta = db.tables.feed_meta.find((r) => r.source === "URLhaus")!;
  assert.match(meta.last_status as string, /error: timeout/);
  assert.equal(meta.last_refresh, 2000);
  // entry_count preserved from before (COALESCE), not zeroed out on a transient failure
  assert.equal(meta.entry_count, 99);
});

test("refreshes all 6 declared feeds, none silently dropped", async () => {
  const db = fakeD1();
  const kv = fakeKv();
  const results = await refreshAllFeeds(db, kv, 1000, fetchTextFor(), SECRETS);
  assert.equal(results.length, 6);
  assert.deepEqual(
    results.map((r) => r.source).sort(),
    ["HaGeZi-AbusedTLD", "HaGeZi-Entropy-NRD-7d", "HaGeZi-Shortener", "HaGeZi-TIF-domains", "HaGeZi-TIF-ips", "URLhaus"],
  );
});

// --- URLhaus via abuse.ch Auth-Key (2026-10-24: /downloads/ returns 410 Gone) ---

const URLHAUS_CSV = [
  "################################################################",
  "# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #",
  "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter",
  '"1","2026-10-24 10:00:00","http://bad.example/a.exe","online","2026-10-24 10:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/1/","r"',
  '"2","2026-10-24 10:00:00","http://gone.example/b","offline","","malware_download","","https://urlhaus.abuse.ch/url/2/","r"',
  '"3","2026-10-24 10:00:00","http://bad.example/x?a=1,b=""q""","online","","malware_download","","https://urlhaus.abuse.ch/url/3/","r"',
  "",
].join("\n");

test("URLhaus: fetches the keyed export and stores only ONLINE urls (quoted commas and quotes intact)", async () => {
  const db = fakeD1();
  const kv = fakeKv();
  const seen: string[] = [];
  const fetchText: FetchFn = async (url) => {
    seen.push(url);
    return srcFor(url).name === "URLhaus" ? URLHAUS_CSV : "example.com\n";
  };
  const results = await refreshAllFeeds(db, kv, 1000, fetchText, SECRETS);
  const outcome = results.find((r) => r.source === "URLhaus")!;
  assert.equal(outcome.status, "ok");
  assert.equal(outcome.entryCount, 2);
  assert.ok(seen.includes("https://urlhaus-api.abuse.ch/v2/files/exports/test%2Bkey%2F123/recent.csv"));
  const urls = db.tables.feed_urls_exact.filter((r) => r.source === "URLhaus").map((r) => r.url);
  assert.deepEqual(urls.sort(), ["http://bad.example/a.exe", 'http://bad.example/x?a=1,b="q"']);
});

test("URLhaus: missing URLHAUS_AUTH_KEY is a loud error, no fetch, other feeds unaffected", async () => {
  const db = fakeD1();
  const kv = fakeKv();
  const seen: string[] = [];
  const fetchText: FetchFn = async (url) => {
    seen.push(url);
    return "example.com\n";
  };
  const results = await refreshAllFeeds(db, kv, 1000, fetchText, {});
  const outcome = results.find((r) => r.source === "URLhaus")!;
  assert.equal(outcome.status, "error");
  assert.match(outcome.error!, /URLHAUS_AUTH_KEY/);
  assert.ok(!seen.some((u) => u.includes("urlhaus")), "must not fetch without the key");
  assert.ok(results.filter((r) => r.source !== "URLhaus").every((r) => r.status === "ok"));
});

test("URLhaus: the key never reaches feed_meta or the returned error (public via /health)", async () => {
  const db = fakeD1();
  const kv = fakeKv();
  const fetchText: FetchFn = async (url) => {
    if (srcFor(url).name === "URLhaus") throw new Error(`fetch ${url} -> HTTP 401`);
    return "example.com\n";
  };
  const results = await refreshAllFeeds(db, kv, 1000, fetchText, SECRETS);
  const outcome = results.find((r) => r.source === "URLhaus")!;
  const meta = db.tables.feed_meta.find((r) => r.source === "URLhaus")!;
  for (const text of [outcome.error!, meta.last_status as string]) {
    assert.ok(!text.includes("test+key/123") && !text.includes("test%2Bkey%2F123"), `key leaked: ${text}`);
    assert.match(text, /\[redacted\]/);
  }
});

test("URLhaus: a 200 that isn't the export, or has no online rows, is an error and keeps existing rows", async () => {
  for (const body of ['{"query_status":"unknown_auth_key"}', URLHAUS_CSV.replace(/"online"/g, '"offline"')]) {
    const db = fakeD1({ feed_urls_exact: [{ url: "http://kept.example/", source: "URLhaus" }] });
    const kv = fakeKv();
    const fetchText: FetchFn = async (url) => (srcFor(url).name === "URLhaus" ? body : "example.com\n");
    const results = await refreshAllFeeds(db, kv, 1000, fetchText, SECRETS);
    const outcome = results.find((r) => r.source === "URLhaus")!;
    assert.equal(outcome.status, "error");
    assert.deepEqual(db.tables.feed_urls_exact.map((r) => r.url), ["http://kept.example/"], "existing rows must not be wiped");
  }
});
