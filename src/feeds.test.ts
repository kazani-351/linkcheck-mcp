import { test } from "node:test";
import assert from "node:assert/strict";
import {
  lookupDomain,
  lookupIp,
  lookupTld,
  lookupInBlob,
  lookupDomainInBlob,
  _resetBlobCacheForTests,
  toSortedBlob,
  SORTED_BLOB_HEADER,
  type MinimalD1,
  type MinimalKV,
} from "./feeds.ts";

// Minimal in-memory fake matching the exact query shapes feeds.ts issues —
// faithful enough to exercise real matching logic without a live D1 binding
// (D1 itself is only reachable from the Workers runtime; see CLAUDE.md).
function fakeDb(
  domains: Array<{ domain: string; source: string }>,
  ips: Array<{ ip: string; source: string }> = [],
): MinimalD1 {
  return {
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          return {
            async all<T>() {
              if (sql.includes("feed_domains")) {
                const set = new Set(values as string[]);
                return { results: domains.filter((d) => set.has(d.domain)) as T[] };
              }
              if (sql.includes("feed_ips")) {
                return { results: ips.filter((i) => i.ip === values[0]) as T[] };
              }
              return { results: [] as T[] };
            },
          };
        },
      };
    },
  };
}

test("lookupDomain: exact match on the full host", async () => {
  const db = fakeDb([{ domain: "evil.com", source: "TIF" }]);
  const hit = await lookupDomain(db, "evil.com");
  assert.deepEqual(hit, { matchedValue: "evil.com", source: "TIF" });
});

test("lookupDomain: subdomain evasion prevented via parent-label walk", async () => {
  const db = fakeDb([{ domain: "evil.com", source: "TIF" }]);
  const hit = await lookupDomain(db, "login.attacker.evil.com");
  assert.deepEqual(hit, { matchedValue: "evil.com", source: "TIF" });
});

test("lookupDomain: prefers the most specific match when both levels are listed", async () => {
  const db = fakeDb([
    { domain: "evil.com", source: "TIF" },
    { domain: "sub.evil.com", source: "URLhaus" },
  ]);
  const hit = await lookupDomain(db, "sub.evil.com");
  assert.equal(hit?.matchedValue, "sub.evil.com");
});

test("lookupDomain: no match returns null", async () => {
  const db = fakeDb([{ domain: "evil.com", source: "TIF" }]);
  assert.equal(await lookupDomain(db, "anthropic.com"), null);
});

test("lookupDomain: never matches a bare TLD", async () => {
  // Even if "com" were somehow a row (it shouldn't be), a single-label host has
  // no parent chain to walk — this documents the 2-label floor from SPEC §6.
  const db = fakeDb([{ domain: "com", source: "junk" }]);
  assert.equal(await lookupDomain(db, "com"), null);
});

test("lookupIp: exact match only", async () => {
  const db = fakeDb([], [{ ip: "203.0.113.5", source: "TIF-IPs" }]);
  assert.deepEqual(await lookupIp(db, "203.0.113.5"), { matchedValue: "203.0.113.5", source: "TIF-IPs" });
  assert.equal(await lookupIp(db, "203.0.113.6"), null);
});

// --- lookupTld ---

function fakeDbTlds(tlds: Array<{ tld: string; source: string }>): MinimalD1 {
  return {
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          return {
            async all<T>() {
              if (sql.includes("feed_tlds")) {
                return { results: tlds.filter((t) => t.tld === values[0]) as T[] };
              }
              return { results: [] as T[] };
            },
          };
        },
      };
    },
  };
}

test("lookupTld: matches the hostname's final label", async () => {
  const db = fakeDbTlds([{ tld: "top", source: "HaGeZi-AbusedTLD" }]);
  assert.deepEqual(await lookupTld(db, "totally-legit-bank.top"), { matchedValue: "top", source: "HaGeZi-AbusedTLD" });
  assert.equal(await lookupTld(db, "anthropic.com"), null);
});

// --- KV-blob lookups (TIF domains/IPs, Entropy-NRD) ---

function fakeKv(store: Record<string, string>): MinimalKV & { getCalls: number } {
  const obj = {
    getCalls: 0,
    async get(key: string) {
      obj.getCalls++;
      return store[key] ?? null;
    },
  };
  return obj;
}

test("lookupInBlob: exact membership (TIF-IPs shape)", async () => {
  _resetBlobCacheForTests();
  const kv = fakeKv({ "feed:tif-ips": "203.0.113.5\n198.51.100.9" });
  assert.deepEqual(await lookupInBlob(kv, "feed:tif-ips", "203.0.113.5", "HaGeZi-TIF-ips"), {
    matchedValue: "203.0.113.5",
    source: "HaGeZi-TIF-ips",
  });
  assert.equal(await lookupInBlob(kv, "feed:tif-ips", "203.0.113.6", "HaGeZi-TIF-ips"), null);
});

test("lookupDomainInBlob: parent-label walk against blob-backed data (subdomain evasion prevented)", async () => {
  _resetBlobCacheForTests();
  const kv = fakeKv({ "feed:tif-domains": "evil.com\nother-bad.net" });
  const hit = await lookupDomainInBlob(kv, "feed:tif-domains", "login.attacker.evil.com", "HaGeZi-TIF-domains");
  assert.deepEqual(hit, { matchedValue: "evil.com", source: "HaGeZi-TIF-domains" });
  assert.equal(await lookupDomainInBlob(kv, "feed:tif-domains", "anthropic.com", "HaGeZi-TIF-domains"), null);
});

test("toSortedBlob: sorts, dedupes and prefixes the header; passes already-sorted input through", () => {
  assert.equal(toSortedBlob(["b.com", "a.com", "b.com"]), `${SORTED_BLOB_HEADER}\na.com\nb.com`);
  assert.equal(toSortedBlob(["a.com", "b.com"]), `${SORTED_BLOB_HEADER}\na.com\nb.com`);
  assert.equal(toSortedBlob([]), `${SORTED_BLOB_HEADER}\n`);
});

test("sorted blob: binary search finds every entry and no non-entry (first, last, middle, gaps)", async () => {
  _resetBlobCacheForTests();
  const entries = Array.from({ length: 1000 }, (_, i) => `d${String(i).padStart(4, "0")}.com`);
  const kv = fakeKv({ "feed:entropy-nrd": toSortedBlob(entries) });
  for (const e of entries) {
    assert.ok(await lookupInBlob(kv, "feed:entropy-nrd", e, "HaGeZi-Entropy-NRD"), `should find ${e}`);
  }
  for (const miss of ["", "a.com", "d0000.co", "d0500.comx", "d9999.com", "zzz.com", SORTED_BLOB_HEADER]) {
    assert.equal(await lookupInBlob(kv, "feed:entropy-nrd", miss, "HaGeZi-Entropy-NRD"), null, `should not find ${JSON.stringify(miss)}`);
  }
});

test("sorted blob: parent-label walk still prevents subdomain evasion", async () => {
  _resetBlobCacheForTests();
  const kv = fakeKv({ "feed:tif-domains": toSortedBlob(["other-bad.net", "evil.com"]) });
  const hit = await lookupDomainInBlob(kv, "feed:tif-domains", "login.attacker.evil.com", "HaGeZi-TIF-domains");
  assert.deepEqual(hit, { matchedValue: "evil.com", source: "HaGeZi-TIF-domains" });
  assert.equal(await lookupDomainInBlob(kv, "feed:tif-domains", "anthropic.com", "HaGeZi-TIF-domains"), null);
});

test("legacy blob without the header (pre-sort KV data) is still matched correctly", async () => {
  _resetBlobCacheForTests();
  // Unsorted on purpose: binary search over this would miss "a.com" — a false-safe.
  const kv = fakeKv({ "feed:tif-domains": "z.com\na.com\nm.com" });
  for (const v of ["z.com", "a.com", "m.com"]) {
    assert.ok(await lookupInBlob(kv, "feed:tif-domains", v, "HaGeZi-TIF-domains"), `should find ${v}`);
  }
});

test("blob cache: kv.get is called once per key, not once per lookup", async () => {
  _resetBlobCacheForTests();
  const kv = fakeKv({ "feed:entropy-nrd": "xk3jz9q.com\nother.net" });
  await lookupInBlob(kv, "feed:entropy-nrd", "xk3jz9q.com", "HaGeZi-Entropy-NRD");
  await lookupInBlob(kv, "feed:entropy-nrd", "other.net", "HaGeZi-Entropy-NRD");
  await lookupInBlob(kv, "feed:entropy-nrd", "nope.com", "HaGeZi-Entropy-NRD");
  assert.equal(kv.getCalls, 1, "the blob should be fetched+parsed once, then served from the module cache");
});

test("blob cache: expires after its TTL, re-fetching so a cron refresh eventually becomes visible", async (t) => {
  // Real behavior this guards: a cron refresh writes new KV data from a
  // DIFFERENT Worker isolate than the ones serving live requests, so there's
  // no cross-isolate "clear the cache now" signal — the TTL is what bounds
  // staleness instead. Verified deterministically via Node's built-in timer
  // mocking rather than skipped for being awkward to test.
  t.mock.timers.enable({ apis: ["Date"] });
  try {
    _resetBlobCacheForTests();
    const store: Record<string, string> = { "feed:tif-domains": "old-evil.com" };
    const kv = fakeKv(store);
    assert.equal(await lookupInBlob(kv, "feed:tif-domains", "old-evil.com", "HaGeZi-TIF-domains") !== null, true);
    assert.equal(kv.getCalls, 1);

    // Still within the TTL (15 min) — cache should NOT refetch.
    t.mock.timers.tick(10 * 60 * 1000);
    await lookupInBlob(kv, "feed:tif-domains", "old-evil.com", "HaGeZi-TIF-domains");
    assert.equal(kv.getCalls, 1, "within TTL: should still be served from cache");

    // Cron "refreshes" the blob (new isolate, real production scenario) while
    // this isolate's cache is still holding the stale Set.
    store["feed:tif-domains"] = "new-evil.com";

    // Past the TTL — next lookup should refetch and pick up the new data.
    t.mock.timers.tick(6 * 60 * 1000); // total 16 min, past the 15 min TTL
    const staleHit = await lookupInBlob(kv, "feed:tif-domains", "old-evil.com", "HaGeZi-TIF-domains");
    const freshHit = await lookupInBlob(kv, "feed:tif-domains", "new-evil.com", "HaGeZi-TIF-domains");
    assert.equal(kv.getCalls, 2, "past TTL: should have refetched");
    assert.equal(staleHit, null, "the old entry should no longer match — the refresh is now visible");
    assert.ok(freshHit, "the newly-refreshed entry should now match");
  } finally {
    t.mock.timers.reset();
  }
});

test("concurrent lookups on a cold cache fetch and parse each blob ONCE (no stampede)", async () => {
  _resetBlobCacheForTests();
  let gets = 0;
  const kv = {
    async get() {
      gets++;
      await new Promise((r) => setTimeout(r, 5)); // let every caller start before the first resolves
      return "evil.com\nbad.net";
    },
  };
  const hits = await Promise.all(
    Array.from({ length: 5 }, () => lookupDomainInBlob(kv, "feed:tif-domains", "a.evil.com", "T")),
  );
  assert.equal(gets, 1, "5 concurrent cold lookups must share one KV read + parse");
  assert.ok(hits.every((h) => h?.matchedValue === "evil.com"));
});

test("a failed blob load is not cached — the next lookup retries", async () => {
  _resetBlobCacheForTests();
  let calls = 0;
  const kv = {
    async get() {
      calls++;
      if (calls === 1) throw new Error("KV down");
      return "evil.com";
    },
  };
  await assert.rejects(lookupDomainInBlob(kv, "feed:x", "evil.com", "T"));
  assert.ok(await lookupDomainInBlob(kv, "feed:x", "evil.com", "T"));
});

test("lookupDomain: a 110+ label hostname stays under D1's 100-param limit and still matches", async () => {
  let maxParams = 0;
  const db: MinimalD1 = {
    prepare() {
      return {
        bind(...values: unknown[]) {
          maxParams = Math.max(maxParams, values.length);
          return {
            async all<T>() {
              return { results: (values.includes("evil.com") ? [{ domain: "evil.com", source: "TEST" }] : []) as T[] };
            },
          };
        },
      };
    },
  };
  const hit = await lookupDomain(db, "a.".repeat(110) + "evil.com");
  assert.ok(maxParams <= 100, `bound ${maxParams} params`);
  assert.equal(hit?.matchedValue, "evil.com");
});
