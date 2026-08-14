import { test } from "node:test";
import assert from "node:assert/strict";
import {
  lookupDomain,
  lookupIp,
  lookupExactUrl,
  lookupTld,
  lookupInBlob,
  lookupDomainInBlob,
  _resetBlobCacheForTests,
  type MinimalD1,
  type MinimalKV,
} from "./feeds.ts";

// Minimal in-memory fake matching the exact query shapes feeds.ts issues —
// faithful enough to exercise real matching logic without a live D1 binding
// (D1 itself is only reachable from the Workers runtime; see CLAUDE.md).
function fakeDb(
  domains: Array<{ domain: string; source: string }>,
  ips: Array<{ ip: string; source: string }> = [],
  urls: Array<{ url: string; source: string }> = [],
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
              if (sql.includes("feed_urls_exact")) {
                return { results: urls.filter((u) => u.url === values[0]) as T[] };
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

test("lookupExactUrl: exact match only (URLhaus precision split)", async () => {
  const db = fakeDb([], [], [{ url: "https://evil.com/payload.exe", source: "URLhaus" }]);
  assert.deepEqual(
    await lookupExactUrl(db, "https://evil.com/payload.exe"),
    { matchedValue: "https://evil.com/payload.exe", source: "URLhaus" },
  );
  assert.equal(await lookupExactUrl(db, "https://evil.com/other"), null);
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

test("blob cache: kv.get is called once per key, not once per lookup", async () => {
  _resetBlobCacheForTests();
  const kv = fakeKv({ "feed:entropy-nrd": "xk3jz9q.com\nother.net" });
  await lookupInBlob(kv, "feed:entropy-nrd", "xk3jz9q.com", "HaGeZi-Entropy-NRD");
  await lookupInBlob(kv, "feed:entropy-nrd", "other.net", "HaGeZi-Entropy-NRD");
  await lookupInBlob(kv, "feed:entropy-nrd", "nope.com", "HaGeZi-Entropy-NRD");
  assert.equal(kv.getCalls, 1, "the blob should be fetched+parsed once, then served from the module cache");
});
