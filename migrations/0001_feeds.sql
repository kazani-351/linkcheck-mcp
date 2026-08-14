-- SPEC §6: threat-feed storage. Domain/IP membership tables (parent-label matched
-- at query time, see src/feeds.ts) + exact-URL matches (URLhaus precision split,
-- SPEC §6/§8) + per-source freshness metadata (SPEC §9/§20 stale-feed handling).

CREATE TABLE IF NOT EXISTS feed_domains (
  domain TEXT PRIMARY KEY,
  source TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feed_ips (
  ip TEXT PRIMARY KEY,
  source TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feed_urls_exact (
  url TEXT PRIMARY KEY,
  source TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feed_meta (
  source TEXT PRIMARY KEY,
  last_refresh INTEGER NOT NULL,
  last_status TEXT NOT NULL,
  entry_count INTEGER NOT NULL
);
