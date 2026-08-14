-- Abused-TLD suffix matching (SPEC §6/§8) — distinct from feed_domains: this
-- table holds bare TLD labels (e.g. "actor"), matched against a resolved
-- hostname's final label, not the parent-label domain walk.
CREATE TABLE IF NOT EXISTS feed_tlds (
  tld TEXT PRIMARY KEY,
  source TEXT NOT NULL
);
