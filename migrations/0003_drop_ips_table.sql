-- feed_ips (from 0001) is superseded: TIF-IPs (62K entries) doesn't fit D1's
-- row-write budget, so it moved to a single KV blob instead (see feeds.ts,
-- SPEC §6/§18/§20 — the KV-blob pivot for the large feeds). Table was created
-- empty and never populated; dropping rather than leaving dead schema around.
DROP TABLE IF EXISTS feed_ips;
