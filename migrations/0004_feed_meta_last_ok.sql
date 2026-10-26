-- last_refresh is the last ATTEMPT (a failed refresh writes it too), so it can't
-- say how old the data being served is. last_ok is the last SUCCESSFUL refresh,
-- written only on success; a check degrades once it is over 48h old (refresh.ts
-- STALE_AFTER_MS). Backfill: rows whose last attempt succeeded get last_refresh;
-- rows currently in error stay NULL ("no successful refresh on record") until
-- their next success.
ALTER TABLE feed_meta ADD COLUMN last_ok INTEGER;
UPDATE feed_meta SET last_ok = last_refresh WHERE last_status = 'ok';
