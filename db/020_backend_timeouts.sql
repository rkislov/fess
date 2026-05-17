-- Per-backend upstream timeouts (seconds; 0 = gateway default).
ALTER TABLE backends
  ADD COLUMN IF NOT EXISTS timeout_sec INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS idle_timeout_sec INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN backends.timeout_sec IS 'Max upstream round-trip time in seconds (0 = no limit).';
COMMENT ON COLUMN backends.idle_timeout_sec IS 'Idle keep-alive connection lifetime in seconds (0 = transport default).';
