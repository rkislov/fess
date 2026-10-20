-- System-wide rate limit + optional overrides on backends and paths (inherit when NULL).

CREATE TABLE IF NOT EXISTS rate_limit_settings (
  singleton TEXT PRIMARY KEY CHECK (singleton = 'global'),
  config JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO rate_limit_settings (singleton, config)
SELECT
  'global',
  COALESCE(
    (SELECT (config->'rate_limit') FROM bot_protection_settings WHERE singleton = 'global'),
    '{"enabled":true,"requests_per_window":120,"window_sec":60,"scope":"ip_host"}'::jsonb
  )
WHERE NOT EXISTS (SELECT 1 FROM rate_limit_settings WHERE singleton = 'global');

ALTER TABLE backends
  ADD COLUMN IF NOT EXISTS rate_limit_override JSONB;

ALTER TABLE backend_paths
  ADD COLUMN IF NOT EXISTS rate_limit_override JSONB;

COMMENT ON COLUMN backends.rate_limit_override IS 'NULL = inherit system rate limit; JSON object = override for all paths on this backend unless path overrides.';
COMMENT ON COLUMN backend_paths.rate_limit_override IS 'NULL = inherit backend then system; JSON object = override for this path prefix.';
