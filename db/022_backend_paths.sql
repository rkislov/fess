-- Path rules per upstream backend (multiple prefixes per base_url).
CREATE TABLE IF NOT EXISTS backend_paths (
  id UUID PRIMARY KEY,
  backend_id UUID NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
  path_prefix TEXT NOT NULL DEFAULT '*',
  priority INTEGER NOT NULL DEFAULT 100,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  websocket_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  timeout_sec INTEGER NOT NULL DEFAULT 0,
  idle_timeout_sec INTEGER NOT NULL DEFAULT 0,
  ip_allow_mode TEXT NOT NULL DEFAULT 'none',
  allowed_cidrs TEXT NOT NULL DEFAULT '[]',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT backend_paths_ip_allow_mode_check CHECK (ip_allow_mode IN ('none', 'private', 'custom'))
);

CREATE UNIQUE INDEX IF NOT EXISTS backend_paths_backend_prefix_uq
  ON backend_paths (backend_id, lower(path_prefix));

COMMENT ON TABLE backend_paths IS 'URI path rules for a backend; path_prefix * = all paths (catch-all).';
COMMENT ON COLUMN backend_paths.path_prefix IS 'Path prefix (/admin) or * for any path on this upstream.';

-- Migrate existing per-backend path settings into backend_paths.
INSERT INTO backend_paths (
  id, backend_id, path_prefix, priority, enabled,
  websocket_enabled, timeout_sec, idle_timeout_sec, ip_allow_mode, allowed_cidrs
)
SELECT
  gen_random_uuid(),
  b.id,
  CASE
    WHEN trim(COALESCE(b.path_prefix, '')) = '' THEN '*'
    ELSE trim(b.path_prefix)
  END,
  b.priority,
  TRUE,
  COALESCE(b.websocket_enabled, FALSE),
  COALESCE(b.timeout_sec, 0),
  COALESCE(b.idle_timeout_sec, 0),
  COALESCE(NULLIF(trim(b.ip_allow_mode), ''), 'none'),
  COALESCE(NULLIF(trim(b.allowed_cidrs), ''), '[]')
FROM backends b
WHERE NOT EXISTS (SELECT 1 FROM backend_paths p WHERE p.backend_id = b.id);

ALTER TABLE backends DROP COLUMN IF EXISTS path_prefix;
ALTER TABLE backends DROP COLUMN IF EXISTS websocket_enabled;
ALTER TABLE backends DROP COLUMN IF EXISTS timeout_sec;
ALTER TABLE backends DROP COLUMN IF EXISTS idle_timeout_sec;
ALTER TABLE backends DROP COLUMN IF EXISTS ip_allow_mode;
ALTER TABLE backends DROP COLUMN IF EXISTS allowed_cidrs;
