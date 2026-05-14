CREATE TABLE IF NOT EXISTS sites (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  host_pattern TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 100,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT sites_host_pattern_nonempty CHECK (length(trim(host_pattern)) > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS sites_host_pattern_unique ON sites (lower(host_pattern));

CREATE TABLE IF NOT EXISTS backends (
  id UUID PRIMARY KEY,
  site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 100,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT backends_base_url_nonempty CHECK (length(trim(base_url)) > 0)
);

-- Default catch-all for docker-compose (Host header often not set / arbitrary); tune in UI.
INSERT INTO sites (id, name, host_pattern, priority, enabled)
VALUES (
  '33333333-3333-3333-3333-333333333333',
  'default',
  '*',
  1000000,
  TRUE
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO backends (id, site_id, name, base_url, priority, enabled)
VALUES (
  '44444444-4444-4444-4444-444444444444',
  '33333333-3333-3333-3333-333333333333',
  'httpbin',
  'http://httpbin:8080',
  100,
  TRUE
)
ON CONFLICT (id) DO NOTHING;
