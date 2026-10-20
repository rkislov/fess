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
