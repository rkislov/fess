CREATE TABLE IF NOT EXISTS policies (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('block', 'log')),
  priority INTEGER NOT NULL DEFAULT 100,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rules (
  id UUID PRIMARY KEY,
  policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('allow', 'block', 'log', 'redirect', 'replace')),
  priority INTEGER NOT NULL DEFAULT 100,
  condition_json JSONB NOT NULL,
  transform_json JSONB,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policy_versions (
  id UUID PRIMARY KEY,
  policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  version BIGINT NOT NULL,
  snapshot_json JSONB NOT NULL,
  published_by TEXT NOT NULL,
  published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(policy_id, version)
);

CREATE TABLE IF NOT EXISTS ip_lists (
  id UUID PRIMARY KEY,
  list_type TEXT NOT NULL CHECK (list_type IN ('whitelist', 'blacklist')),
  cidr TEXT NOT NULL,
  comment TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_logs (
  id BIGSERIAL PRIMARY KEY,
  request_id TEXT NOT NULL,
  policy_id UUID,
  rule_id UUID,
  action TEXT NOT NULL,
  source_ip TEXT,
  method TEXT,
  path TEXT,
  details JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  actor TEXT NOT NULL,
  operation TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  before_json JSONB,
  after_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
