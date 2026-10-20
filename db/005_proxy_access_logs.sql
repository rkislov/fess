-- Per-request routing / outcome log from waf-gateway (Host → upstream, outcome).
CREATE TABLE IF NOT EXISTS proxy_access_logs (
  id BIGSERIAL PRIMARY KEY,
  host TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  client_ip TEXT,
  upstream_base TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL DEFAULT 'proxied',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS proxy_access_logs_created_at_idx ON proxy_access_logs (created_at DESC);
