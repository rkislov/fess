-- Temporary or permanent client IP/CIDR bypass (threat feed, bot protection, WAF rules, rate limit).
CREATE TABLE IF NOT EXISTS ip_bypass (
  cidr TEXT PRIMARY KEY,
  comment TEXT NOT NULL DEFAULT '',
  source_waf_log_id BIGINT,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ip_bypass_expires_idx ON ip_bypass (expires_at) WHERE expires_at IS NOT NULL;
