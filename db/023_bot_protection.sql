-- Bot protection: rate limit, scoring, challenge cookie, geo/asn/cidr blocklists.
CREATE TABLE IF NOT EXISTS bot_protection_settings (
  singleton TEXT PRIMARY KEY CHECK (singleton = 'global'),
  config JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO bot_protection_settings (singleton, config)
VALUES (
  'global',
  '{
    "enabled": false,
    "log_hits": true,
    "rate_limit": {
      "enabled": true,
      "requests_per_window": 120,
      "window_sec": 60,
      "scope": "ip_host"
    },
    "scoring": {
      "enabled": true,
      "block_threshold": 70,
      "challenge_threshold": 45
    },
    "challenge": {
      "enabled": false,
      "cookie_name": "fence_bot",
      "ttl_sec": 86400,
      "secret": ""
    },
    "geo_block": {
      "enabled": false,
      "blocked_countries": []
    },
    "asn_block": {
      "enabled": false
    },
    "cidr_block": {
      "enabled": false
    },
    "tls_scoring": {
      "enabled": true,
      "block_legacy_tls": true,
      "trust_ja3_header": true
    }
  }'::jsonb
)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS bot_protection_asn (
  asn BIGINT PRIMARY KEY CHECK (asn > 0)
);

CREATE TABLE IF NOT EXISTS bot_protection_cidr (
  cidr TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS bot_protection_sync_state (
  singleton TEXT PRIMARY KEY CHECK (singleton = 'global'),
  last_attempt_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  last_error TEXT NOT NULL DEFAULT '',
  asn_rows INT NOT NULL DEFAULT 0,
  cidr_rows INT NOT NULL DEFAULT 0
);

INSERT INTO bot_protection_sync_state (singleton) VALUES ('global')
ON CONFLICT DO NOTHING;
