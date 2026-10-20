-- External threat feeds (e.g. Q-Feeds): sync indicators + optional gateway blocklist.
CREATE TABLE IF NOT EXISTS threat_feed_settings (
  singleton TEXT PRIMARY KEY CHECK (singleton = 'global'),
  config JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO threat_feed_settings (singleton, config)
VALUES (
  'global',
  '{
    "enabled": false,
    "block": true,
    "log_hits": true,
    "feed_url": "",
    "poll_interval_sec": 3600,
    "http_timeout_sec": 120,
    "sources": [],
    "format": "auto",
    "csv_indicator_column": "",
    "csv_source_column": "",
    "api_key": "",
    "api_key_header": "Authorization"
  }'::jsonb
)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS threat_feed_indicators (
  indicator TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS threat_feed_sync_state (
  singleton TEXT PRIMARY KEY CHECK (singleton = 'global'),
  last_attempt_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  last_error TEXT NOT NULL DEFAULT '',
  rows_ingested INT NOT NULL DEFAULT 0
);

INSERT INTO threat_feed_sync_state (singleton) VALUES ('global')
ON CONFLICT DO NOTHING;
