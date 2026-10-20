-- Native SQLite baseline. Apply once; evolve with numbered SQLite migrations.
CREATE TABLE acme_http01_challenges (
  token TEXT PRIMARY KEY,
  key_authorization TEXT NOT NULL,
  certificate_id TEXT REFERENCES certificates(id) ON DELETE CASCADE,
  expires_at TIMESTAMP NOT NULL
);
CREATE TABLE acme_settings (
  id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  directory_url TEXT NOT NULL DEFAULT 'https://acme-v02.api.letsencrypt.org/directory',
  email TEXT NOT NULL DEFAULT '',
  tos_agreed BOOLEAN NOT NULL DEFAULT FALSE,
  account_key_pem TEXT,
  account_uri TEXT,
  eab_kid TEXT,
  eab_hmac_key TEXT,
  renew_before_days INT NOT NULL DEFAULT 30,
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
INSERT INTO "acme_settings" VALUES(1,'https://acme-v02.api.letsencrypt.org/directory','',0,NULL,NULL,NULL,NULL,30,'2026-10-20 09:01:26.378');
CREATE TABLE ai_settings (
  singleton TEXT PRIMARY KEY DEFAULT 'global' CHECK (singleton = 'global'),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  base_url TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  api_key TEXT NOT NULL DEFAULT '',
  http_timeout_sec INT NOT NULL DEFAULT 0,
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
INSERT INTO "ai_settings" VALUES('global',1,'','','',0,'2026-10-20 09:01:26.377');
CREATE TABLE audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  operation TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  before_json TEXT,
  after_json TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
CREATE TABLE auth_settings (
  singleton TEXT PRIMARY KEY DEFAULT 'global',
  local_auth_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  ldap_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  ldap_url TEXT NOT NULL DEFAULT '',
  ldap_bind_dn TEXT NOT NULL DEFAULT '',
  ldap_bind_password TEXT NOT NULL DEFAULT '',
  ldap_base_dn TEXT NOT NULL DEFAULT '',
  ldap_user_filter TEXT NOT NULL DEFAULT '(sAMAccountName=%s)',
  ldap_user_attr TEXT NOT NULL DEFAULT 'sAMAccountName',
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
INSERT INTO "auth_settings" VALUES('global',1,0,'','','','','(sAMAccountName=%s)','sAMAccountName','2026-10-20 09:01:26.375');
CREATE TABLE backend_paths (
  id TEXT PRIMARY KEY,
  backend_id TEXT NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
  path_prefix TEXT NOT NULL DEFAULT '*',
  priority INTEGER NOT NULL DEFAULT 100,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  websocket_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  timeout_sec INTEGER NOT NULL DEFAULT 0,
  idle_timeout_sec INTEGER NOT NULL DEFAULT 0,
  ip_allow_mode TEXT NOT NULL DEFAULT 'none',
  allowed_cidrs TEXT NOT NULL DEFAULT '[]',
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')), rate_limit_override TEXT,
  CONSTRAINT backend_paths_ip_allow_mode_check CHECK (ip_allow_mode IN ('none', 'private', 'custom'))
);
CREATE TABLE backends (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 100,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')), tls_skip_verify BOOLEAN NOT NULL DEFAULT FALSE, rate_limit_override TEXT,
  CONSTRAINT backends_base_url_nonempty CHECK (length(trim(base_url)) > 0)
);
CREATE TABLE bot_protection_asn (
  asn BIGINT PRIMARY KEY CHECK (asn > 0)
);
CREATE TABLE bot_protection_cidr (
  cidr TEXT PRIMARY KEY
);
CREATE TABLE bot_protection_settings (
  singleton TEXT PRIMARY KEY CHECK (singleton = 'global'),
  config TEXT NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
INSERT INTO "bot_protection_settings" VALUES('global','{
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
  }','2026-10-20 09:01:26.373');
CREATE TABLE bot_protection_sync_state (
  singleton TEXT PRIMARY KEY CHECK (singleton = 'global'),
  last_attempt_at TIMESTAMP,
  last_success_at TIMESTAMP,
  last_error TEXT NOT NULL DEFAULT '',
  asn_rows INT NOT NULL DEFAULT 0,
  cidr_rows INT NOT NULL DEFAULT 0
);
INSERT INTO "bot_protection_sync_state" VALUES('global',NULL,NULL,'',0,0);
CREATE TABLE certificates (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'manual',
  domains TEXT NOT NULL DEFAULT '[]',
  cert_pem TEXT,
  key_pem TEXT,
  issuer TEXT,
  serial TEXT,
  fingerprint_sha256 TEXT,
  not_before TIMESTAMP,
  not_after TIMESTAMP,
  auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
  status TEXT NOT NULL DEFAULT 'pending',
  last_error TEXT,
  last_issued_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
CREATE TABLE ip_bypass (
  cidr TEXT PRIMARY KEY,
  comment TEXT NOT NULL DEFAULT '',
  source_waf_log_id BIGINT,
  expires_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
CREATE TABLE ip_lists (
  id TEXT PRIMARY KEY,
  list_type TEXT NOT NULL CHECK (list_type IN ('whitelist', 'blacklist')),
  cidr TEXT NOT NULL,
  comment TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
CREATE TABLE malware_scan_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL DEFAULT '',
  host TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  content_type TEXT NOT NULL DEFAULT '',
  body_bytes BIGINT NOT NULL DEFAULT 0,
  clean BOOLEAN NOT NULL,
  scan_source TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  source_ip TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
, scan_result TEXT NOT NULL DEFAULT 'clean', icap_checked BOOLEAN NOT NULL DEFAULT FALSE, external_checked BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE malware_settings (
  singleton TEXT PRIMARY KEY CHECK (singleton = 'global'),
  config TEXT NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
INSERT INTO "malware_settings" VALUES('global','{
    "icap": {
      "enabled": true,
      "host": "clamav-icap",
      "port": 1344,
      "service": "avscan",
      "timeout_ms": 60000,
      "fail_open": true
    },
    "clamav_mirror": {
      "database_mirror": ""
    },
    "external_scanner": {
      "url": "",
      "timeout_ms": 60000,
      "api_key": "",
      "api_key_header": "X-Api-Key"
    },
    "sandbox": {
      "webhook_url": "",
      "timeout_ms": 120000,
      "api_key": "",
      "api_key_header": "X-Api-Key"
    },
    "body_scan": {
      "max_bytes": 20971520,
      "methods": ["POST", "PUT", "PATCH"],
      "mime_substrings": [
        "octet-stream",
        "pdf",
        "zip",
        "msword",
        "spreadsheet",
        "officedocument",
        "form-data",
        "x-tar",
        "gzip"
      ]
    },
    "geoip": {
      "mmdb_source_url": "",
      "mmdb_last_installed_at": ""
    }
  }','2026-10-20 09:01:26.362');
CREATE TABLE policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('block', 'log')),
  priority INTEGER NOT NULL DEFAULT 100,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
CREATE TABLE policy_versions (
  id TEXT PRIMARY KEY,
  policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  version BIGINT NOT NULL,
  snapshot_json TEXT NOT NULL,
  published_by TEXT NOT NULL,
  published_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  UNIQUE(policy_id, version)
);
CREATE TABLE proxy_access_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  client_ip TEXT,
  upstream_base TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL DEFAULT 'proxied',
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
, protocol TEXT NOT NULL DEFAULT 'http', country_code TEXT NOT NULL DEFAULT '', tcp_peer TEXT NOT NULL DEFAULT '', backend_name TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '');
CREATE TABLE rate_limit_settings (
  singleton TEXT PRIMARY KEY CHECK (singleton = 'global'),
  config TEXT NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
INSERT INTO "rate_limit_settings" VALUES('global','{"enabled":true,"requests_per_window":120,"window_sec":60,"scope":"ip_host"}','2026-10-20 09:01:26.378');
CREATE TABLE refresh_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  revoked_at TIMESTAMP
);
CREATE TABLE rules (
  id TEXT PRIMARY KEY,
  policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('allow', 'block', 'log', 'redirect', 'replace')),
  priority INTEGER NOT NULL DEFAULT 100,
  condition_json TEXT NOT NULL,
  transform_json TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
CREATE TABLE siem_export_cursors (
  stream TEXT PRIMARY KEY,
  last_id BIGINT NOT NULL DEFAULT 0
);
INSERT INTO "siem_export_cursors" VALUES('waf_logs',0);
INSERT INTO "siem_export_cursors" VALUES('proxy_access_logs',0);
INSERT INTO "siem_export_cursors" VALUES('audit_logs',0);
CREATE TABLE siem_export_settings (
  singleton TEXT PRIMARY KEY DEFAULT 'global',
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  format TEXT NOT NULL DEFAULT 'cef' CHECK (format IN ('cef', 'syslog')),
  host TEXT NOT NULL DEFAULT '',
  port INT NOT NULL DEFAULT 514,
  protocol TEXT NOT NULL DEFAULT 'udp' CHECK (protocol IN ('udp', 'tcp')),
  tls BOOLEAN NOT NULL DEFAULT FALSE,
  export_waf_logs BOOLEAN NOT NULL DEFAULT TRUE,
  export_proxy_logs BOOLEAN NOT NULL DEFAULT TRUE,
  export_audit_logs BOOLEAN NOT NULL DEFAULT FALSE,
  device_vendor TEXT NOT NULL DEFAULT 'Fence',
  device_product TEXT NOT NULL DEFAULT 'WAF',
  device_version TEXT NOT NULL DEFAULT '1.0',
  poll_interval_sec INT NOT NULL DEFAULT 30,
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
INSERT INTO "siem_export_settings" VALUES('global',0,'cef','',514,'udp',0,1,1,0,'Fence','WAF','1.0',30,'2026-10-20 09:01:26.375');
CREATE TABLE sites (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  host_pattern TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 100,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')), policy_id TEXT NULL REFERENCES policies(id) ON DELETE SET NULL, tls_enabled BOOLEAN NOT NULL DEFAULT FALSE, tls_cert_pem TEXT, tls_key_pem TEXT, certificate_id TEXT REFERENCES certificates(id) ON DELETE SET NULL,
  CONSTRAINT sites_host_pattern_nonempty CHECK (length(trim(host_pattern)) > 0)
);
CREATE TABLE threat_feed_file_hashes (
  hash TEXT PRIMARY KEY,
  hash_alg TEXT NOT NULL CHECK (hash_alg IN ('md5', 'sha256'))
);
CREATE TABLE threat_feed_indicators (
  indicator TEXT PRIMARY KEY
);
CREATE TABLE threat_feed_settings (
  singleton TEXT PRIMARY KEY CHECK (singleton = 'global'),
  config TEXT NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
INSERT INTO "threat_feed_settings" VALUES('global','{
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
  }','2026-10-20 09:01:26.368');
CREATE TABLE threat_feed_sync_state (
  singleton TEXT PRIMARY KEY CHECK (singleton = 'global'),
  last_attempt_at TIMESTAMP,
  last_success_at TIMESTAMP,
  last_error TEXT NOT NULL DEFAULT '',
  rows_ingested INT NOT NULL DEFAULT 0
, auto_sync_day DATE, auto_sync_count INT NOT NULL DEFAULT 0);
INSERT INTO "threat_feed_sync_state" VALUES('global',NULL,NULL,'',0,NULL,0);
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'operator', 'viewer')),
  auth_provider TEXT NOT NULL DEFAULT 'local' CHECK (auth_provider IN ('local', 'ldap')),
  ldap_dn TEXT NOT NULL DEFAULT '',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  last_login_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
  updated_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
CREATE TABLE waf_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  policy_id TEXT,
  rule_id TEXT,
  action TEXT NOT NULL,
  source_ip TEXT,
  method TEXT,
  path TEXT,
  host TEXT NOT NULL DEFAULT '',
  ai_analysis TEXT NOT NULL DEFAULT '',
  details TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
CREATE UNIQUE INDEX sites_host_pattern_unique ON sites (lower(host_pattern));
CREATE INDEX sites_policy_id_idx ON sites(policy_id) WHERE policy_id IS NOT NULL;
CREATE INDEX proxy_access_logs_created_at_idx ON proxy_access_logs (created_at DESC);
CREATE INDEX proxy_access_logs_host_idx ON proxy_access_logs (host);
CREATE INDEX proxy_access_logs_country_idx ON proxy_access_logs (country_code) WHERE country_code <> '';
CREATE INDEX waf_logs_created_at_rule_idx ON waf_logs (created_at DESC, rule_id);
CREATE INDEX malware_scan_logs_created_at_idx ON malware_scan_logs (created_at DESC);
CREATE INDEX malware_scan_logs_clean_idx ON malware_scan_logs (clean, created_at DESC);
CREATE INDEX malware_scan_logs_scan_result_idx ON malware_scan_logs (scan_result, created_at DESC);
CREATE UNIQUE INDEX backend_paths_backend_prefix_uq
  ON backend_paths (backend_id, lower(path_prefix));
CREATE INDEX ip_bypass_expires_idx ON ip_bypass (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX malware_scan_logs_icap_checked_idx
  ON malware_scan_logs (icap_checked, created_at DESC)
  WHERE icap_checked;
CREATE INDEX malware_scan_logs_external_checked_idx
  ON malware_scan_logs (external_checked, created_at DESC)
  WHERE external_checked;
CREATE INDEX users_role_idx ON users (role);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id, expires_at DESC);
CREATE INDEX idx_threat_feed_file_hashes_alg ON threat_feed_file_hashes (hash_alg);
