-- Пользователи, refresh-токены, настройки LDAP и экспорт в SIEM.
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'operator', 'viewer')),
  auth_provider TEXT NOT NULL DEFAULT 'local' CHECK (auth_provider IN ('local', 'ldap')),
  ldap_dn TEXT NOT NULL DEFAULT '',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS users_role_idx ON users (role);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS refresh_tokens_user_idx ON refresh_tokens (user_id, expires_at DESC);

CREATE TABLE IF NOT EXISTS auth_settings (
  singleton TEXT PRIMARY KEY DEFAULT 'global',
  local_auth_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  ldap_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  ldap_url TEXT NOT NULL DEFAULT '',
  ldap_bind_dn TEXT NOT NULL DEFAULT '',
  ldap_bind_password TEXT NOT NULL DEFAULT '',
  ldap_base_dn TEXT NOT NULL DEFAULT '',
  ldap_user_filter TEXT NOT NULL DEFAULT '(sAMAccountName=%s)',
  ldap_user_attr TEXT NOT NULL DEFAULT 'sAMAccountName',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO auth_settings (singleton) VALUES ('global') ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS siem_export_settings (
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
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO siem_export_settings (singleton) VALUES ('global') ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS siem_export_cursors (
  stream TEXT PRIMARY KEY,
  last_id BIGINT NOT NULL DEFAULT 0
);

INSERT INTO siem_export_cursors (stream, last_id) VALUES
  ('waf_logs', 0),
  ('proxy_access_logs', 0),
  ('audit_logs', 0)
ON CONFLICT (stream) DO NOTHING;
