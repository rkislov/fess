-- Per-site TLS material for HTTPS termination on waf-gateway (SNI).
ALTER TABLE sites ADD COLUMN IF NOT EXISTS tls_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS tls_cert_pem TEXT;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS tls_key_pem TEXT;
