-- Upstream HTTPS backends: optionally skip TLS certificate verification (e.g. self-signed in lab).
ALTER TABLE backends
  ADD COLUMN IF NOT EXISTS tls_skip_verify BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN backends.tls_skip_verify IS 'When true and base_url uses https, gateway connects without verifying server certificate (InsecureSkipVerify).';
