-- Per-backend client IP allowlist (applies to requests matching path_prefix on the site).
ALTER TABLE backends
  ADD COLUMN IF NOT EXISTS ip_allow_mode TEXT NOT NULL DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS allowed_cidrs TEXT NOT NULL DEFAULT '[]';

ALTER TABLE backends DROP CONSTRAINT IF EXISTS backends_ip_allow_mode_check;
ALTER TABLE backends ADD CONSTRAINT backends_ip_allow_mode_check
  CHECK (ip_allow_mode IN ('none', 'private', 'custom'));

COMMENT ON COLUMN backends.ip_allow_mode IS 'Client IP gate: none, private (RFC1918/loopback/ULA), or custom (allowed_cidrs JSON array).';
COMMENT ON COLUMN backends.allowed_cidrs IS 'JSON array of CIDR strings when ip_allow_mode=custom, else [].';
