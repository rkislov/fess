-- Certificate inventory (УЦ) and ACME HTTP-01 challenges.

CREATE TABLE IF NOT EXISTS certificates (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'manual',
  domains JSONB NOT NULL DEFAULT '[]'::jsonb,
  cert_pem TEXT,
  key_pem TEXT,
  issuer TEXT,
  serial TEXT,
  fingerprint_sha256 TEXT,
  not_before TIMESTAMPTZ,
  not_after TIMESTAMPTZ,
  auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
  status TEXT NOT NULL DEFAULT 'pending',
  last_error TEXT,
  last_issued_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS acme_settings (
  id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  directory_url TEXT NOT NULL DEFAULT 'https://acme-v02.api.letsencrypt.org/directory',
  email TEXT NOT NULL DEFAULT '',
  tos_agreed BOOLEAN NOT NULL DEFAULT FALSE,
  account_key_pem TEXT,
  account_uri TEXT,
  eab_kid TEXT,
  eab_hmac_key TEXT,
  renew_before_days INT NOT NULL DEFAULT 30,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO acme_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS acme_http01_challenges (
  token TEXT PRIMARY KEY,
  key_authorization TEXT NOT NULL,
  certificate_id UUID REFERENCES certificates(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE sites ADD COLUMN IF NOT EXISTS certificate_id UUID REFERENCES certificates(id) ON DELETE SET NULL;

-- Move existing per-site PEMs into the inventory.
INSERT INTO certificates (
  id, name, source, domains, cert_pem, key_pem, auto_renew, status, last_issued_at, created_at, updated_at
)
SELECT
  gen_random_uuid(),
  'site:' || s.name,
  'manual',
  '[]'::jsonb,
  s.tls_cert_pem,
  s.tls_key_pem,
  FALSE,
  'issued',
  NOW(),
  NOW(),
  NOW()
FROM sites s
WHERE s.certificate_id IS NULL
  AND length(trim(COALESCE(s.tls_cert_pem, ''))) > 0
  AND length(trim(COALESCE(s.tls_key_pem, ''))) > 0;

UPDATE sites s
SET certificate_id = c.id
FROM certificates c
WHERE s.certificate_id IS NULL
  AND c.source = 'manual'
  AND c.name = 'site:' || s.name
  AND c.cert_pem = s.tls_cert_pem
  AND c.key_pem = s.tls_key_pem;
