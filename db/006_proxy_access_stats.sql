-- Protocol (http/https) and optional GeoIP country for access logs + dashboard indexes.
ALTER TABLE proxy_access_logs ADD COLUMN IF NOT EXISTS protocol TEXT NOT NULL DEFAULT 'http';
ALTER TABLE proxy_access_logs ADD COLUMN IF NOT EXISTS country_code TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS proxy_access_logs_host_idx ON proxy_access_logs (host);
CREATE INDEX IF NOT EXISTS proxy_access_logs_country_idx ON proxy_access_logs (country_code) WHERE country_code <> '';
