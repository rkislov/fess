-- Adopt the OS clamd service when the old bundled ICAP address is still set.
UPDATE malware_settings
SET config = jsonb_set(jsonb_set(config, '{icap,enabled}', 'false'::jsonb), '{clamd}',
 '{"enabled":true,"socket":"/run/fess-clamav/clamd.sock","timeout_ms":60000,"fail_open":false}'::jsonb), updated_at=NOW()
WHERE singleton='global' AND config->'icap'->>'host'='clamav-icap';
ALTER TABLE malware_scan_logs ADD COLUMN IF NOT EXISTS clamd_checked BOOLEAN NOT NULL DEFAULT FALSE;
