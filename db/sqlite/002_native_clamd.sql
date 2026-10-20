UPDATE malware_settings SET config=json_set(config, '$.icap.enabled', json('false'), '$.icap.host', '127.0.0.1', '$.clamd', json('{"enabled":true,"socket":"/run/fess-clamav/clamd.sock","timeout_ms":60000,"fail_open":false}')) WHERE singleton='global';
ALTER TABLE malware_scan_logs ADD COLUMN clamd_checked BOOLEAN NOT NULL DEFAULT FALSE;
