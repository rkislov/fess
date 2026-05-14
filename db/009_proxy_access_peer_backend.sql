-- Who connected to the gateway vs resolved client (LB); which backend row was chosen for routing.
ALTER TABLE proxy_access_logs ADD COLUMN IF NOT EXISTS tcp_peer TEXT NOT NULL DEFAULT '';
ALTER TABLE proxy_access_logs ADD COLUMN IF NOT EXISTS backend_name TEXT NOT NULL DEFAULT '';
