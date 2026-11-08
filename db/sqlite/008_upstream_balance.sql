ALTER TABLE sites ADD COLUMN upstream_mode TEXT NOT NULL DEFAULT 'priority'
    CHECK (upstream_mode IN ('priority','round_robin','ip_hash','path_hash','header_hash','cookie_hash'));
ALTER TABLE sites ADD COLUMN upstream_key TEXT NOT NULL DEFAULT '';
