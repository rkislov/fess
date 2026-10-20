-- Optional WAF policy bound to a virtual host. NULL = evaluate all enabled policies (legacy behavior).
ALTER TABLE sites ADD COLUMN IF NOT EXISTS policy_id UUID NULL REFERENCES policies(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS sites_policy_id_idx ON sites(policy_id) WHERE policy_id IS NOT NULL;
