ALTER TABLE xdp_samples ADD COLUMN trial_budget_hit DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE xdp_samples ADD COLUMN trial_icmp_hit DOUBLE PRECISION NOT NULL DEFAULT 0;
CREATE TABLE xdp_alerts (
 kind TEXT NOT NULL, opened_ms BIGINT NOT NULL, closed_ms BIGINT, reason TEXT NOT NULL, drop_percent DOUBLE PRECISION NOT NULL, PRIMARY KEY(kind, opened_ms)
);
CREATE UNIQUE INDEX xdp_alerts_active ON xdp_alerts(kind) WHERE closed_ms IS NULL;
