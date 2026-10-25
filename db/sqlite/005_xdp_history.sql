-- Durable XDP rate samples, independent of dashboard sessions.
CREATE TABLE IF NOT EXISTS xdp_samples (
  sampled_ms BIGINT NOT NULL,
  run_id TEXT NOT NULL,
  interface TEXT NOT NULL,
  interval_seconds DOUBLE PRECISION NOT NULL,
  seen DOUBLE PRECISION NOT NULL,
  passed DOUBLE PRECISION NOT NULL,
  cidr_drop DOUBLE PRECISION NOT NULL,
  rate_drop DOUBLE PRECISION NOT NULL,
  fragment_drop DOUBLE PRECISION NOT NULL,
  malformed_pass DOUBLE PRECISION NOT NULL,
  global_budget_drop DOUBLE PRECISION NOT NULL,
  icmp_ping_drop DOUBLE PRECISION NOT NULL,
  malformed_drop DOUBLE PRECISION NOT NULL,
  temporary_block_drop DOUBLE PRECISION NOT NULL,
  frame_bytes DOUBLE PRECISION NOT NULL,
  protected_packets DOUBLE PRECISION NOT NULL,
  protected_bytes DOUBLE PRECISION NOT NULL,
  protected_syn DOUBLE PRECISION NOT NULL,
  icmp_echo DOUBLE PRECISION NOT NULL,
  PRIMARY KEY (sampled_ms, run_id)
);
