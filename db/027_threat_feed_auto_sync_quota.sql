-- Track automatic Q-feed / threat-feed URL syncs (manual sync is unlimited).
ALTER TABLE threat_feed_sync_state
  ADD COLUMN IF NOT EXISTS auto_sync_day DATE,
  ADD COLUMN IF NOT EXISTS auto_sync_count INT NOT NULL DEFAULT 0;
