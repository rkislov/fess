package main

import (
	"context"
	"database/sql"
	"time"

	"fence/pkg/threatfeed"
)

const (
	threatFeedMaxAutoSyncsPerDay     = 2
	threatFeedMinAutoPollIntervalSec = 12 * 3600 // spread automatic runs (~2 per day)
)

type threatFeedAutoQuota struct {
	Day   sql.NullTime
	Count int
}

func threatFeedUTCDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func effectiveThreatFeedPollIntervalSec(cfg threatfeed.Config) int {
	interval := cfg.PollIntervalSec
	if interval < threatFeedMinAutoPollIntervalSec {
		interval = threatFeedMinAutoPollIntervalSec
	}
	return interval
}

func loadThreatFeedAutoQuota(ctx context.Context, db *sql.DB) (threatFeedAutoQuota, error) {
	var q threatFeedAutoQuota
	err := db.QueryRowContext(ctx, `
SELECT auto_sync_day, auto_sync_count
FROM threat_feed_sync_state WHERE singleton = 'global'`).Scan(&q.Day, &q.Count)
	return q, err
}

func autoSyncsUsedToday(quota threatFeedAutoQuota, now time.Time) int {
	if !quota.Day.Valid {
		return 0
	}
	if !threatFeedUTCDay(quota.Day.Time).Equal(threatFeedUTCDay(now)) {
		return 0
	}
	return quota.Count
}

func recordThreatFeedAutoSync(ctx context.Context, db *sql.DB, now time.Time) error {
	today := threatFeedUTCDay(now)
	quota, err := loadThreatFeedAutoQuota(ctx, db)
	if err != nil {
		return err
	}
	count := 1
	if quota.Day.Valid && threatFeedUTCDay(quota.Day.Time).Equal(today) {
		count = quota.Count + 1
	}
	_, err = db.ExecContext(ctx, `
UPDATE threat_feed_sync_state SET auto_sync_day = $1, auto_sync_count = $2
WHERE singleton = 'global'`, today, count)
	return err
}

// autoThreatFeedSyncPermitted reports whether the background poller may run another automatic sync.
func autoThreatFeedSyncPermitted(
	ctx context.Context,
	db *sql.DB,
	cfg threatfeed.Config,
	now time.Time,
) (ok bool, nextAt time.Time) {
	used := 0
	quota, err := loadThreatFeedAutoQuota(ctx, db)
	if err == nil {
		used = autoSyncsUsedToday(quota, now)
	}
	if used >= threatFeedMaxAutoSyncsPerDay {
		today := threatFeedUTCDay(now)
		nextAt = today.Add(24 * time.Hour)
		return false, nextAt
	}

	interval := time.Duration(effectiveThreatFeedPollIntervalSec(cfg)) * time.Second
	var lastOK sql.NullTime
	_ = db.QueryRowContext(ctx, `SELECT last_success_at FROM threat_feed_sync_state WHERE singleton = 'global'`).Scan(&lastOK)
	if lastOK.Valid {
		nextAt = lastOK.Time.Add(interval)
		if now.Before(nextAt) {
			return false, nextAt
		}
	}
	nextAt = now
	return true, nextAt
}
