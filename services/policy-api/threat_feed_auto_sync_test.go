package main

import (
	"database/sql"
	"testing"
	"time"

	"fence/pkg/threatfeed"
)

func TestAutoSyncsUsedTodayResetsOnNewDay(t *testing.T) {
	yesterday := time.Now().UTC().Add(-25 * time.Hour)
	quota := threatFeedAutoQuota{
		Day:   sql.NullTime{Time: yesterday, Valid: true},
		Count: 2,
	}
	if got := autoSyncsUsedToday(quota, time.Now()); got != 0 {
		t.Fatalf("expected 0 used today, got %d", got)
	}
}

func TestAutoSyncsUsedTodaySameDay(t *testing.T) {
	now := time.Now()
	quota := threatFeedAutoQuota{
		Day:   sql.NullTime{Time: now, Valid: true},
		Count: 1,
	}
	if got := autoSyncsUsedToday(quota, now); got != 1 {
		t.Fatalf("got %d", got)
	}
}

func TestEffectiveThreatFeedPollIntervalMin12h(t *testing.T) {
	cfg := threatfeed.Config{PollIntervalSec: 60}
	if got := effectiveThreatFeedPollIntervalSec(cfg); got != threatFeedMinAutoPollIntervalSec {
		t.Fatalf("got %d want %d", got, threatFeedMinAutoPollIntervalSec)
	}
}
