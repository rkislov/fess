package main

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var threatFeedPollerMu sync.Mutex

func runThreatFeedPoller(ctx context.Context, db *sql.DB, rdb *redis.Client) {
	go func() {
		ticker := time.NewTicker(45 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tickThreatFeedPoll(ctx, db, rdb)
			}
		}
	}()
}

func tickThreatFeedPoll(parent context.Context, db *sql.DB, rdb *redis.Client) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()

	threatFeedPollerMu.Lock()
	defer threatFeedPollerMu.Unlock()

	cfg, err := loadThreatFeedConfig(ctx, db)
	if err != nil {
		log.Printf("threat feed: load config: %v", err)
		return
	}
	if !cfg.Enabled || strings.TrimSpace(cfg.FeedURL) == "" {
		return
	}
	interval := cfg.PollIntervalSec
	if interval < 120 {
		interval = 120
	}

	var lastOK sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT last_success_at FROM threat_feed_sync_state WHERE singleton = 'global'`).Scan(&lastOK); err != nil {
		log.Printf("threat feed: read sync state: %v", err)
	}
	if lastOK.Valid {
		next := lastOK.Time.Add(time.Duration(interval) * time.Second)
		if time.Now().Before(next) {
			return
		}
	}

	if err := syncThreatFeedFromConfig(ctx, db, cfg); err != nil {
		log.Printf("threat feed poll: %v", err)
		return
	}
	if err := rdb.Publish(ctx, "threat_feed_updated", `{"singleton":"global"}`).Err(); err != nil {
		log.Printf("threat feed publish: %v", err)
	}
}
