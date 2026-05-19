package main

import (
	"context"
	"database/sql"
	"log"
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
	ctx, cancel := context.WithTimeout(parent, 45*time.Minute)
	defer cancel()

	threatFeedPollerMu.Lock()
	defer threatFeedPollerMu.Unlock()

	cfg, err := loadThreatFeedConfig(ctx, db)
	if err != nil {
		log.Printf("threat feed: load config: %v", err)
		return
	}
	if !cfg.Enabled || !cfg.AutoSyncConfigured() {
		return
	}
	now := time.Now()
	if ok, _ := autoThreatFeedSyncPermitted(ctx, db, cfg, now); !ok {
		return
	}

	if err := syncThreatFeedFromConfigRouter(ctx, db, cfg); err != nil {
		log.Printf("threat feed poll: %v", err)
		return
	}
	if err := recordThreatFeedAutoSync(ctx, db, now); err != nil {
		log.Printf("threat feed auto sync quota: %v", err)
	}
	if err := rdb.Publish(ctx, "threat_feed_updated", `{"singleton":"global"}`).Err(); err != nil {
		log.Printf("threat feed publish: %v", err)
	}
}
