package main

import (
	"context"
	"database/sql"
	"log"
	"sync/atomic"
	"time"

	"fence/pkg/ipbypass"

	"github.com/redis/go-redis/v9"
)

type ipBypassStore struct {
	v atomic.Value // *ipbypass.Matcher
}

func newIPBypassStore() *ipBypassStore {
	s := &ipBypassStore{}
	s.v.Store((*ipbypass.Matcher)(nil))
	return s
}

func (s *ipBypassStore) Current() *ipbypass.Matcher {
	x := s.v.Load()
	if x == nil {
		return nil
	}
	return x.(*ipbypass.Matcher)
}

func (s *ipBypassStore) Swap(m *ipbypass.Matcher) {
	s.v.Store(m)
}

func clientIPBypassed(store *ipBypassStore, clientHost string) bool {
	m := store.Current()
	if m == nil {
		return false
	}
	return m.Contains(clientHost)
}

func reloadIPBypass(db *sql.DB, store *ipBypassStore) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
SELECT cidr, expires_at FROM ip_bypass ORDER BY cidr`)
	if err != nil {
		log.Printf("ip bypass: load: %v", err)
		store.Swap(nil)
		return
	}
	defer rows.Close()

	now := time.Now().UTC()
	var entries []ipbypass.Entry
	for rows.Next() {
		var cidr string
		var exp sql.NullTime
		if err := rows.Scan(&cidr, &exp); err != nil {
			log.Printf("ip bypass scan: %v", err)
			continue
		}
		var expPtr *time.Time
		if exp.Valid {
			t := exp.Time.UTC()
			expPtr = &t
		}
		entries = append(entries, ipbypass.Entry{CIDR: cidr, ExpiresAt: expPtr})
	}
	if err := rows.Err(); err != nil {
		log.Printf("ip bypass rows: %v", err)
		store.Swap(nil)
		return
	}

	m, err := ipbypass.NewMatcher(entries, now)
	if err != nil {
		log.Printf("ip bypass matcher: %v", err)
		store.Swap(nil)
		return
	}
	store.Swap(m)
	log.Printf("ip bypass reloaded entries=%d", m.Size())
}

func subscribeIPBypassUpdates(db *sql.DB, rdb *redis.Client, store *ipBypassStore) {
	ctx := context.Background()
	sub := rdb.Subscribe(ctx, "ip_bypass_updated")
	defer sub.Close()
	for msg := range sub.Channel() {
		log.Printf("ip bypass event: %s", msg.Payload)
		reloadIPBypass(db, store)
	}
}

func clearBotRateLimitForIP(ctx context.Context, rdb *redis.Client, clientIP string) {
	ipbypass.ClearBotRateLimitKeys(ctx, rdb, clientIP)
}
