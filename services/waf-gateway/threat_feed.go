package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"fence/pkg/clientip"
	"fence/pkg/routing"
	"fence/pkg/threatfeed"

	"encoding/json"

	"time"

	"github.com/redis/go-redis/v9"
)

// threatFeedSnap is the hot-path snapshot built from Postgres + synced indicators.
type threatFeedSnap struct {
	GW     threatfeed.GatewayConfig
	M      *threatfeed.Matcher
	Hashes *threatfeed.HashSet
}

func (s threatFeedSnap) MatchThreat(clientHost string) (matched, block bool) {
	if !s.GW.Enabled || s.M == nil {
		return false, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(clientHost))
	if err != nil || !addr.IsValid() {
		return false, false
	}
	addr = addr.Unmap()
	if !s.M.Contains(addr) {
		return false, false
	}
	return true, s.GW.Block
}

// MatchFileHash checks request body against ThreatFox file-hash IOCs.
func (s threatFeedSnap) MatchFileHash(body []byte) (hash string, matched, block bool) {
	if !s.GW.Enabled || s.Hashes == nil {
		return "", false, false
	}
	h, ok := s.Hashes.MatchBody(body)
	if !ok {
		return "", false, false
	}
	return h, true, s.GW.Block
}

type threatFeedStore struct {
	v atomic.Value // threatFeedSnap
}

func newThreatFeedStore() *threatFeedStore {
	s := &threatFeedStore{}
	s.v.Store(threatFeedSnap{})
	return s
}

func (s *threatFeedStore) Current() threatFeedSnap {
	x := s.v.Load()
	if x == nil {
		return threatFeedSnap{}
	}
	return x.(threatFeedSnap)
}

func (s *threatFeedStore) Swap(snap threatFeedSnap) {
	s.v.Store(snap)
}

func reloadThreatFeed(db *sql.DB, store *threatFeedStore) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT config FROM threat_feed_settings WHERE singleton = 'global'`).Scan(&raw)
	if err != nil {
		log.Printf("threat feed: load config skipped: %v", err)
		store.Swap(threatFeedSnap{})
		return
	}
	cfg, err := threatfeed.ParseConfig(raw)
	if err != nil {
		log.Printf("threat feed: parse config: %v", err)
		store.Swap(threatFeedSnap{GW: cfg.Gateway()})
		return
	}

	rows, err := db.QueryContext(ctx, `SELECT indicator FROM threat_feed_indicators ORDER BY indicator`)
	if err != nil {
		log.Printf("threat feed: list indicators: %v", err)
		store.Swap(threatFeedSnap{GW: cfg.Gateway()})
		return
	}
	defer rows.Close()

	var entries []string
	for rows.Next() {
		var ind string
		if err := rows.Scan(&ind); err != nil {
			log.Printf("threat feed scan: %v", err)
			store.Swap(threatFeedSnap{GW: cfg.Gateway()})
			return
		}
		ind = strings.TrimSpace(ind)
		if ind != "" {
			entries = append(entries, ind)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("threat feed rows: %v", err)
		store.Swap(threatFeedSnap{GW: cfg.Gateway()})
		return
	}

	var m *threatfeed.Matcher
	if len(entries) > 0 {
		mat, err := threatfeed.NewMatcher(entries)
		if err != nil {
			log.Printf("threat feed: build matcher (%d indicators): %v", len(entries), err)
		} else {
			m = mat
		}
	}

	var hashes []string
	hrows, herr := db.QueryContext(ctx, `SELECT hash FROM threat_feed_file_hashes ORDER BY hash`)
	if herr != nil {
		log.Printf("threat feed: list file hashes: %v", herr)
	} else {
		defer hrows.Close()
		for hrows.Next() {
			var h string
			if err := hrows.Scan(&h); err != nil {
				log.Printf("threat feed hash scan: %v", err)
				break
			}
			h = strings.TrimSpace(h)
			if h != "" {
				hashes = append(hashes, h)
			}
		}
		_ = hrows.Err()
	}

	snap := threatFeedSnap{GW: cfg.Gateway(), M: m, Hashes: threatfeed.NewHashSet(hashes)}
	store.Swap(snap)
	nInd := 0
	if m != nil {
		nInd = m.Size()
	}
	log.Printf("threat feed reloaded enabled=%v block=%v ip_indicators=%d file_hashes=%d",
		snap.GW.Enabled, snap.GW.Block, nInd, snap.Hashes.Len())
}

func subscribeThreatFeedUpdates(db *sql.DB, rdb *redis.Client, store *threatFeedStore) {
	ctx := context.Background()
	sub := rdb.Subscribe(ctx, "threat_feed_updated")
	defer sub.Close()
	for msg := range sub.Channel() {
		log.Printf("threat feed event: %s", msg.Payload)
		reloadThreatFeed(db, store)
	}
}

func writeThreatFeedLog(ctx context.Context, db *sql.DB, r *http.Request, blocked bool, ipRes *clientip.Resolver) {
	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = "req-" + time.Now().Format(time.RFC3339Nano)
	}
	action := "threat_feed_log"
	if blocked {
		action = "threat_feed_block"
	}
	details, _ := json.Marshal(map[string]any{
		"source": "threat_feed",
		"detail": "client IP matched synced threat feed blocklist",
	})
	h := publicHostHeader(r, ipRes)
	srcIP := ipRes.ClientHost(r)
	if srcIP == "" {
		srcIP = r.RemoteAddr
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO waf_logs(request_id, policy_id, rule_id, action, source_ip, method, path, host, details)
VALUES ($1, NULL, NULL, $2, $3, $4, $5, $6, $7::jsonb)`,
		requestID, action, srcIP, r.Method, r.URL.Path, h, string(details))
	if err != nil {
		log.Printf("threat feed waf log: %v", err)
	}
}

// threatFeedGateResult is produced before the body is buffered; Caller sets proxy outcome from ProxyOutcomeHint when the request ends as proxied.
type threatFeedGateResult struct {
	Responded        bool   // true if gateway already sent HTTP response (e.g. 403)
	ProxyOutcomeHint string // e.g. "threat_feed_log" when matched, not blocked, logging enabled
}

func applyThreatFeedGate(
	w http.ResponseWriter,
	r *http.Request,
	db *sql.DB,
	mr routing.MatchResult,
	ipRes *clientip.Resolver,
	tf *threatFeedStore,
) threatFeedGateResult {
	clientHost := ipRes.ClientHost(r)
	if strings.TrimSpace(clientHost) == "" {
		clientHost = clientip.PeerHost(r)
	}
	snap := tf.Current()
	matched, doBlock := snap.MatchThreat(clientHost)
	if !matched {
		return threatFeedGateResult{}
	}
	if snap.GW.LogHits || doBlock {
		writeThreatFeedLog(r.Context(), db, r, doBlock, ipRes)
	}
	if doBlock {
		writeProxyAccessLog(r.Context(), db, r, mr, "threat_feed_block", ipRes)
		http.Error(w, "blocked by threat intelligence feed", http.StatusForbidden)
		return threatFeedGateResult{Responded: true}
	}
	if snap.GW.LogHits {
		return threatFeedGateResult{ProxyOutcomeHint: "threat_feed_log"}
	}
	return threatFeedGateResult{}
}
