package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"fence/pkg/clientip"
	"fence/pkg/ratelimit"
	"fence/pkg/routing"

	"github.com/redis/go-redis/v9"
)

type rateLimitStore struct {
	v atomic.Value // ratelimit.Config
}

func newRateLimitStore() *rateLimitStore {
	s := &rateLimitStore{}
	s.v.Store(ratelimit.DefaultConfig())
	return s
}

func (s *rateLimitStore) Global() ratelimit.Config {
	x := s.v.Load()
	if x == nil {
		return ratelimit.DefaultConfig()
	}
	return x.(ratelimit.Config)
}

func (s *rateLimitStore) Swap(cfg ratelimit.Config) {
	s.v.Store(ratelimit.NormalizeConfig(cfg))
}

func reloadRateLimitSettings(db *sql.DB, store *rateLimitStore) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT config FROM rate_limit_settings WHERE singleton = 'global'`).Scan(&raw)
	if err != nil {
		log.Printf("rate limit: load skipped: %v", err)
		store.Swap(ratelimit.DefaultConfig())
		return
	}
	cfg, err := ratelimit.ParseConfig(raw)
	if err != nil {
		log.Printf("rate limit: parse: %v", err)
		return
	}
	store.Swap(cfg)
	log.Printf("rate limit reloaded enabled=%v %d/%ds scope=%s",
		cfg.Enabled, cfg.RequestsPerWindow, cfg.WindowSec, cfg.Scope)
}

func subscribeRateLimitUpdates(db *sql.DB, rdb *redis.Client, store *rateLimitStore) {
	ctx := context.Background()
	sub := rdb.Subscribe(ctx, "rate_limit_updated")
	defer sub.Close()
	for msg := range sub.Channel() {
		log.Printf("rate limit event: %s", msg.Payload)
		reloadRateLimitSettings(db, store)
	}
}

type rateLimitGateResult struct {
	Responded        bool
	ProxyOutcomeHint string
}

func applyRateLimitGate(
	w http.ResponseWriter,
	r *http.Request,
	db *sql.DB,
	mr routing.MatchResult,
	ipRes *clientip.Resolver,
	global ratelimit.Config,
	rdb *redis.Client,
) rateLimitGateResult {
	cfg := ratelimit.Resolve(global, mr.BackendRateOverride, mr.PathRateOverride)
	if !cfg.Enabled {
		return rateLimitGateResult{}
	}
	clientHost := ipRes.ClientHost(r)
	if strings.TrimSpace(clientHost) == "" {
		clientHost = clientip.PeerHost(r)
	}
	host := publicHostHeader(r, ipRes)
	path := r.URL.Path
	allowed, detail := ratelimit.Check(r.Context(), rdb, cfg, clientHost, host, path, mr.BackendName)
	if allowed {
		return rateLimitGateResult{}
	}
	writeRateLimitLog(r.Context(), db, r, mr, ipRes, detail, cfg)
	writeProxyAccessLog(r.Context(), db, r, mr, "rate_limit", ipRes)
	writeFESSError(w, http.StatusTooManyRequests, pageError, "Слишком много запросов", "Сработал rate limit FESS. Подождите и повторите попытку.")
	return rateLimitGateResult{Responded: true}
}

func writeRateLimitLog(ctx context.Context, db *sql.DB, r *http.Request, mr routing.MatchResult, ipRes *clientip.Resolver, detail string, cfg ratelimit.Config) {
	if db == nil {
		return
	}
	details := map[string]any{
		"detail": detail,
		"source": "rate_limit",
		"scope":  cfg.Scope,
		"limit":  cfg.RequestsPerWindow,
		"window_sec": cfg.WindowSec,
	}
	if mr.BackendName != "" {
		details["backend"] = mr.BackendName
	}
	if mr.MatchedPathPrefix != "" {
		details["path_prefix"] = mr.MatchedPathPrefix
	}
	raw, _ := json.Marshal(details)
	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	_, _ = db.ExecContext(ctx, `
INSERT INTO waf_logs(request_id, policy_id, rule_id, action, source_ip, method, path, host, details)
VALUES ($1, NULL, NULL, $2, $3, $4, $5, $6, $7::jsonb)`,
		requestID, "rate_limit", ipRes.ClientHost(r), r.Method, r.URL.Path, publicHostHeader(r, ipRes), string(raw))
}
