package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"fence/pkg/botprotection"
	"fence/pkg/clientip"
	"fence/pkg/routing"
	"fence/pkg/threatfeed"

	"github.com/redis/go-redis/v9"
)

type botProtectionSnap struct {
	Cfg          botprotection.Config
	BlockedGeo   map[string]struct{}
	BlockedASN   map[uint]struct{}
	CIDRMatcher  *threatfeed.Matcher
	BlockedJA3   map[string]struct{}
}

type botProtectionStore struct {
	v atomic.Value // botProtectionSnap
}

func newBotProtectionStore() *botProtectionStore {
	s := &botProtectionStore{}
	s.v.Store(botProtectionSnap{})
	return s
}

func (s *botProtectionStore) Current() botProtectionSnap {
	x := s.v.Load()
	if x == nil {
		return botProtectionSnap{}
	}
	return x.(botProtectionSnap)
}

func (s *botProtectionStore) Swap(snap botProtectionSnap) {
	s.v.Store(snap)
}

func reloadBotProtection(db *sql.DB, store *botProtectionStore) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT config FROM bot_protection_settings WHERE singleton = 'global'`).Scan(&raw)
	if err != nil {
		log.Printf("bot protection: load config skipped: %v", err)
		store.Swap(botProtectionSnap{})
		return
	}
	cfg, err := botprotection.ParseConfig(raw)
	if err != nil {
		log.Printf("bot protection: parse config: %v", err)
		store.Swap(botProtectionSnap{Cfg: cfg})
		return
	}

	blockedASN := make(map[uint]struct{})
	if cfg.ASNBlock.Enabled {
		rows, err := db.QueryContext(ctx, `SELECT asn FROM bot_protection_asn`)
		if err != nil {
			log.Printf("bot protection: list asn: %v", err)
		} else {
			for rows.Next() {
				var n int64
				if err := rows.Scan(&n); err == nil && n > 0 {
					blockedASN[uint(n)] = struct{}{}
				}
			}
			rows.Close()
		}
	}

	var cidrMatcher *threatfeed.Matcher
	if cfg.CIDRBlock.Enabled {
		rows, err := db.QueryContext(ctx, `SELECT cidr FROM bot_protection_cidr ORDER BY cidr`)
		if err != nil {
			log.Printf("bot protection: list cidr: %v", err)
		} else {
			var list []string
			for rows.Next() {
				var c string
				if err := rows.Scan(&c); err == nil && strings.TrimSpace(c) != "" {
					list = append(list, c)
				}
			}
			rows.Close()
			if len(list) > 0 {
				m, err := threatfeed.NewMatcher(list)
				if err != nil {
					log.Printf("bot protection: cidr matcher: %v", err)
				} else {
					cidrMatcher = m
				}
			}
		}
	}

	snap := botProtectionSnap{
		Cfg:         cfg,
		BlockedGeo:  cfg.BlockedCountrySet(),
		BlockedASN:  blockedASN,
		CIDRMatcher: cidrMatcher,
		BlockedJA3:  cfg.BlockedJA3Set(),
	}
	store.Swap(snap)
	log.Printf("bot protection reloaded enabled=%v asn=%d cidr=%d geo=%d",
		cfg.Enabled, len(blockedASN), matcherSize(cidrMatcher), len(snap.BlockedGeo))
}

func matcherSize(m *threatfeed.Matcher) int {
	if m == nil {
		return 0
	}
	return m.Size()
}

func subscribeBotProtectionUpdates(db *sql.DB, rdb *redis.Client, store *botProtectionStore) {
	ctx := context.Background()
	sub := rdb.Subscribe(ctx, "bot_protection_updated")
	defer sub.Close()
	for msg := range sub.Channel() {
		log.Printf("bot protection event: %s", msg.Payload)
		reloadBotProtection(db, store)
	}
}

type botProtectionGateResult struct {
	Responded        bool
	ProxyOutcomeHint string
}

func applyBotProtectionGate(
	w http.ResponseWriter,
	r *http.Request,
	db *sql.DB,
	mr routing.MatchResult,
	ipRes *clientip.Resolver,
	store *botProtectionStore,
	rdb *redis.Client,
) botProtectionGateResult {
	snap := store.Current()
	if !snap.Cfg.Enabled {
		return botProtectionGateResult{}
	}

	clientHost := ipRes.ClientHost(r)
	if strings.TrimSpace(clientHost) == "" {
		clientHost = clientip.PeerHost(r)
	}
	// Challenge cookie bypass for subsequent requests.
	if snap.Cfg.Challenge.Enabled && botprotection.ChallengeValid(r, snap.Cfg.Challenge, clientHost) {
		if q := strings.TrimSpace(r.URL.Query().Get(botprotection.ChallengeQueryParam)); q != "" {
			botprotection.SetChallengeCookie(w, snap.Cfg.Challenge, clientHost, requestIsHTTPS(r))
			qv := r.URL.Query()
			qv.Del(botprotection.ChallengeQueryParam)
			r.URL.RawQuery = qv.Encode()
			target := r.URL.RequestURI()
			if target == "" {
				target = "/"
			}
			http.Redirect(w, r, target, http.StatusFound)
			return botProtectionGateResult{Responded: true}
		}
		return botProtectionGateResult{}
	}

	addr, addrErr := netip.ParseAddr(strings.TrimSpace(clientHost))
	if addrErr == nil {
		addr = addr.Unmap()
	}

	// Geo block
	if snap.BlockedGeo != nil {
		cc := countryCodeForRequest(r, clientHost)
		if cc != "" {
			if _, blocked := snap.BlockedGeo[cc]; blocked {
				return botFinish(w, r, db, mr, ipRes, snap, "geo_block", "blocked country "+cc, true, nil)
			}
		}
	}

	// Datacenter CIDR block
	if snap.CIDRMatcher != nil && addrErr == nil && snap.CIDRMatcher.Contains(addr) {
		return botFinish(w, r, db, mr, ipRes, snap, "bot_cidr_block", "client IP in datacenter CIDR blocklist", true, nil)
	}

	// ASN block (requires GeoLite2-ASN MMDB + uploaded ASN list)
	if snap.BlockedASN != nil && len(snap.BlockedASN) > 0 {
		if asnNum, org, ok := asnForIP(clientHost); ok {
			if _, blocked := snap.BlockedASN[asnNum]; blocked {
				detail := fmt.Sprintf("ASN %d", asnNum)
				if org != "" {
					detail += " (" + org + ")"
				}
				return botFinish(w, r, db, mr, ipRes, snap, "bot_asn_block", detail, true, nil)
			}
		}
	}

	// Rate limit is enforced globally (rate_limit_settings + backend/path overrides) before bot protection.

	// Behavioral score + TLS/JA3 + timing
	var inter time.Duration = -1
	if rdb != nil {
		inter = recordBotTiming(r.Context(), rdb, clientHost)
	}
	scoreIn := botprotection.CollectScoreInput(r, inter)
	if snap.BlockedJA3 != nil && scoreIn.JA3Header != "" {
		if _, ok := snap.BlockedJA3[strings.ToLower(scoreIn.JA3Header)]; ok {
			return botFinish(w, r, db, mr, ipRes, snap, "bot_ja3_block", "blocked JA3 hash", true, map[string]any{"ja3": scoreIn.JA3Header})
		}
	}
	score := botprotection.ComputeScore(snap.Cfg, scoreIn)

	action := "allow"
	detail := ""
	if snap.Cfg.Scoring.Enabled {
		if score.Score >= snap.Cfg.Scoring.BlockThreshold {
			action = "block"
			detail = fmt.Sprintf("score %d >= %d: %s", score.Score, snap.Cfg.Scoring.BlockThreshold, strings.Join(score.Reasons, "; "))
		} else if score.Score >= snap.Cfg.Scoring.ChallengeThreshold && snap.Cfg.Challenge.Enabled {
			action = "challenge"
			detail = fmt.Sprintf("score %d: %s", score.Score, strings.Join(score.Reasons, "; "))
		}
	}

	switch action {
	case "block":
		return botFinish(w, r, db, mr, ipRes, snap, "bot_score_block", detail, true, map[string]any{"score": score.Score, "reasons": score.Reasons})
	case "challenge":
		return botChallenge(w, r, db, mr, ipRes, snap, detail, score)
	default:
		if snap.Cfg.LogHits && score.Score > 0 {
			writeBotProtectionLog(r.Context(), db, r, "bot_score_log", false, ipRes, map[string]any{"score": score.Score, "reasons": score.Reasons})
			return botProtectionGateResult{ProxyOutcomeHint: "bot_score_log"}
		}
		return botProtectionGateResult{}
	}
}

func botFinish(
	w http.ResponseWriter,
	r *http.Request,
	db *sql.DB,
	mr routing.MatchResult,
	ipRes *clientip.Resolver,
	snap botProtectionSnap,
	outcome, detail string,
	blocked bool,
	extra map[string]any,
) botProtectionGateResult {
	if snap.Cfg.LogHits || blocked {
		d := map[string]any{"detail": detail}
		for k, v := range extra {
			d[k] = v
		}
		writeBotProtectionLog(r.Context(), db, r, outcome, blocked, ipRes, d)
	}
	if blocked {
		writeProxyAccessLog(r.Context(), db, r, mr, outcome, ipRes)
		writeFESSError(w, http.StatusForbidden, pageBlocked, "Похоже на бота", "Защита FESS отклонила этот запрос.")
		return botProtectionGateResult{Responded: true}
	}
	return botProtectionGateResult{ProxyOutcomeHint: outcome}
}

func botChallenge(
	w http.ResponseWriter,
	r *http.Request,
	db *sql.DB,
	mr routing.MatchResult,
	ipRes *clientip.Resolver,
	snap botProtectionSnap,
	detail string,
	score botprotection.ScoreResult,
) botProtectionGateResult {
	if strings.TrimSpace(snap.Cfg.Challenge.Secret) == "" {
		return botFinish(w, r, db, mr, ipRes, snap, "bot_score_block", detail+"; challenge secret not configured", true, map[string]any{"score": score.Score})
	}
	writeBotProtectionLog(r.Context(), db, r, "bot_challenge", false, ipRes, map[string]any{"score": score.Score, "detail": detail})
	writeProxyAccessLog(r.Context(), db, r, mr, "bot_challenge", ipRes)
	verifyURL := botprotection.BuildChallengeVerifyURL(r, snap.Cfg.Challenge, ipRes.ClientHost(r))
	writeFESSChallenge(w, verifyURL)
	return botProtectionGateResult{Responded: true}
}

func checkBotRateLimit(ctx context.Context, rdb *redis.Client, cfg botprotection.Config, clientIP, host, path string) (bool, string) {
	key := botRateLimitKey(cfg.RateLimit.Scope, clientIP, host, path)
	window := time.Duration(cfg.RateLimit.WindowSec) * time.Second
	if window <= 0 {
		window = time.Minute
	}
	limit := int64(cfg.RateLimit.RequestsPerWindow)
	if limit <= 0 {
		limit = 120
	}
	pipe := rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return true, ""
	}
	n, err := incr.Result()
	if err != nil {
		return true, ""
	}
	if n > limit {
		return false, fmt.Sprintf("rate limit %d/%d per %ds (%s)", n, limit, cfg.RateLimit.WindowSec, cfg.RateLimit.Scope)
	}
	return true, ""
}

func botRateLimitKey(scope, clientIP, host, path string) string {
	switch scope {
	case "ip":
		return "fence:bot:rl:ip:" + clientIP
	case "ip_path":
		return "fence:bot:rl:ipp:" + clientIP + ":" + host + ":" + path
	default:
		return "fence:bot:rl:iph:" + clientIP + ":" + host
	}
}

func recordBotTiming(ctx context.Context, rdb *redis.Client, clientIP string) time.Duration {
	key := "fence:bot:ts:" + clientIP
	now := time.Now().UnixMilli()
	prev, err := rdb.GetSet(ctx, key, now).Int64()
	_ = rdb.Expire(ctx, key, 2*time.Minute).Err()
	if err != nil || prev <= 0 {
		return -1
	}
	return time.Duration(now-prev) * time.Millisecond
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func writeBotProtectionLog(ctx context.Context, db *sql.DB, r *http.Request, action string, blocked bool, ipRes *clientip.Resolver, details map[string]any) {
	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = "req-" + time.Now().Format(time.RFC3339Nano)
	}
	if blocked && !strings.HasSuffix(action, "_block") {
		action = action + "_block"
	}
	details["source"] = "bot_protection"
	payload, _ := json.Marshal(details)
	h := publicHostHeader(r, ipRes)
	srcIP := ipRes.ClientHost(r)
	if srcIP == "" {
		srcIP = r.RemoteAddr
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO waf_logs(request_id, policy_id, rule_id, action, source_ip, method, path, host, details)
VALUES ($1, NULL, NULL, $2, $3, $4, $5, $6, $7::jsonb)`,
		requestID, action, srcIP, r.Method, r.URL.Path, h, string(payload))
	if err != nil {
		log.Printf("bot protection waf log: %v", err)
	}
}
