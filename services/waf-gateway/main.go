package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"fence/internal/bootstrap"
	"fence/pkg/engine"
	"fence/pkg/malware"
	"fence/pkg/policy"
	"fence/pkg/routing"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

func main() {
	target := getenv("UPSTREAM_URL", "http://localhost:8081")
	listen := getenv("WAF_LISTEN_ADDR", ":8080")
	pgDSN := getenv("POSTGRES_DSN", "postgres://fence:fence@localhost:5432/fence?sslmode=disable")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")
	failMode := getenv("WAF_FAIL_MODE", "open")

	upstream, err := url.Parse(target)
	if err != nil {
		log.Fatalf("invalid UPSTREAM_URL: %v", err)
	}
	db, err := sql.Open("postgres", pgDSN)
	if err != nil {
		log.Fatalf("open postgres: %v", err)
	}
	defer db.Close()

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := bootstrap.RetryUntil(waitCtx, "postgres", time.Second, func() error {
		return db.Ping()
	}); err != nil {
		log.Fatalf("postgres: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer rdb.Close()
	if err := bootstrap.RetryUntil(waitCtx, "redis", time.Second, func() error {
		return rdb.Ping(context.Background()).Err()
	}); err != nil {
		log.Fatalf("redis: %v", err)
	}

	initGeoIP(getenv("GEOIP_MMDB_PATH", ""))
	defer closeGeoIP()

	store := policy.NewStore()
	mwStore := newMalwareStore()
	evaluator := engine.NewEvaluator()

	routeStore := routing.NewStore(upstream)
	proxy := newDynamicReverseProxy(upstream, routeStore)
	reloadPolicySnapshot(db, store)
	reloadMalwareConfig(db, mwStore)
	reloadRoutingTable(db, upstream, routeStore)
	go subscribePolicyUpdates(db, rdb, store)
	go subscribeMalwareUpdates(db, rdb, mwStore)
	go subscribeRoutingUpdates(db, rdb, upstream, routeStore)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mcfg := mwStore.Current()
		maxRead := mcfg.BodyScan.MaxBytes
		if maxRead <= 0 {
			maxRead = 32 << 20
		}
		body, err := readRequestBody(r, maxRead)
		if err != nil {
			code := http.StatusBadRequest
			if strings.Contains(err.Error(), "exceeds max_bytes") {
				code = http.StatusRequestEntityTooLarge
			}
			http.Error(w, err.Error(), code)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		mr := routeStore.Current().Match(hostHeader(r))

		if mcfg.ShouldScanHTTPRequest(r.Method, r.Header.Get("Content-Type"), int64(len(body))) {
			v := malware.Scan(r.Context(), mcfg, r.Method, r.URL.RequestURI(), hostHeader(r), r.Header.Get("Content-Type"), body)
			if !v.Clean {
				writeMalwareLog(r.Context(), db, r, v)
				writeProxyAccessLog(r.Context(), db, r, mr, "malware_block")
				http.Error(w, "request blocked by malware scanner", http.StatusForbidden)
				return
			}
		}

		snapshot := store.Current()
		decision := evaluator.Evaluate(r, snapshot, mr.PolicyID)
		effectiveAction := decision.Action
		if decision.PolicyMode == "log" && (decision.Action == "block" || decision.Action == "redirect" || decision.Action == "replace") {
			effectiveAction = "log"
		}
		writeWAFLog(r.Context(), db, r, decision, effectiveAction)

		accessOutcome := "proxied"
		switch effectiveAction {
		case "block":
			accessOutcome = "waf_block"
		case "redirect":
			accessOutcome = "redirect"
		}
		writeProxyAccessLog(r.Context(), db, r, mr, accessOutcome)

		switch effectiveAction {
		case "block":
			http.Error(w, "blocked by WAF policy", http.StatusForbidden)
			return
		case "redirect":
			target := decision.RedirectURL
			if target == "" {
				target = "/"
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		case "replace":
			// Replace action mutates request body in evaluator pipeline in later milestones.
			proxy.ServeHTTP(w, r)
			return
		default:
			if decision.Action == "deny_on_error" && strings.EqualFold(failMode, "close") {
				http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			proxy.ServeHTTP(w, r)
		}
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           loggingMiddleware(handler),
		ReadHeaderTimeout: 3 * time.Second,
	}

	log.Printf("waf-gateway listening on %s -> %s", listen, target)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func reloadPolicySnapshot(db *sql.DB, store *policy.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	next, err := policy.LoadActiveSnapshot(ctx, db)
	if err != nil {
		log.Printf("policy reload failed: %v", err)
		return
	}
	next.Version = store.Current().Version + 1
	store.Swap(next)
	log.Printf("policy snapshot loaded version=%d policies=%d", next.Version, len(next.Policies))
}

func subscribePolicyUpdates(db *sql.DB, rdb *redis.Client, store *policy.Store) {
	ctx := context.Background()
	sub := rdb.Subscribe(ctx, "policy_updates")
	defer sub.Close()

	for msg := range sub.Channel() {
		log.Printf("received policy update event: %s", msg.Payload)
		reloadPolicySnapshot(db, store)
	}
}

func writeWAFLog(ctx context.Context, db *sql.DB, r *http.Request, decision engine.Decision, effectiveAction string) {
	if decision.RuleID == "" {
		return
	}
	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}

	details, _ := json.Marshal(map[string]any{
		"reason":         decision.Reason,
		"policy_mode":    decision.PolicyMode,
		"effective":      effectiveAction,
		"originalAction": decision.Action,
	})
	_, err := db.ExecContext(ctx, `
INSERT INTO waf_logs(request_id, policy_id, rule_id, action, source_ip, method, path, details)
VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, $7, $8::jsonb)`,
		requestID, decision.PolicyID, decision.RuleID, effectiveAction, r.RemoteAddr, r.Method, r.URL.Path, string(details))
	if err != nil {
		log.Printf("failed to write waf log: %v", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("method=%s path=%s remote=%s latency=%s", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
