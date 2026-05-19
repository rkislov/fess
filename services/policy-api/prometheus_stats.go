package main

import (
	"context"
	"database/sql"
	"log"
	"time"

	"fence/pkg/prommetrics"
)

func runPrometheusDBCollector(ctx context.Context, db *sql.DB) {
	interval := 30 * time.Second
	if v := getenv("FENCE_METRICS_DB_INTERVAL", ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 5*time.Second {
			interval = d
		}
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	collectPrometheusDBStats(ctx, db)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			collectPrometheusDBStats(ctx, db)
		}
	}
}

func collectPrometheusDBStats(ctx context.Context, db *sql.DB) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	tables := []string{"proxy_access_logs", "waf_logs", "malware_scan_logs", "audit_logs", "users"}
	for _, t := range tables {
		var n int64
		q := "SELECT COUNT(*)::bigint FROM " + t
		if err := db.QueryRowContext(cctx, q).Scan(&n); err != nil {
			log.Printf("prometheus db stats %s: %v", t, err)
			continue
		}
		prommetrics.DBRowsTotal.WithLabelValues(t).Set(float64(n))
	}

	type streamQuery struct {
		stream string
		query  string
	}
	streams := []streamQuery{
		{"proxy_access", `SELECT COUNT(*)::bigint FROM proxy_access_logs WHERE created_at >= NOW() - INTERVAL '1 hour'`},
		{"waf_hits", `SELECT COUNT(*)::bigint FROM waf_logs WHERE created_at >= NOW() - INTERVAL '1 hour'`},
		{"malware_scans", `SELECT COUNT(*)::bigint FROM malware_scan_logs WHERE created_at >= NOW() - INTERVAL '1 hour' AND scan_result IS DISTINCT FROM 'skipped'`},
		{"waf_blocks", `SELECT COUNT(*)::bigint FROM proxy_access_logs WHERE created_at >= NOW() - INTERVAL '1 hour' AND outcome NOT IN ('proxied', 'proxied_static')`},
	}
	for _, s := range streams {
		var n int64
		if err := db.QueryRowContext(cctx, s.query).Scan(&n); err != nil {
			log.Printf("prometheus stream %s: %v", s.stream, err)
			continue
		}
		prommetrics.DBEventsLastHour.WithLabelValues(s.stream).Set(float64(n))
	}
}
