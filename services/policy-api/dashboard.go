package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"fence/pkg/countrycentroid"
)

type countRow struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type hostRow struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

type countryPoint struct {
	CountryCode string  `json:"country_code"`
	Count       int64   `json:"count"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

type wafActionRow struct {
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

type wafRuleRow struct {
	RuleID     string `json:"rule_id"`
	RuleName   string `json:"rule_name"`
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Action     string `json:"action"`
	Count      int64  `json:"count"`
	LastHitAt  string `json:"last_hit_at"`
}

type rpsPoint struct {
	BucketStartRFC3339 string  `json:"bucket_start"`
	BucketSeconds      float64 `json:"bucket_seconds"`
	Count              int64   `json:"count"`
	RPS                float64 `json:"rps"`
}

var rpsBinOrigin = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

func rpsStrideForHours(hours int) (stride time.Duration, intervalSQL string) {
	switch {
	case hours <= 6:
		return time.Minute, "1 minute"
	case hours <= 24:
		return 5 * time.Minute, "5 minutes"
	case hours <= 72:
		return 15 * time.Minute, "15 minutes"
	default:
		return time.Hour, "1 hour"
	}
}

func alignBinDown(t time.Time, stride time.Duration) time.Time {
	if stride <= 0 {
		return t.UTC()
	}
	t = t.UTC()
	nano := t.Sub(rpsBinOrigin).Nanoseconds()
	step := stride.Nanoseconds()
	q := nano / step
	if nano < 0 {
		q--
	}
	return rpsBinOrigin.Add(time.Duration(q * step))
}

func queryRPSSeries(ctx context.Context, db *sql.DB, since time.Time, hours int) ([]rpsPoint, float64, string, error) {
	stride, intervalSQL := rpsStrideForHours(hours)
	rows, err := db.QueryContext(ctx, `
SELECT date_bin($2::interval, created_at, TIMESTAMPTZ '2000-01-01') AS b, COUNT(*)::bigint AS c
FROM proxy_access_logs
WHERE created_at >= $1
GROUP BY b
ORDER BY b`, since, intervalSQL)
	if err != nil {
		return nil, 0, "", err
	}
	defer rows.Close()

	counts := make(map[int64]int64)
	for rows.Next() {
		var b time.Time
		var c int64
		if err := rows.Scan(&b, &c); err != nil {
			return nil, 0, "", err
		}
		b = alignBinDown(b.UTC(), stride)
		counts[b.Unix()] = c
	}
	if err := rows.Err(); err != nil {
		return nil, 0, "", err
	}

	now := time.Now().UTC()
	start := alignBinDown(since.UTC(), stride)
	end := alignBinDown(now, stride)
	sec := stride.Seconds()
	if start.After(end) {
		return []rpsPoint{}, sec, intervalSQL, nil
	}
	var out []rpsPoint
	for t := start; !t.After(end); t = t.Add(stride) {
		c := counts[t.Unix()]
		rps := float64(c) / sec
		out = append(out, rpsPoint{
			BucketStartRFC3339: t.Format(time.RFC3339),
			BucketSeconds:      sec,
			Count:              c,
			RPS:                rps,
		})
	}
	return out, sec, intervalSQL, nil
}

func dashboardSummaryHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)

	ctx := r.Context()

	byHost, err := queryHostCounts(ctx, db, since)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	byMethod, err := querySimpleCounts(ctx, db, since, "method")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	byProtocol, err := querySimpleCounts(ctx, db, since, "protocol")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	byOutcome, err := querySimpleCounts(ctx, db, since, "outcome")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	byCountry, err := queryCountryCounts(ctx, db, since)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	byUserAgent, err := querySimpleCounts(ctx, db, since, "user_agent")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	topWAFActions, err := queryWAFActions(ctx, db, since)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	topWAFRules, err := queryWAFRules(ctx, db, since)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rpsSeries, bucketSec, bucketLabel, err := queryRPSSeries(ctx, db, since, hours)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"period_hours":        hours,
		"since":               since.Format(time.RFC3339Nano),
		"by_host":             byHost,
		"by_method":           byMethod,
		"by_protocol":         byProtocol,
		"by_outcome":          byOutcome,
		"by_country":          byCountry,
		"by_user_agent":       byUserAgent,
		"top_waf_actions":     topWAFActions,
		"top_waf_rules":       topWAFRules,
		"rps_series":          rpsSeries,
		"rps_bucket_seconds":  bucketSec,
		"rps_bucket_interval": bucketLabel,
	})
}

func queryHostCounts(ctx context.Context, db *sql.DB, since time.Time) ([]hostRow, error) {
	rows, err := db.QueryContext(ctx, `
SELECT host, COUNT(*)::bigint AS c
FROM proxy_access_logs
WHERE created_at >= $1
GROUP BY host
ORDER BY c DESC
LIMIT 25`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []hostRow
	for rows.Next() {
		var h hostRow
		if err := rows.Scan(&h.Host, &h.Count); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func querySimpleCounts(ctx context.Context, db *sql.DB, since time.Time, column string) ([]countRow, error) {
	var q string
	switch column {
	case "method":
		q = `SELECT method, COUNT(*)::bigint AS c FROM proxy_access_logs WHERE created_at >= $1 GROUP BY method ORDER BY c DESC LIMIT 20`
	case "protocol":
		q = `SELECT protocol, COUNT(*)::bigint AS c FROM proxy_access_logs WHERE created_at >= $1 GROUP BY protocol ORDER BY c DESC LIMIT 20`
	case "outcome":
		q = `SELECT outcome, COUNT(*)::bigint AS c FROM proxy_access_logs WHERE created_at >= $1 GROUP BY outcome ORDER BY c DESC LIMIT 20`
	case "user_agent":
		q = `SELECT user_agent, COUNT(*)::bigint AS c FROM proxy_access_logs WHERE created_at >= $1 AND user_agent <> '' GROUP BY user_agent ORDER BY c DESC LIMIT 20`
	default:
		return nil, fmt.Errorf("unknown aggregate column %q", column)
	}
	rows, err := db.QueryContext(ctx, q, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []countRow
	for rows.Next() {
		var r0 countRow
		if err := rows.Scan(&r0.Key, &r0.Count); err != nil {
			return nil, err
		}
		out = append(out, r0)
	}
	return out, rows.Err()
}

func queryCountryCounts(ctx context.Context, db *sql.DB, since time.Time) ([]countryPoint, error) {
	rows, err := db.QueryContext(ctx, `
SELECT country_code, COUNT(*)::bigint AS c
FROM proxy_access_logs
WHERE created_at >= $1
GROUP BY country_code
ORDER BY c DESC
LIMIT 40`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []countryPoint
	for rows.Next() {
		var code string
		var c int64
		if err := rows.Scan(&code, &c); err != nil {
			return nil, err
		}
		lat, lon, ok := countrycentroid.LatLon(code)
		if !ok {
			out = append(out, countryPoint{CountryCode: code, Count: c, Lat: 0, Lon: 0})
			continue
		}
		out = append(out, countryPoint{CountryCode: code, Count: c, Lat: lat, Lon: lon})
	}
	return out, rows.Err()
}

func queryWAFActions(ctx context.Context, db *sql.DB, since time.Time) ([]wafActionRow, error) {
	rows, err := db.QueryContext(ctx, `
SELECT action, COUNT(*)::bigint AS c
FROM waf_logs
WHERE created_at >= $1
GROUP BY action
ORDER BY c DESC
LIMIT 15`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wafActionRow
	for rows.Next() {
		var w wafActionRow
		if err := rows.Scan(&w.Action, &w.Count); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func queryWAFRules(ctx context.Context, db *sql.DB, since time.Time) ([]wafRuleRow, error) {
	rows, err := db.QueryContext(ctx, `
SELECT COALESCE(MAX(wl.rule_id::text), '') AS rule_id,
       wl.action,
       COUNT(*)::bigint AS c,
       MAX(wl.created_at) AS last_at,
       MAX(COALESCE(r.name, '')) AS rule_name,
       COALESCE(MAX(wl.policy_id::text), '') AS policy_id,
       MAX(COALESCE(p.name, '')) AS policy_name
FROM waf_logs wl
LEFT JOIN rules r ON r.id = wl.rule_id
LEFT JOIN policies p ON p.id = wl.policy_id
WHERE wl.created_at >= $1 AND wl.rule_id IS NOT NULL
GROUP BY wl.rule_id, wl.action
ORDER BY c DESC
LIMIT 10`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wafRuleRow
	for rows.Next() {
		var w wafRuleRow
		var last time.Time
		if err := rows.Scan(&w.RuleID, &w.Action, &w.Count, &last, &w.RuleName, &w.PolicyID, &w.PolicyName); err != nil {
			return nil, err
		}
		w.LastHitAt = last.UTC().Format(time.RFC3339Nano)
		out = append(out, w)
	}
	return out, rows.Err()
}
