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
	RuleID string `json:"rule_id"`
	Action string `json:"action"`
	Count  int64  `json:"count"`
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

	writeJSON(w, http.StatusOK, map[string]any{
		"period_hours":    hours,
		"since":           since.Format(time.RFC3339Nano),
		"by_host":         byHost,
		"by_method":       byMethod,
		"by_protocol":     byProtocol,
		"by_outcome":      byOutcome,
		"by_country":      byCountry,
		"top_waf_actions": topWAFActions,
		"top_waf_rules":   topWAFRules,
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
WHERE created_at >= $1 AND country_code <> ''
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
SELECT COALESCE(rule_id::text, ''), action, COUNT(*)::bigint AS c
FROM waf_logs
WHERE created_at >= $1
GROUP BY rule_id, action
ORDER BY c DESC
LIMIT 20`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wafRuleRow
	for rows.Next() {
		var w wafRuleRow
		if err := rows.Scan(&w.RuleID, &w.Action, &w.Count); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
