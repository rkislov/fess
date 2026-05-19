package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"fence/pkg/ipbypass"
	"fence/pkg/threatfeed"
)

type ipBypassCreateRequest struct {
	CIDR           string `json:"cidr"`
	IP             string `json:"ip"`
	Comment        string `json:"comment"`
	TTLHours       int    `json:"ttl_hours"`
	SourceWafLogID int64  `json:"source_waf_log_id"`
}

func normalizeBypassCIDR(ipOrCIDR string) (string, error) {
	ipOrCIDR = strings.TrimSpace(ipOrCIDR)
	if ipOrCIDR == "" {
		return "", errors.New("ip or cidr is required")
	}
	inds := threatfeed.ValidIPCIDR([]string{ipOrCIDR})
	if len(inds) == 0 {
		return "", fmt.Errorf("invalid IP or CIDR: %q", ipOrCIDR)
	}
	return inds[0], nil
}

func upsertIPBypass(ctx context.Context, db *sql.DB, cidr, comment string, sourceID int64, ttlHours int) error {
	cidr, err := normalizeBypassCIDR(cidr)
	if err != nil {
		return err
	}
	var exp sql.NullTime
	if ttlHours > 0 {
		t := time.Now().UTC().Add(time.Duration(ttlHours) * time.Hour)
		exp = sql.NullTime{Time: t, Valid: true}
	} else if ttlHours < 0 {
		return fmt.Errorf("ttl_hours must be >= 0")
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO ip_bypass(cidr, comment, source_waf_log_id, expires_at)
VALUES ($1, $2, NULLIF($3::bigint, 0), $4)
ON CONFLICT (cidr) DO UPDATE SET
  comment = EXCLUDED.comment,
  source_waf_log_id = COALESCE(EXCLUDED.source_waf_log_id, ip_bypass.source_waf_log_id),
  expires_at = EXCLUDED.expires_at`, cidr, strings.TrimSpace(comment), sourceID, exp)
	return err
}

func ipInThreatFeed(ctx context.Context, db *sql.DB, clientIP string) (bool, string, error) {
	norm, err := normalizeBypassCIDR(clientIP)
	if err != nil {
		return false, "", err
	}
	rows, err := db.QueryContext(ctx, `SELECT indicator FROM threat_feed_indicators`)
	if err != nil {
		return false, "", err
	}
	defer rows.Close()
	var list []string
	for rows.Next() {
		var ind string
		if err := rows.Scan(&ind); err != nil {
			return false, "", err
		}
		list = append(list, ind)
	}
	if err := rows.Err(); err != nil {
		return false, "", err
	}
	if len(list) == 0 {
		return false, "", nil
	}
	m, err := threatfeed.NewMatcher(list)
	if err != nil {
		return false, "", err
	}
	addr, err := netip.ParseAddr(norm)
	if err != nil || !m.Contains(addr.Unmap()) {
		return false, "", nil
	}
	return true, norm, nil
}

func removeIPFromThreatFeed(ctx context.Context, db *sql.DB, clientIP string) (bool, error) {
	norm, err := normalizeBypassCIDR(clientIP)
	if err != nil {
		return false, err
	}
	res, err := db.ExecContext(ctx, `DELETE FROM threat_feed_indicators WHERE indicator = $1`, norm)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func loadIPBypassEntries(ctx context.Context, db *sql.DB) ([]ipbypass.Entry, error) {
	rows, err := db.QueryContext(ctx, `SELECT cidr, expires_at FROM ip_bypass ORDER BY cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []ipbypass.Entry
	for rows.Next() {
		var cidr string
		var exp sql.NullTime
		if err := rows.Scan(&cidr, &exp); err != nil {
			return nil, err
		}
		var expPtr *time.Time
		if exp.Valid {
			t := exp.Time.UTC()
			expPtr = &t
		}
		entries = append(entries, ipbypass.Entry{CIDR: cidr, ExpiresAt: expPtr})
	}
	return entries, rows.Err()
}

func ipBypassActive(ctx context.Context, db *sql.DB, clientIP string) (bool, string, error) {
	entries, err := loadIPBypassEntries(ctx, db)
	if err != nil {
		return false, "", err
	}
	m, err := ipbypass.NewMatcher(entries, time.Now().UTC())
	if err != nil {
		return false, "", err
	}
	if !m.Contains(clientIP) {
		return false, "", nil
	}
	cidr, _ := normalizeBypassCIDR(clientIP)
	return true, cidr, nil
}

func wafLogEventUnblockHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, eventID int64) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RemoveFromThreatFeed bool `json:"remove_from_threat_feed"`
		TTLHours             int  `json:"ttl_hours"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	ctx := r.Context()
	var action, sourceIP string
	err := db.QueryRowContext(ctx, `SELECT action, source_ip FROM waf_logs WHERE id = $1`, eventID).Scan(&action, &sourceIP)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sourceIP = strings.TrimSpace(sourceIP)
	if sourceIP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event has no source_ip"})
		return
	}

	comment := fmt.Sprintf("unblock from waf-log event #%d (%s)", eventID, action)
	if err := upsertIPBypass(ctx, db, sourceIP, comment, eventID, req.TTLHours); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	removedFromFeed := false
	if req.RemoveFromThreatFeed {
		ok, err := removeIPFromThreatFeed(ctx, db, sourceIP)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		removedFromFeed = ok
	}

	if rdb != nil && strings.HasPrefix(action, "bot_") {
		ipbypass.ClearBotRateLimitKeys(ctx, rdb, sourceIP)
	}

	if err := rdb.Publish(ctx, "ip_bypass_updated", `{"source":"waf_log_unblock"}`).Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if removedFromFeed {
		_ = rdb.Publish(ctx, "threat_feed_updated", `{"source":"unblock"}`).Err()
	}

	cidr, _ := normalizeBypassCIDR(sourceIP)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                     true,
		"bypass_cidr":            cidr,
		"ttl_hours":              req.TTLHours,
		"removed_from_threat_feed": removedFromFeed,
		"cleared_bot_rate_limit": strings.HasPrefix(action, "bot_"),
	})
}

type ipBypassListItem struct {
	CIDR           string  `json:"cidr"`
	Comment        string  `json:"comment"`
	SourceWafLogID *int64  `json:"source_waf_log_id,omitempty"`
	ExpiresAt      *string `json:"expires_at,omitempty"`
	CreatedAt      string  `json:"created_at"`
	Scopes         []string `json:"scopes"`
}

func listIPBypass(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	rows, err := db.QueryContext(r.Context(), `
SELECT cidr, comment, source_waf_log_id, expires_at, created_at
FROM ip_bypass
ORDER BY created_at DESC`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	var items []ipBypassListItem
	for rows.Next() {
		var cidr, comment string
		var src sql.NullInt64
		var exp sql.NullTime
		var created time.Time
		if err := rows.Scan(&cidr, &comment, &src, &exp, &created); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		it := ipBypassListItem{
			CIDR:      cidr,
			Comment:   comment,
			CreatedAt: created.UTC().Format(time.RFC3339Nano),
			Scopes:    []string{"WAF", "Threat feed", "Боты", "Rate limit"},
		}
		if src.Valid {
			v := src.Int64
			it.SourceWafLogID = &v
		}
		if exp.Valid {
			s := exp.Time.UTC().Format(time.RFC3339Nano)
			it.ExpiresAt = &s
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if items == nil {
		items = []ipBypassListItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func deleteIPBypass(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	norm, err := normalizeBypassCIDR(req.CIDR)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	res, err := db.ExecContext(r.Context(), `DELETE FROM ip_bypass WHERE cidr = $1`, norm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err := rdb.Publish(r.Context(), "ip_bypass_updated", `{"source":"delete"}`).Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cidr": norm})
}

func ipBypassHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	switch r.Method {
	case http.MethodGet:
		listIPBypass(w, r, db)
	case http.MethodPost:
		postIPBypass(w, r, db, rdb)
	case http.MethodDelete:
		deleteIPBypass(w, r, db, rdb)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func postIPBypass(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	var req ipBypassCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	cidr := strings.TrimSpace(req.CIDR)
	if cidr == "" {
		cidr = strings.TrimSpace(req.IP)
	}
	ttl := req.TTLHours
	if ttl <= 0 {
		ttl = 24 * 7
	}
	if err := upsertIPBypass(r.Context(), db, cidr, req.Comment, req.SourceWafLogID, ttl); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := rdb.Publish(r.Context(), "ip_bypass_updated", `{}`).Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	norm, _ := normalizeBypassCIDR(cidr)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cidr": norm})
}
