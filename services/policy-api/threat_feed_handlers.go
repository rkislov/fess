package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"fence/pkg/threatfeed"
)

type threatFeedResponse struct {
	threatfeed.Config
	APIKeySet bool `json:"api_key_set"`
}

type threatFeedStatusResponse struct {
	Enabled          bool   `json:"enabled"`
	Block            bool   `json:"block"`
	LastAttemptAtRFC string `json:"last_attempt_at,omitempty"`
	LastSuccessAtRFC string `json:"last_success_at,omitempty"`
	LastError        string `json:"last_error,omitempty"`
	RowsLastIngested int    `json:"rows_last_ingested"`
	IndicatorCount   int    `json:"indicator_count"`
}

func loadThreatFeedConfig(ctx context.Context, db *sql.DB) (threatfeed.Config, error) {
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT config FROM threat_feed_settings WHERE singleton = 'global'`).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return threatfeed.DefaultConfig(), nil
		}
		return threatfeed.Config{}, err
	}
	return threatfeed.ParseConfig(raw)
}

func getThreatFeedSettings(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadThreatFeedConfig(r.Context(), db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	keySet := cfg.APIKey != ""
	cfg.APIKey = maskSecret(cfg.APIKey)
	writeJSON(w, http.StatusOK, threatFeedResponse{Config: cfg, APIKeySet: keySet})
}

func putThreatFeedSettings(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	old, err := loadThreatFeedConfig(r.Context(), db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var incoming threatfeed.Config
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	mergeThreatFeedSecrets(&incoming, old)
	mergedJSON, err := json.Marshal(incoming)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	normalized, err := threatfeed.ParseConfig(mergedJSON)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if _, err := db.ExecContext(r.Context(), `
UPDATE threat_feed_settings SET config = $1::jsonb, updated_at = NOW() WHERE singleton = 'global'`, string(raw)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := rdb.Publish(r.Context(), "threat_feed_updated", `{"singleton":"global"}`).Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": true})
}

func mergeThreatFeedSecrets(in *threatfeed.Config, old threatfeed.Config) {
	if in.APIKey == "" || in.APIKey == "***" {
		in.APIKey = old.APIKey
	}
}

func getThreatFeedStatus(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadThreatFeedConfig(r.Context(), db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var lastAtt, lastOK sql.NullTime
	var lastErr sql.NullString
	var rowsIng int
	_ = db.QueryRowContext(r.Context(), `
SELECT last_attempt_at, last_success_at, last_error, rows_ingested
FROM threat_feed_sync_state WHERE singleton = 'global'`).Scan(&lastAtt, &lastOK, &lastErr, &rowsIng)

	var cnt int
	_ = db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM threat_feed_indicators`).Scan(&cnt)

	out := threatFeedStatusResponse{
		Enabled:          cfg.Enabled,
		Block:            cfg.Block,
		RowsLastIngested: rowsIng,
		IndicatorCount:   cnt,
	}
	if lastAtt.Valid {
		out.LastAttemptAtRFC = lastAtt.Time.UTC().Format(time.RFC3339Nano)
	}
	if lastOK.Valid {
		out.LastSuccessAtRFC = lastOK.Time.UTC().Format(time.RFC3339Nano)
	}
	if lastErr.Valid && strings.TrimSpace(lastErr.String) != "" {
		out.LastError = lastErr.String
	}
	writeJSON(w, http.StatusOK, out)
}

func postThreatFeedSync(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadThreatFeedConfig(r.Context(), db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	syncCtx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	switch err := syncThreatFeedFromConfig(syncCtx, db, cfg); err {
	case nil:
		if err := rdb.Publish(r.Context(), "threat_feed_updated", `{"singleton":"global"}`).Err(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case errThreatFeedMissingURL, errThreatFeedSkipped:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "feed_url is empty"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
}
