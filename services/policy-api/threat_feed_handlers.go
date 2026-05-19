package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
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
	Provider         string `json:"provider,omitempty"`
	ThreatFoxReady   bool   `json:"threatfox_ready"`
	LastAttemptAtRFC string `json:"last_attempt_at,omitempty"`
	LastSuccessAtRFC string `json:"last_success_at,omitempty"`
	LastError        string `json:"last_error,omitempty"`
	RowsLastIngested int    `json:"rows_last_ingested"`
	IndicatorCount   int    `json:"indicator_count"`
	AutoSyncsToday   int    `json:"auto_syncs_today"`
	AutoSyncLimit    int    `json:"auto_sync_limit"`
	NextAutoSyncAt   string `json:"next_auto_sync_at,omitempty"`
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

	now := time.Now()
	quota, _ := loadThreatFeedAutoQuota(r.Context(), db)
	usedToday := autoSyncsUsedToday(quota, now)
	_, nextAuto := autoThreatFeedSyncPermitted(r.Context(), db, cfg, now)

	out := threatFeedStatusResponse{
		Enabled:          cfg.Enabled,
		Block:            cfg.Block,
		Provider:         cfg.Provider,
		ThreatFoxReady:   cfg.UsesThreatFox() && strings.TrimSpace(cfg.APIKey) != "",
		RowsLastIngested: rowsIng,
		IndicatorCount:   cnt,
		AutoSyncsToday:   usedToday,
		AutoSyncLimit:    threatFeedMaxAutoSyncsPerDay,
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
	if cfg.AutoSyncConfigured() && cfg.Enabled {
		if usedToday >= threatFeedMaxAutoSyncsPerDay {
			nextAuto = threatFeedUTCDay(now).Add(24 * time.Hour)
		}
		if !nextAuto.IsZero() && nextAuto.After(now) {
			out.NextAutoSyncAt = nextAuto.UTC().Format(time.RFC3339Nano)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func postThreatFeedUpload(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(threatFeedMaxPageBytes + (1 << 20)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "multipart parse failed: " + err.Error()})
		return
	}
	fh, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing form field \"file\""})
		return
	}
	defer fh.Close()
	body, err := io.ReadAll(io.LimitReader(fh, threatFeedMaxPageBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(body) > threatFeedMaxPageBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file exceeds max size (64 MiB)"})
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file is empty"})
		return
	}

	syncCtx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	n, err := ingestThreatFeedTXT(syncCtx, db, body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": sanitizeThreatFeedError(err.Error())})
		return
	}
	if err := rdb.Publish(r.Context(), "threat_feed_updated", `{"singleton":"global"}`).Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rows_ingested": n})
}

// postThreatFeedSync runs on-demand incremental sync (ThreatFox API or URL feed).
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
	switch err := syncThreatFeedFromConfigRouter(syncCtx, db, cfg); err {
	case nil:
		if err := rdb.Publish(r.Context(), "threat_feed_updated", `{"singleton":"global"}`).Err(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case errThreatFeedMissingURL:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "feed_url is empty"})
	case errThreatFoxNoAuthKey:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ThreatFox Auth-Key не задан"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": sanitizeThreatFeedError(err.Error())})
	}
}

// postThreatFoxFull replaces the blocklist from ThreatFox full CSV export.
func postThreatFoxFull(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadThreatFeedConfig(r.Context(), db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !cfg.UsesThreatFox() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider is not threatfox"})
		return
	}
	syncCtx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()
	switch err := syncThreatFoxFull(syncCtx, db, cfg); err {
	case nil:
		if err := rdb.Publish(r.Context(), "threat_feed_updated", `{"singleton":"global"}`).Err(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case errThreatFoxNoAuthKey:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ThreatFox Auth-Key не задан"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": sanitizeThreatFeedError(err.Error())})
	}
}
