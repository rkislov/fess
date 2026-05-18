package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"fence/pkg/botprotection"
	"fence/pkg/threatfeed"
)

const botProtectionMaxUploadBytes = 16 << 20

type botProtectionResponse struct {
	botprotection.Config
	ChallengeSecretSet bool `json:"challenge_secret_set"`
}

type botProtectionStatusResponse struct {
	Enabled       bool   `json:"enabled"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	ASNRows       int    `json:"asn_rows"`
	CIDRRows      int    `json:"cidr_rows"`
	ASNMmdbPresent bool  `json:"asn_mmdb_present"`
}

func loadBotProtectionConfig(ctx context.Context, db *sql.DB) (botprotection.Config, error) {
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT config FROM bot_protection_settings WHERE singleton = 'global'`).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return botprotection.DefaultConfig(), nil
		}
		return botprotection.Config{}, err
	}
	return botprotection.ParseConfig(raw)
}

func getBotProtectionSettings(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadBotProtectionConfig(r.Context(), db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	secretSet := cfg.Challenge.Secret != ""
	cfg.Challenge.Secret = maskSecret(cfg.Challenge.Secret)
	writeJSON(w, http.StatusOK, botProtectionResponse{Config: cfg, ChallengeSecretSet: secretSet})
}

func putBotProtectionSettings(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	old, err := loadBotProtectionConfig(r.Context(), db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var incoming botprotection.Config
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	mergeBotProtectionSecrets(&incoming, old)
	if strings.TrimSpace(incoming.Challenge.Secret) == "" && incoming.Challenge.Enabled {
		incoming.Challenge.Secret = uuid.NewString()
	}
	raw, err := json.Marshal(incoming)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	normalized, err := botprotection.ParseConfig(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := json.Marshal(normalized)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if _, err := db.ExecContext(r.Context(), `
UPDATE bot_protection_settings SET config = $1::jsonb, updated_at = NOW() WHERE singleton = 'global'`, string(out)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := rdb.Publish(r.Context(), "bot_protection_updated", `{"singleton":"global"}`).Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": true})
}

func mergeBotProtectionSecrets(in *botprotection.Config, old botprotection.Config) {
	if in.Challenge.Secret == "" || in.Challenge.Secret == "***" {
		in.Challenge.Secret = old.Challenge.Secret
	}
}

func getBotProtectionStatus(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadBotProtectionConfig(r.Context(), db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var lastOK sql.NullTime
	var lastErr sql.NullString
	var asnRows, cidrRows int
	_ = db.QueryRowContext(r.Context(), `
SELECT last_success_at, last_error, asn_rows, cidr_rows
FROM bot_protection_sync_state WHERE singleton = 'global'`).Scan(&lastOK, &lastErr, &asnRows, &cidrRows)

	out := botProtectionStatusResponse{
		Enabled:        cfg.Enabled,
		ASNRows:        asnRows,
		CIDRRows:       cidrRows,
		ASNMmdbPresent: botASNMMDBPresent(),
	}
	if lastOK.Valid {
		out.LastSuccessAt = lastOK.Time.UTC().Format(time.RFC3339Nano)
	}
	if lastErr.Valid {
		out.LastError = lastErr.String
	}
	writeJSON(w, http.StatusOK, out)
}

func postBotProtectionUpload(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	if kind != "asn" && kind != "cidr" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "query type must be asn or cidr"})
		return
	}
	if err := r.ParseMultipartForm(botProtectionMaxUploadBytes + (1 << 20)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "multipart parse failed: " + err.Error()})
		return
	}
	fh, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing form field \"file\""})
		return
	}
	defer fh.Close()
	body, err := io.ReadAll(io.LimitReader(fh, botProtectionMaxUploadBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(body) > botProtectionMaxUploadBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file exceeds 16 MiB"})
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file is empty"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	n, err := ingestBotProtectionList(ctx, db, kind, body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := rdb.Publish(r.Context(), "bot_protection_updated", `{"singleton":"global"}`).Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "type": kind, "rows_ingested": n})
}

func ingestBotProtectionList(ctx context.Context, db *sql.DB, kind string, body []byte) (int, error) {
	now := time.Now().UTC()
	_, _ = db.ExecContext(ctx, `UPDATE bot_protection_sync_state SET last_attempt_at = $1 WHERE singleton = 'global'`, now)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var n int
	switch kind {
	case "asn":
		asns, err := botprotection.ParseASNList(body)
		if err != nil {
			recordBotProtectionFail(ctx, db, err.Error())
			return 0, err
		}
		if len(asns) == 0 {
			err := errors.New("no valid ASN numbers in file")
			recordBotProtectionFail(ctx, db, err.Error())
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM bot_protection_asn`); err != nil {
			recordBotProtectionFail(ctx, db, err.Error())
			return 0, err
		}
		for _, asn := range asns {
			if _, err := tx.ExecContext(ctx, `INSERT INTO bot_protection_asn(asn) VALUES ($1)`, int64(asn)); err != nil {
				recordBotProtectionFail(ctx, db, err.Error())
				return 0, err
			}
		}
		n = len(asns)
		if _, err := tx.ExecContext(ctx, `
UPDATE bot_protection_sync_state SET last_success_at = $1, last_error = '', asn_rows = $2 WHERE singleton = 'global'`, now, n); err != nil {
			recordBotProtectionFail(ctx, db, err.Error())
			return 0, err
		}
	case "cidr":
		rows, err := threatfeed.ParseFeedBody(body, "plain", "", "")
		if err != nil {
			recordBotProtectionFail(ctx, db, err.Error())
			return 0, err
		}
		inds := threatfeed.ValidIPCIDR(threatfeed.UniqueIndicators(rows))
		if len(inds) == 0 {
			err := errors.New("no valid IP/CIDR in file")
			recordBotProtectionFail(ctx, db, err.Error())
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM bot_protection_cidr`); err != nil {
			recordBotProtectionFail(ctx, db, err.Error())
			return 0, err
		}
		for _, c := range inds {
			if _, err := tx.ExecContext(ctx, `INSERT INTO bot_protection_cidr(cidr) VALUES ($1)`, c); err != nil {
				recordBotProtectionFail(ctx, db, err.Error())
				return 0, err
			}
		}
		n = len(inds)
		if _, err := tx.ExecContext(ctx, `
UPDATE bot_protection_sync_state SET last_success_at = $1, last_error = '', cidr_rows = $2 WHERE singleton = 'global'`, now, n); err != nil {
			recordBotProtectionFail(ctx, db, err.Error())
			return 0, err
		}
	default:
		return 0, fmt.Errorf("unknown list type %q", kind)
	}

	if err := tx.Commit(); err != nil {
		recordBotProtectionFail(ctx, db, err.Error())
		return 0, err
	}
	return n, nil
}

func recordBotProtectionFail(ctx context.Context, db *sql.DB, msg string) {
	msg = strings.TrimSpace(msg)
	if len(msg) > 2000 {
		msg = msg[:2000] + "…"
	}
	_, _ = db.ExecContext(ctx, `UPDATE bot_protection_sync_state SET last_error = $1 WHERE singleton = 'global'`, msg)
}

func botASNMMDBPath() string {
	return filepath.Join(geoipDataDir(), "GeoLite2-ASN.mmdb")
}

func botASNMMDBPresent() bool {
	fi, err := os.Stat(botASNMMDBPath())
	return err == nil && fi.Size() > 0
}

func postBotProtectionASNMMDB(w http.ResponseWriter, r *http.Request, rdb *redis.Client) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(geoipMaxBytes + (1 << 20)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "multipart parse failed: " + err.Error()})
		return
	}
	fh, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing form field \"file\""})
		return
	}
	defer fh.Close()
	if err := installASNMMDB(r.Context(), fh); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := rdb.Publish(r.Context(), "bot_protection_updated", `{"singleton":"global"}`).Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := rdb.Publish(r.Context(), "geoip_asn_mmdb_updated", "{}").Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": true})
}

func installASNMMDB(ctx context.Context, body io.Reader) error {
	if err := os.MkdirAll(geoipDataDir(), 0o755); err != nil {
		return fmt.Errorf("geoip dir: %w", err)
	}
	final := botASNMMDBPath()
	tmp := final + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(body, geoipMaxBytes+1))
	_ = f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if n > geoipMaxBytes {
		_ = os.Remove(tmp)
		return fmt.Errorf("file exceeds max size (%d bytes)", geoipMaxBytes)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = ctx
	return nil
}
