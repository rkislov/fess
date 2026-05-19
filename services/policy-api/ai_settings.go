package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"fence/pkg/auth"
)

type aiSettingsRow struct {
	Enabled        bool
	BaseURL        string
	Model          string
	APIKey         string
	HTTPTimeoutSec int
}

type aiSettingsPayload struct {
	Enabled        bool   `json:"enabled"`
	BaseURL        string `json:"base_url"`
	Model          string `json:"model"`
	APIKey         string `json:"api_key"`
	HTTPTimeoutSec int    `json:"http_timeout_sec"`
}

type aiSettingsAPIResponse struct {
	aiSettingsPayload
	APIKeySet      bool              `json:"api_key_set"`
	Configured     bool              `json:"configured"`
	EnvDefaults    aiSettingsPayload `json:"env_defaults"`
	Effective      aiSettingsPayload `json:"effective"`
}

type resolvedAIConfig struct {
	Enabled bool
	BaseURL string
	Model   string
	APIKey  string
	Timeout time.Duration
}

func (c resolvedAIConfig) configured() bool {
	return c.Enabled && strings.TrimSpace(c.APIKey) != ""
}

func envAIDefaults() aiSettingsRow {
	base := strings.TrimSpace(os.Getenv("FENCE_AI_BASE_URL"))
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	base = strings.TrimRight(base, "/")
	model := strings.TrimSpace(os.Getenv("FENCE_AI_MODEL"))
	if model == "" {
		model = "gpt-4o-mini"
	}
	timeoutSec := int(aiTimeoutFromEnv().Seconds())
	return aiSettingsRow{
		Enabled:        true,
		BaseURL:        base,
		Model:          model,
		APIKey:         strings.TrimSpace(os.Getenv("FENCE_AI_API_KEY")),
		HTTPTimeoutSec: timeoutSec,
	}
}

func aiTimeoutFromEnv() time.Duration {
	d := parseDurationEnv("FENCE_AI_HTTP_TIMEOUT", 10*time.Minute)
	if d < 30*time.Second {
		return 30 * time.Second
	}
	if d > 30*time.Minute {
		return 30 * time.Minute
	}
	return d
}

func loadAISettingsRow(ctx context.Context, db *sql.DB) (aiSettingsRow, error) {
	var s aiSettingsRow
	err := db.QueryRowContext(ctx, `
SELECT enabled, base_url, model, api_key, http_timeout_sec
FROM ai_settings WHERE singleton = 'global'`).Scan(
		&s.Enabled, &s.BaseURL, &s.Model, &s.APIKey, &s.HTTPTimeoutSec,
	)
	return s, err
}

func resolveAIConfig(ctx context.Context, db *sql.DB) (resolvedAIConfig, error) {
	env := envAIDefaults()
	dbRow, err := loadAISettingsRow(ctx, db)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rowToResolved(env), nil
		}
		return resolvedAIConfig{}, err
	}
	merged := env
	merged.Enabled = dbRow.Enabled
	if v := strings.TrimSpace(dbRow.BaseURL); v != "" {
		merged.BaseURL = strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(dbRow.Model); v != "" {
		merged.Model = v
	}
	if v := strings.TrimSpace(dbRow.APIKey); v != "" {
		merged.APIKey = v
	}
	if dbRow.HTTPTimeoutSec > 0 {
		merged.HTTPTimeoutSec = dbRow.HTTPTimeoutSec
	}
	return rowToResolved(merged), nil
}

func rowToResolved(r aiSettingsRow) resolvedAIConfig {
	timeout := aiTimeoutFromEnv()
	if r.HTTPTimeoutSec > 0 {
		sec := r.HTTPTimeoutSec
		if sec < 30 {
			sec = 30
		}
		if sec > 1800 {
			sec = 1800
		}
		timeout = time.Duration(sec) * time.Second
	}
	base := strings.TrimSpace(r.BaseURL)
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	model := strings.TrimSpace(r.Model)
	if model == "" {
		model = "gpt-4o-mini"
	}
	return resolvedAIConfig{
		Enabled: r.Enabled,
		BaseURL: strings.TrimRight(base, "/"),
		Model:   model,
		APIKey:  strings.TrimSpace(r.APIKey),
		Timeout: timeout,
	}
}

func rowToPayload(r aiSettingsRow) aiSettingsPayload {
	return aiSettingsPayload{
		Enabled:        r.Enabled,
		BaseURL:        r.BaseURL,
		Model:          r.Model,
		APIKey:         r.APIKey,
		HTTPTimeoutSec: r.HTTPTimeoutSec,
	}
}

func mergeAISettingsSecrets(in *aiSettingsPayload, old aiSettingsRow) {
	if in.APIKey == "" || in.APIKey == "***" {
		in.APIKey = old.APIKey
	}
}

func saveAISettings(ctx context.Context, db *sql.DB, p aiSettingsPayload) error {
	base := strings.TrimSpace(p.BaseURL)
	if base != "" {
		base = strings.TrimRight(base, "/")
	}
	model := strings.TrimSpace(p.Model)
	key := strings.TrimSpace(p.APIKey)
	timeout := p.HTTPTimeoutSec
	if timeout < 0 {
		timeout = 0
	}
	if timeout > 0 {
		if timeout < 30 {
			timeout = 30
		}
		if timeout > 1800 {
			timeout = 1800
		}
	}
	_, err := db.ExecContext(ctx, `
UPDATE ai_settings SET
  enabled = $1,
  base_url = $2,
  model = $3,
  api_key = $4,
  http_timeout_sec = $5,
  updated_at = NOW()
WHERE singleton = 'global'`,
		p.Enabled, base, model, key, timeout,
	)
	return err
}

func aiSettingsHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	switch r.Method {
	case http.MethodGet:
		aiSettingsGetHandler(w, r, db)
	case http.MethodPut:
		aiSettingsPutHandler(w, r, db)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func aiSettingsGetHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	ctx := r.Context()
	env := envAIDefaults()
	resolved, err := resolveAIConfig(ctx, db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	dbRow, err := loadAISettingsRow(ctx, db)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		dbRow = aiSettingsRow{}
	}

	payload := rowToPayload(dbRow)
	payload.APIKey = maskSecret(payload.APIKey)
	keySet := strings.TrimSpace(dbRow.APIKey) != "" || strings.TrimSpace(env.APIKey) != ""

	eff := aiSettingsPayload{
		Enabled:        resolved.Enabled,
		BaseURL:        resolved.BaseURL,
		Model:          resolved.Model,
		HTTPTimeoutSec: int(resolved.Timeout.Seconds()),
	}
	envPayload := rowToPayload(env)
	envPayload.APIKey = maskSecret(envPayload.APIKey)

	out := aiSettingsAPIResponse{
		aiSettingsPayload: payload,
		APIKeySet:         keySet,
		Configured:        resolved.configured(),
		EnvDefaults:       envPayload,
		Effective:       eff,
	}

	claims, ok := auth.ClaimsFromContext(ctx)
	if ok && auth.CanAdmin(claims.Role) {
		writeJSON(w, http.StatusOK, out)
		return
	}
	// Операторам — только статус для вкладки «ИИ» (без секретов и без полей БД).
	writeJSON(w, http.StatusOK, map[string]any{
		"configured":       resolved.configured(),
		"enabled":          resolved.Enabled,
		"model":            resolved.Model,
		"base_url":         resolved.BaseURL,
		"http_timeout_sec": int(resolved.Timeout.Seconds()),
	})
}

func aiSettingsPutHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || !auth.CanAdmin(claims.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required"})
		return
	}
	old, err := loadAISettingsRow(r.Context(), db)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var incoming aiSettingsPayload
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	mergeAISettingsSecrets(&incoming, old)
	if err := saveAISettings(r.Context(), db, incoming); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeAuditLog(r.Context(), db, claims.Username, "update", "ai_settings", "global", nil, map[string]any{
		"enabled": incoming.Enabled,
		"model":   incoming.Model,
		"base_url": strings.TrimSpace(incoming.BaseURL),
	})
	aiSettingsGetHandler(w, r, db)
}
