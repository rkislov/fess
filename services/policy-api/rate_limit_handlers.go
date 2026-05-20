package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/redis/go-redis/v9"

	"fence/pkg/ratelimit"
)

func rateLimitSettingsHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := loadRateLimitConfig(r.Context(), db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"config": cfg})
	case http.MethodPut:
		var body struct {
			Config ratelimit.Config `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		cfg := ratelimit.NormalizeConfig(body.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_, err = db.ExecContext(r.Context(), `
UPDATE rate_limit_settings SET config = $1::jsonb, updated_at = NOW() WHERE singleton = 'global'`, string(raw))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if err := rdb.Publish(r.Context(), "rate_limit_updated", `{"singleton":"global"}`).Err(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "updated": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func loadRateLimitConfig(ctx context.Context, db *sql.DB) (ratelimit.Config, error) {
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT config FROM rate_limit_settings WHERE singleton = 'global'`).Scan(&raw)
	if err != nil {
		return ratelimit.DefaultConfig(), err
	}
	return ratelimit.ParseConfig(raw)
}

func rateLimitOverrideToJSON(o ratelimit.Override) (any, error) {
	if !o.Set {
		return nil, nil
	}
	raw, err := json.Marshal(ratelimit.NormalizeConfig(o.Config))
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func rateLimitOverrideFromPayload(p *ratelimit.OverridePayload) (ratelimit.Override, error) {
	return ratelimit.OverrideFromPayload(p)
}

func rateLimitOverrideDBArg(o ratelimit.Override) (any, error) {
	raw, err := ratelimit.MarshalOverrideJSON(o)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	return string(raw), nil
}
