package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"fence/pkg/ratelimit"
)

type backendPathRequest struct {
	PathPrefix       string   `json:"path_prefix"`
	Priority         int      `json:"priority"`
	Enabled          *bool    `json:"enabled"`
	WebSocketEnabled *bool    `json:"websocket_enabled"`
	Timeout          *int     `json:"timeout"`
	IdleTimeout      *int     `json:"idle_timeout"`
	IPAllowMode      string                      `json:"ip_allow_mode"`
	AllowedCIDRs     []string                    `json:"allowed_cidrs"`
	RateLimit        *ratelimit.OverridePayload  `json:"rate_limit"`
}

type backendPathRow struct {
	ID               string    `json:"id"`
	BackendID        string    `json:"backend_id"`
	PathPrefix       string    `json:"path_prefix"`
	Priority         int       `json:"priority"`
	Enabled          bool      `json:"enabled"`
	WebSocketEnabled bool      `json:"websocket_enabled"`
	Timeout          int       `json:"timeout"`
	IdleTimeout      int       `json:"idle_timeout"`
	IPAllowMode      string    `json:"ip_allow_mode"`
	AllowedCIDRs     []string  `json:"allowed_cidrs"`
	RateLimit        any       `json:"rate_limit"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func backendPathByIDHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/backend-paths/")
	id = strings.Trim(id, "/")
	if id == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if _, err := uuid.Parse(id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path id"})
		return
	}
	switch r.Method {
	case http.MethodPut:
		var payload backendPathRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		updateBackendPath(w, r, db, rdb, id, payload)
	case http.MethodDelete:
		deleteBackendPath(w, r, db, rdb, id)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func backendPathsCollectionHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, backendID string) {
	switch r.Method {
	case http.MethodGet:
		listBackendPaths(w, r, db, backendID)
	case http.MethodPost:
		var payload backendPathRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		createBackendPath(w, r, db, rdb, backendID, payload)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func listBackendPaths(w http.ResponseWriter, r *http.Request, db *sql.DB, backendID string) {
	rows, err := db.QueryContext(r.Context(), `
SELECT id::text, backend_id::text, path_prefix, priority, enabled, websocket_enabled,
  timeout_sec, idle_timeout_sec, ip_allow_mode, allowed_cidrs, rate_limit_override, created_at, updated_at
FROM backend_paths
WHERE backend_id=$1::uuid
ORDER BY priority ASC, created_at ASC`, backendID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	var items []backendPathRow
	for rows.Next() {
		it, err := scanBackendPathRow(rows)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func scanBackendPathRow(rows *sql.Rows) (backendPathRow, error) {
	var it backendPathRow
	var allowedJSON string
	var rlRaw []byte
	err := rows.Scan(&it.ID, &it.BackendID, &it.PathPrefix, &it.Priority, &it.Enabled, &it.WebSocketEnabled,
		&it.Timeout, &it.IdleTimeout, &it.IPAllowMode, &allowedJSON, &rlRaw, &it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		return it, err
	}
	it.AllowedCIDRs = decodeAllowedCIDRsJSON(allowedJSON)
	rl, rerr := ratelimit.ParseOverrideJSON(rlRaw)
	if rerr != nil {
		return it, rerr
	}
	it.RateLimit, _ = rateLimitOverrideToJSON(rl)
	return it, nil
}

func createBackendPath(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, backendID string, payload backendPathRequest) {
	if !backendExists(r.Context(), db, backendID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "backend not found"})
		return
	}
	pathPrefix, perr := normalizeBackendPathPrefix(payload.PathPrefix)
	if perr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": perr.Error()})
		return
	}
	if pathPrefix == "" {
		pathPrefix = "*"
	}
	if payload.Priority == 0 {
		payload.Priority = 100
	}
	en := true
	if payload.Enabled != nil {
		en = *payload.Enabled
	}
	wsEn := false
	if payload.WebSocketEnabled != nil {
		wsEn = *payload.WebSocketEnabled
	}
	timeoutSec, idleTimeoutSec, terr := backendTimeoutFields(payload.Timeout, payload.IdleTimeout)
	if terr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": terr.Error()})
		return
	}
	ipMode, allowedJSON, ierr := backendIPAllowFields(payload.IPAllowMode, payload.AllowedCIDRs)
	if ierr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": ierr.Error()})
		return
	}
	rlOverride, rlErr := rateLimitOverrideFromPayload(payload.RateLimit)
	if rlErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": rlErr.Error()})
		return
	}
	rlArg, rlArgErr := rateLimitOverrideDBArg(rlOverride)
	if rlArgErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": rlArgErr.Error()})
		return
	}
	id := uuid.NewString()
	_, err := db.ExecContext(r.Context(), `
INSERT INTO backend_paths(id, backend_id, path_prefix, priority, enabled, websocket_enabled, timeout_sec, idle_timeout_sec, ip_allow_mode, allowed_cidrs, rate_limit_override)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)`,
		id, backendID, pathPrefix, payload.Priority, en, wsEn, timeoutSec, idleTimeoutSec, ipMode, allowedJSON, rlArg)
	if err != nil {
		if isUniqueViolation(err) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "path_prefix already exists for this backend"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeAuditLog(r.Context(), db, "system", "create", "backend_path", id, nil, map[string]any{"backend_id": backendID, "path_prefix": pathPrefix})
	if err := publishRoutingUpdate(r.Context(), rdb); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "backend_id": backendID})
}

func updateBackendPath(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, id string, payload backendPathRequest) {
	pathPrefix, perr := normalizeBackendPathPrefix(payload.PathPrefix)
	if perr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": perr.Error()})
		return
	}
	if pathPrefix == "" {
		pathPrefix = "*"
	}
	if payload.Priority == 0 {
		payload.Priority = 100
	}
	en := true
	if payload.Enabled != nil {
		en = *payload.Enabled
	}
	wsEn := false
	if payload.WebSocketEnabled != nil {
		wsEn = *payload.WebSocketEnabled
	}
	timeoutSec, idleTimeoutSec, terr := backendTimeoutFields(payload.Timeout, payload.IdleTimeout)
	if terr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": terr.Error()})
		return
	}
	ipMode, allowedJSON, ierr := backendIPAllowFields(payload.IPAllowMode, payload.AllowedCIDRs)
	if ierr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": ierr.Error()})
		return
	}
	rlOverride, rlErr := rateLimitOverrideFromPayload(payload.RateLimit)
	if rlErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": rlErr.Error()})
		return
	}
	rlArg, rlArgErr := rateLimitOverrideDBArg(rlOverride)
	if rlArgErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": rlArgErr.Error()})
		return
	}
	res, err := db.ExecContext(r.Context(), `
UPDATE backend_paths SET path_prefix=$2, priority=$3, enabled=$4, websocket_enabled=$5,
  timeout_sec=$6, idle_timeout_sec=$7, ip_allow_mode=$8, allowed_cidrs=$9,
  rate_limit_override=$10::jsonb, updated_at=NOW()
WHERE id=$1::uuid`, id, pathPrefix, payload.Priority, en, wsEn, timeoutSec, idleTimeoutSec, ipMode, allowedJSON, rlArg)
	if err != nil {
		if isUniqueViolation(err) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "path_prefix already exists for this backend"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "path not found"})
		return
	}
	writeAuditLog(r.Context(), db, "system", "update", "backend_path", id, nil, map[string]any{"path_prefix": pathPrefix})
	if err := publishRoutingUpdate(r.Context(), rdb); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
}

func deleteBackendPath(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, id string) {
	res, err := db.ExecContext(r.Context(), `DELETE FROM backend_paths WHERE id=$1::uuid`, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "path not found"})
		return
	}
	writeAuditLog(r.Context(), db, "system", "delete", "backend_path", id, nil, nil)
	if err := publishRoutingUpdate(r.Context(), rdb); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func insertDefaultBackendPath(ctx context.Context, db *sql.DB, backendID string) error {
	_, err := db.ExecContext(ctx, `
INSERT INTO backend_paths(id, backend_id, path_prefix, priority, enabled)
VALUES ($1::uuid, $2::uuid, '*', 100, TRUE)`, uuid.NewString(), backendID)
	return err
}

func backendExists(ctx context.Context, db *sql.DB, backendID string) bool {
	var n int
	err := db.QueryRowContext(ctx, `SELECT 1 FROM backends WHERE id=$1::uuid`, backendID).Scan(&n)
	return err == nil
}

func loadPathsForBackend(ctx context.Context, db *sql.DB, backendID string) ([]backendPathRow, error) {
	rows, err := db.QueryContext(ctx, `
SELECT id::text, backend_id::text, path_prefix, priority, enabled, websocket_enabled,
  timeout_sec, idle_timeout_sec, ip_allow_mode, allowed_cidrs, rate_limit_override, created_at, updated_at
FROM backend_paths WHERE backend_id=$1::uuid ORDER BY priority ASC, created_at ASC`, backendID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []backendPathRow
	for rows.Next() {
		it, err := scanBackendPathRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
