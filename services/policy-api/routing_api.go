package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type siteCreateRequest struct {
	Name         string `json:"name"`
	HostPattern  string `json:"host_pattern"`
	Priority     int    `json:"priority"`
	Enabled      *bool  `json:"enabled"`
	PolicyID     string `json:"policy_id"`
}

type siteUpdateRequest struct {
	Name        string `json:"name"`
	HostPattern string `json:"host_pattern"`
	Priority    int    `json:"priority"`
	Enabled     *bool  `json:"enabled"`
	PolicyID    string `json:"policy_id"`
}

type backendCreateRequest struct {
	Name     string `json:"name"`
	BaseURL  string `json:"base_url"`
	Priority int    `json:"priority"`
	Enabled  *bool  `json:"enabled"`
}

func publishRoutingUpdate(ctx context.Context, rdb *redis.Client) error {
	return rdb.Publish(ctx, "routing_updated", `{"v":1}`).Err()
}

func sitesCollectionHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	switch r.Method {
	case http.MethodGet:
		listSites(w, r, db)
	case http.MethodPost:
		createSite(w, r, db, rdb)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func sitesTreeHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/sites/")
	path = strings.Trim(path, "/")
	if path == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	parts := strings.Split(path, "/")
	siteID := parts[0]
	if _, err := uuid.Parse(siteID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid site id"})
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodPut:
			var payload siteUpdateRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			updateSite(w, r, db, rdb, siteID, payload)
		case http.MethodDelete:
			deleteSite(w, r, db, rdb, siteID)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "backends" {
		switch r.Method {
		case http.MethodGet:
			listBackends(w, r, db, siteID)
		case http.MethodPost:
			var payload backendCreateRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			createBackend(w, r, db, rdb, siteID, payload)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func backendByIDHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/backends/")
	id = strings.Trim(id, "/")
	if id == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if _, err := uuid.Parse(id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid backend id"})
		return
	}
	switch r.Method {
	case http.MethodPut:
		var payload backendCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		updateBackend(w, r, db, rdb, id, payload)
	case http.MethodDelete:
		deleteBackend(w, r, db, rdb, id)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func listSites(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	rows, err := db.QueryContext(r.Context(), `
SELECT id::text, name, host_pattern, priority, enabled, COALESCE(policy_id::text, ''), created_at, updated_at
FROM sites
ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type row struct {
		ID          string    `json:"id"`
		Name        string    `json:"name"`
		HostPattern string    `json:"host_pattern"`
		Priority    int       `json:"priority"`
		Enabled     bool      `json:"enabled"`
		PolicyID    string    `json:"policy_id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
	}
	var items []row
	for rows.Next() {
		var it row
		if err := rows.Scan(&it.ID, &it.Name, &it.HostPattern, &it.Priority, &it.Enabled, &it.PolicyID, &it.CreatedAt, &it.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func createSite(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	var payload siteCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(payload.Name) == "" || strings.TrimSpace(payload.HostPattern) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and host_pattern required"})
		return
	}
	if payload.Priority == 0 {
		payload.Priority = 100
	}
	en := true
	if payload.Enabled != nil {
		en = *payload.Enabled
	}
	var policyArg interface{}
	if pid := strings.TrimSpace(payload.PolicyID); pid != "" {
		if _, err := uuid.Parse(pid); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid policy_id"})
			return
		}
		policyArg = pid
	}
	id := uuid.NewString()
	_, err := db.ExecContext(r.Context(), `
INSERT INTO sites(id, name, host_pattern, priority, enabled, policy_id)
VALUES ($1::uuid, $2, $3, $4, $5, $6::uuid)`,
		id, payload.Name, strings.TrimSpace(payload.HostPattern), payload.Priority, en, policyArg)
	if err != nil {
		if isUniqueViolation(err) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "host_pattern already exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeAuditLog(r.Context(), db, "system", "create", "site", id, nil, map[string]any{"id": id, "host_pattern": payload.HostPattern})
	if err := publishRoutingUpdate(r.Context(), rdb); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func updateSite(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, id string, payload siteUpdateRequest) {
	if strings.TrimSpace(payload.Name) == "" || strings.TrimSpace(payload.HostPattern) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and host_pattern required"})
		return
	}
	if payload.Priority == 0 {
		payload.Priority = 100
	}
	en := true
	if payload.Enabled != nil {
		en = *payload.Enabled
	}
	var policyArg interface{}
	if pid := strings.TrimSpace(payload.PolicyID); pid != "" {
		if _, err := uuid.Parse(pid); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid policy_id"})
			return
		}
		policyArg = pid
	}
	res, err := db.ExecContext(r.Context(), `
UPDATE sites SET name=$2, host_pattern=$3, priority=$4, enabled=$5, policy_id=$6::uuid, updated_at=NOW()
WHERE id=$1::uuid`, id, payload.Name, strings.TrimSpace(payload.HostPattern), payload.Priority, en, policyArg)
	if err != nil {
		if isUniqueViolation(err) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "host_pattern already exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "site not found"})
		return
	}
	writeAuditLog(r.Context(), db, "system", "update", "site", id, nil, map[string]any{"id": id})
	if err := publishRoutingUpdate(r.Context(), rdb); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
}

func deleteSite(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, id string) {
	res, err := db.ExecContext(r.Context(), `DELETE FROM sites WHERE id=$1::uuid`, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "site not found"})
		return
	}
	writeAuditLog(r.Context(), db, "system", "delete", "site", id, nil, nil)
	if err := publishRoutingUpdate(r.Context(), rdb); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func listBackends(w http.ResponseWriter, r *http.Request, db *sql.DB, siteID string) {
	rows, err := db.QueryContext(r.Context(), `
SELECT id::text, name, base_url, priority, enabled, created_at, updated_at
FROM backends
WHERE site_id=$1::uuid
ORDER BY priority ASC, created_at ASC`, siteID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type row struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		BaseURL   string    `json:"base_url"`
		Priority  int       `json:"priority"`
		Enabled   bool      `json:"enabled"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	var items []row
	for rows.Next() {
		var it row
		if err := rows.Scan(&it.ID, &it.Name, &it.BaseURL, &it.Priority, &it.Enabled, &it.CreatedAt, &it.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func createBackend(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, siteID string, payload backendCreateRequest) {
	if strings.TrimSpace(payload.Name) == "" || strings.TrimSpace(payload.BaseURL) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and base_url required"})
		return
	}
	if !validBaseURL(payload.BaseURL) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid base_url (need scheme and host, e.g. https://api:443)"})
		return
	}
	if payload.Priority == 0 {
		payload.Priority = 100
	}
	en := true
	if payload.Enabled != nil {
		en = *payload.Enabled
	}
	id := uuid.NewString()
	_, err := db.ExecContext(r.Context(), `
INSERT INTO backends(id, site_id, name, base_url, priority, enabled)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)`,
		id, siteID, payload.Name, strings.TrimSpace(payload.BaseURL), payload.Priority, en)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeAuditLog(r.Context(), db, "system", "create", "backend", id, nil, map[string]any{"site_id": siteID, "base_url": payload.BaseURL})
	if err := publishRoutingUpdate(r.Context(), rdb); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "site_id": siteID})
}

func updateBackend(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, id string, payload backendCreateRequest) {
	if strings.TrimSpace(payload.Name) == "" || strings.TrimSpace(payload.BaseURL) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and base_url required"})
		return
	}
	if !validBaseURL(payload.BaseURL) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid base_url (need scheme and host)"})
		return
	}
	if payload.Priority == 0 {
		payload.Priority = 100
	}
	en := true
	if payload.Enabled != nil {
		en = *payload.Enabled
	}
	res, err := db.ExecContext(r.Context(), `
UPDATE backends SET name=$2, base_url=$3, priority=$4, enabled=$5, updated_at=NOW()
WHERE id=$1::uuid`, id, payload.Name, strings.TrimSpace(payload.BaseURL), payload.Priority, en)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "backend not found"})
		return
	}
	writeAuditLog(r.Context(), db, "system", "update", "backend", id, nil, map[string]any{"id": id})
	if err := publishRoutingUpdate(r.Context(), rdb); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
}

func deleteBackend(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, id string) {
	res, err := db.ExecContext(r.Context(), `DELETE FROM backends WHERE id=$1::uuid`, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "backend not found"})
		return
	}
	writeAuditLog(r.Context(), db, "system", "delete", "backend", id, nil, nil)
	if err := publishRoutingUpdate(r.Context(), rdb); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func isUniqueViolation(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique constraint")
}

func validBaseURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && u != nil && u.Scheme != "" && u.Host != ""
}
