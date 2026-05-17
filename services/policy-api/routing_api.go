package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"fence/pkg/routing"
)

type siteCreateRequest struct {
	Name        string `json:"name"`
	HostPattern string `json:"host_pattern"`
	Priority    int    `json:"priority"`
	Enabled     *bool  `json:"enabled"`
	PolicyID    string `json:"policy_id"`
}

type siteUpdateRequest struct {
	Name        string `json:"name"`
	HostPattern string `json:"host_pattern"`
	Priority    int    `json:"priority"`
	Enabled     *bool  `json:"enabled"`
	PolicyID    string `json:"policy_id"`
}

type backendCreateRequest struct {
	Name             string `json:"name"`
	BaseURL          string `json:"base_url"`
	Priority         int    `json:"priority"`
	Enabled          *bool  `json:"enabled"`
	TLSSkipVerify    *bool  `json:"tls_skip_verify"`
	PathPrefix       string `json:"path_prefix"`
	WebSocketEnabled *bool  `json:"websocket_enabled"`
	Timeout          *int   `json:"timeout"`
	IdleTimeout      *int   `json:"idle_timeout"`
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
	if len(parts) == 2 && parts[1] == "tls" {
		switch r.Method {
		case http.MethodGet:
			getSiteTLS(w, r, db, siteID)
		case http.MethodPut:
			var payload siteTLSPutRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			putSiteTLS(w, r, db, rdb, siteID, payload)
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

type siteTLSPutRequest struct {
	TLSEnabled *bool   `json:"tls_enabled"`
	TLSCertPem *string `json:"tls_cert_pem"`
	TLSKeyPem  *string `json:"tls_key_pem"`
}

func getSiteTLS(w http.ResponseWriter, r *http.Request, db *sql.DB, siteID string) {
	var en bool
	var cert, key sql.NullString
	err := db.QueryRowContext(r.Context(), `
SELECT tls_enabled, tls_cert_pem, tls_key_pem FROM sites WHERE id=$1::uuid`, siteID).Scan(&en, &cert, &key)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "site not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	has := strings.TrimSpace(cert.String) != "" && strings.TrimSpace(key.String) != ""
	writeJSON(w, http.StatusOK, map[string]any{
		"tls_enabled":         en,
		"tls_has_certificate": has,
	})
}

func putSiteTLS(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, siteID string, payload siteTLSPutRequest) {
	var curEn bool
	var curCert, curKey sql.NullString
	err := db.QueryRowContext(r.Context(), `
SELECT tls_enabled, tls_cert_pem, tls_key_pem FROM sites WHERE id=$1::uuid`, siteID).Scan(&curEn, &curCert, &curKey)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "site not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	en := curEn
	if payload.TLSEnabled != nil {
		en = *payload.TLSEnabled
	}
	cert := curCert.String
	if payload.TLSCertPem != nil {
		cert = *payload.TLSCertPem
	}
	key := curKey.String
	if payload.TLSKeyPem != nil {
		key = *payload.TLSKeyPem
	}

	if en && (strings.TrimSpace(cert) == "" || strings.TrimSpace(key) == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tls_enabled requires non-empty tls_cert_pem and tls_key_pem"})
		return
	}

	_, err = db.ExecContext(r.Context(), `
UPDATE sites SET tls_enabled=$2, tls_cert_pem=NULLIF(trim($3), ''), tls_key_pem=NULLIF(trim($4), ''), updated_at=NOW()
WHERE id=$1::uuid`,
		siteID, en, strings.TrimSpace(cert), strings.TrimSpace(key))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeAuditLog(r.Context(), db, "system", "update", "site_tls", siteID, nil, map[string]any{"tls_enabled": en})
	if err := publishRoutingUpdate(r.Context(), rdb); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": siteID, "updated": true})
}

func listSites(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	rows, err := db.QueryContext(r.Context(), `
SELECT id::text, name, host_pattern, priority, enabled, COALESCE(policy_id::text, ''), tls_enabled,
  (length(trim(COALESCE(tls_cert_pem, ''))) > 0 AND length(trim(COALESCE(tls_key_pem, ''))) > 0) AS tls_has_certificate,
  created_at, updated_at
FROM sites
ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type row struct {
		ID                string    `json:"id"`
		Name              string    `json:"name"`
		HostPattern       string    `json:"host_pattern"`
		Priority          int       `json:"priority"`
		Enabled           bool      `json:"enabled"`
		PolicyID          string    `json:"policy_id"`
		TLSEnabled        bool      `json:"tls_enabled"`
		TLSHasCertificate bool      `json:"tls_has_certificate"`
		CreatedAt         time.Time `json:"created_at"`
		UpdatedAt         time.Time `json:"updated_at"`
	}
	var items []row
	for rows.Next() {
		var it row
		if err := rows.Scan(&it.ID, &it.Name, &it.HostPattern, &it.Priority, &it.Enabled, &it.PolicyID, &it.TLSEnabled, &it.TLSHasCertificate, &it.CreatedAt, &it.UpdatedAt); err != nil {
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
SELECT id::text, name, base_url, priority, enabled, tls_skip_verify,
  COALESCE(path_prefix, ''), websocket_enabled, timeout_sec, idle_timeout_sec,
  created_at, updated_at
FROM backends
WHERE site_id=$1::uuid
ORDER BY priority ASC, created_at ASC`, siteID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type row struct {
		ID               string    `json:"id"`
		Name             string    `json:"name"`
		BaseURL          string    `json:"base_url"`
		Priority         int       `json:"priority"`
		Enabled          bool      `json:"enabled"`
		TLSSkipVerify    bool      `json:"tls_skip_verify"`
		PathPrefix       string    `json:"path_prefix"`
		WebSocketEnabled bool      `json:"websocket_enabled"`
		Timeout          int       `json:"timeout"`
		IdleTimeout      int       `json:"idle_timeout"`
		CreatedAt        time.Time `json:"created_at"`
		UpdatedAt        time.Time `json:"updated_at"`
	}
	var items []row
	for rows.Next() {
		var it row
		if err := rows.Scan(&it.ID, &it.Name, &it.BaseURL, &it.Priority, &it.Enabled, &it.TLSSkipVerify,
			&it.PathPrefix, &it.WebSocketEnabled, &it.Timeout, &it.IdleTimeout, &it.CreatedAt, &it.UpdatedAt); err != nil {
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
	tlsSkip := false
	if payload.TLSSkipVerify != nil {
		tlsSkip = *payload.TLSSkipVerify
	}
	pathPrefix, perr := normalizeBackendPathPrefix(payload.PathPrefix)
	if perr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": perr.Error()})
		return
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
	id := uuid.NewString()
	_, err := db.ExecContext(r.Context(), `
INSERT INTO backends(id, site_id, name, base_url, priority, enabled, tls_skip_verify, path_prefix, websocket_enabled, timeout_sec, idle_timeout_sec)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		id, siteID, payload.Name, strings.TrimSpace(payload.BaseURL), payload.Priority, en, tlsSkip, pathPrefix, wsEn, timeoutSec, idleTimeoutSec)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeAuditLog(r.Context(), db, "system", "create", "backend", id, nil, map[string]any{"site_id": siteID, "base_url": payload.BaseURL, "tls_skip_verify": tlsSkip})
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
	tlsSkip := false
	if payload.TLSSkipVerify != nil {
		tlsSkip = *payload.TLSSkipVerify
	}
	pathPrefix, perr := normalizeBackendPathPrefix(payload.PathPrefix)
	if perr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": perr.Error()})
		return
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
	res, err := db.ExecContext(r.Context(), `
UPDATE backends SET name=$2, base_url=$3, priority=$4, enabled=$5, tls_skip_verify=$6,
  path_prefix=$7, websocket_enabled=$8, timeout_sec=$9, idle_timeout_sec=$10, updated_at=NOW()
WHERE id=$1::uuid`, id, payload.Name, strings.TrimSpace(payload.BaseURL), payload.Priority, en, tlsSkip, pathPrefix, wsEn, timeoutSec, idleTimeoutSec)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "backend not found"})
		return
	}
	writeAuditLog(r.Context(), db, "system", "update", "backend", id, nil, map[string]any{"id": id, "tls_skip_verify": tlsSkip})
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

const maxBackendTimeoutSec = 86400

func backendTimeoutFields(timeout, idleTimeout *int) (int, int, error) {
	t := 0
	if timeout != nil {
		if *timeout < 0 || *timeout > maxBackendTimeoutSec {
			return 0, 0, errors.New("timeout must be between 0 and 86400 seconds")
		}
		t = *timeout
	}
	idle := 0
	if idleTimeout != nil {
		if *idleTimeout < 0 || *idleTimeout > maxBackendTimeoutSec {
			return 0, 0, errors.New("idle_timeout must be between 0 and 86400 seconds")
		}
		idle = *idleTimeout
	}
	return t, idle, nil
}

func normalizeBackendPathPrefix(p string) (string, error) {
	p = routing.NormalizePathPrefix(p)
	if strings.ContainsAny(p, "?#*") {
		return "", errors.New("path_prefix must be a simple path prefix (e.g. /api/ws)")
	}
	return p, nil
}

func validBaseURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && u != nil && u.Scheme != "" && u.Host != ""
}
