package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"

	"fence/internal/bootstrap"
	"fence/pkg/owasp"
)

var errPolicyNotFound = errors.New("policy not found")

type policyCreateRequest struct {
	Name     string `json:"name"`
	Mode     string `json:"mode"`
	Priority int    `json:"priority"`
}

type policyUpdateRequest struct {
	Name     string `json:"name"`
	Mode     string `json:"mode"`
	Priority int    `json:"priority"`
	Enabled  *bool  `json:"enabled"`
}

type ruleCreateRequest struct {
	Name       string          `json:"name"`
	Action     string          `json:"action"`
	Priority   int             `json:"priority"`
	Condition  json.RawMessage `json:"condition_json"`
	Transform  json.RawMessage `json:"transform_json"`
	Enabled    *bool           `json:"enabled"`
}

type importOWASPRequest struct {
	PackID      string `json:"pack_id"`
	PolicyName  string `json:"policy_name"`
	Mode        string `json:"mode"`
	Priority    int    `json:"priority"`
	Publish     bool   `json:"publish"`
	PublishedBy string `json:"published_by"`
}

func main() {
	listen := getenv("POLICY_API_LISTEN_ADDR", ":8082")
	pgDSN := getenv("POSTGRES_DSN", "postgres://fence:fence@localhost:5432/fence?sslmode=disable")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")

	db, err := sql.Open("postgres", pgDSN)
	if err != nil {
		log.Fatalf("open postgres: %v", err)
	}
	defer db.Close()

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := bootstrap.RetryUntil(waitCtx, "postgres", time.Second, func() error {
		return db.Ping()
	}); err != nil {
		log.Fatalf("postgres: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer rdb.Close()
	if err := bootstrap.RetryUntil(waitCtx, "redis", time.Second, func() error {
		return rdb.Ping(context.Background()).Err()
	}); err != nil {
		log.Fatalf("redis: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		policiesHandler(w, r, db)
	})
	mux.HandleFunc("/api/v1/policies/", func(w http.ResponseWriter, r *http.Request) {
		policyByIDHandler(w, r, db, rdb)
	})
	mux.HandleFunc("/api/v1/rules/", func(w http.ResponseWriter, r *http.Request) {
		ruleByIDHandler(w, r, db)
	})
	mux.HandleFunc("/api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		logsHandler(w, r, db)
	})
	mux.HandleFunc("/api/v1/proxy-access-logs", func(w http.ResponseWriter, r *http.Request) {
		proxyAccessLogsHandler(w, r, db)
	})
	mux.HandleFunc("/api/v1/dashboard/summary", func(w http.ResponseWriter, r *http.Request) {
		dashboardSummaryHandler(w, r, db)
	})
	mux.HandleFunc("/api/v1/settings/malware/status", func(w http.ResponseWriter, r *http.Request) {
		malwareStatusHandler(w, r, db)
	})
	mux.HandleFunc("/api/v1/settings/malware", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getMalwareSettings(w, r, db)
		case http.MethodPut:
			putMalwareSettings(w, r, db, rdb)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/settings/malware/freshclam-snippet", func(w http.ResponseWriter, r *http.Request) {
		freshclamSnippetHandler(w, r, db)
	})
	mux.HandleFunc("/api/v1/owasp/packs", func(w http.ResponseWriter, r *http.Request) {
		owaspPacksHandler(w, r)
	})
	mux.HandleFunc("/api/v1/owasp/pack", func(w http.ResponseWriter, r *http.Request) {
		owaspPackExportHandler(w, r)
	})
	mux.HandleFunc("/api/v1/owasp/import", func(w http.ResponseWriter, r *http.Request) {
		importOWASPHandler(w, r, db, rdb)
	})
	mux.HandleFunc("/api/v1/sites", func(w http.ResponseWriter, r *http.Request) {
		sitesCollectionHandler(w, r, db, rdb)
	})
	mux.HandleFunc("/api/v1/sites/", func(w http.ResponseWriter, r *http.Request) {
		sitesTreeHandler(w, r, db, rdb)
	})
	mux.HandleFunc("/api/v1/backends/", func(w http.ResponseWriter, r *http.Request) {
		backendByIDHandler(w, r, db, rdb)
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 3 * time.Second,
	}

	log.Printf("policy-api listening on %s", listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func policiesHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	switch r.Method {
	case http.MethodGet:
		listPolicies(w, r, db)
	case http.MethodPost:
		var payload policyCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		createPolicy(w, r, db, payload)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func policyByIDHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	if path == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	parts := strings.Split(path, "/")
	id := parts[0]
	if _, err := uuid.Parse(id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid policy id"})
		return
	}

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			snapshot, err := buildPolicySnapshotJSON(r.Context(), db, id)
			if err != nil {
				if errors.Is(err, errPolicyNotFound) {
					writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
					return
				}
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(snapshot)
			return
		case http.MethodPut:
			var payload policyUpdateRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			updatePolicy(w, r, db, id, payload)
			return
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "rules" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var payload ruleCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		createRule(w, r, db, id, payload)
		return
	}

	if len(parts) == 2 && parts[1] == "publish" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		publishPolicy(w, r, db, rdb, id)
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func ruleByIDHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/")
	if id == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if _, err := uuid.Parse(id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rule id"})
		return
	}

	var payload ruleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	updateRule(w, r, db, id, payload)
}

func logActionParamOK(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_':
		default:
			return false
		}
	}
	return true
}

func logsHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	if action != "" && !logActionParamOK(action) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid action query (use letters, digits, underscore)"})
		return
	}

	var rows *sql.Rows
	var err error
	if action == "" {
		rows, err = db.QueryContext(r.Context(), `
SELECT request_id, COALESCE(policy_id::text, ''), COALESCE(rule_id::text, ''), action, source_ip, method, path, COALESCE(details, '{}'::jsonb), created_at
FROM waf_logs
ORDER BY created_at DESC
LIMIT 200`)
	} else {
		rows, err = db.QueryContext(r.Context(), `
SELECT request_id, COALESCE(policy_id::text, ''), COALESCE(rule_id::text, ''), action, source_ip, method, path, COALESCE(details, '{}'::jsonb), created_at
FROM waf_logs
WHERE action = $1
ORDER BY created_at DESC
LIMIT 200`, action)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type item struct {
		RequestID string          `json:"request_id"`
		PolicyID  string          `json:"policy_id"`
		RuleID    string          `json:"rule_id"`
		Action    string          `json:"action"`
		SourceIP  string          `json:"source_ip"`
		Method    string          `json:"method"`
		Path      string          `json:"path"`
		Details   json.RawMessage `json:"details"`
		CreatedAt time.Time       `json:"created_at"`
	}
	var out []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.RequestID, &it.PolicyID, &it.RuleID, &it.Action, &it.SourceIP, &it.Method, &it.Path, &it.Details, &it.CreatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("method=%s path=%s remote=%s latency=%s", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func listPolicies(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	rows, err := db.QueryContext(r.Context(), `
SELECT id::text, name, mode, priority, enabled, created_at, updated_at
FROM policies
ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type policyItem struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Mode      string    `json:"mode"`
		Priority  int       `json:"priority"`
		Enabled   bool      `json:"enabled"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	var items []policyItem
	for rows.Next() {
		var it policyItem
		if err := rows.Scan(&it.ID, &it.Name, &it.Mode, &it.Priority, &it.Enabled, &it.CreatedAt, &it.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func createPolicy(w http.ResponseWriter, r *http.Request, db *sql.DB, payload policyCreateRequest) {
	if payload.Name == "" || !isValidMode(payload.Mode) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and mode(block|log) are required"})
		return
	}
	if payload.Priority == 0 {
		payload.Priority = 100
	}

	id := uuid.NewString()
	_, err := db.ExecContext(r.Context(), `
INSERT INTO policies(id, name, mode, priority, enabled)
VALUES ($1::uuid, $2, $3, $4, TRUE)`, id, payload.Name, payload.Mode, payload.Priority)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeAuditLog(r.Context(), db, "system", "create", "policy", id, nil, map[string]any{
		"id": id, "name": payload.Name, "mode": payload.Mode, "priority": payload.Priority,
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":       id,
		"name":     payload.Name,
		"mode":     payload.Mode,
		"priority": payload.Priority,
	})
}

func updatePolicy(w http.ResponseWriter, r *http.Request, db *sql.DB, id string, payload policyUpdateRequest) {
	if payload.Name == "" || !isValidMode(payload.Mode) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and mode(block|log) are required"})
		return
	}
	if payload.Priority == 0 {
		payload.Priority = 100
	}

	enabled := true
	if payload.Enabled != nil {
		enabled = *payload.Enabled
	}
	res, err := db.ExecContext(r.Context(), `
UPDATE policies
SET name=$2, mode=$3, priority=$4, enabled=$5, updated_at=NOW()
WHERE id=$1::uuid`, id, payload.Name, payload.Mode, payload.Priority, enabled)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
		return
	}
	writeAuditLog(r.Context(), db, "system", "update", "policy", id, nil, map[string]any{
		"id": id, "name": payload.Name, "mode": payload.Mode, "priority": payload.Priority, "enabled": enabled,
	})
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
}

func createRule(w http.ResponseWriter, r *http.Request, db *sql.DB, policyID string, payload ruleCreateRequest) {
	if err := validateRulePayload(payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	id := uuid.NewString()
	enabled := true
	if payload.Enabled != nil {
		enabled = *payload.Enabled
	}

	_, err := db.ExecContext(r.Context(), `
INSERT INTO rules(id, policy_id, name, action, priority, condition_json, transform_json, enabled)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb, COALESCE(NULLIF($7::text, '')::jsonb, '{}'::jsonb), $8)`,
		id, policyID, payload.Name, payload.Action, defaultPriority(payload.Priority), jsonOrEmpty(payload.Condition), string(payload.Transform), enabled)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeAuditLog(r.Context(), db, "system", "create", "rule", id, nil, map[string]any{
		"id": id, "policy_id": policyID, "name": payload.Name, "action": payload.Action,
	})
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "policy_id": policyID})
}

func updateRule(w http.ResponseWriter, r *http.Request, db *sql.DB, id string, payload ruleCreateRequest) {
	if err := validateRulePayload(payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	enabled := true
	if payload.Enabled != nil {
		enabled = *payload.Enabled
	}
	res, err := db.ExecContext(r.Context(), `
UPDATE rules
SET name=$2, action=$3, priority=$4, condition_json=$5::jsonb, transform_json=COALESCE(NULLIF($6::text, '')::jsonb, '{}'::jsonb), enabled=$7, updated_at=NOW()
WHERE id=$1::uuid`,
		id, payload.Name, payload.Action, defaultPriority(payload.Priority), jsonOrEmpty(payload.Condition), string(payload.Transform), enabled)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	writeAuditLog(r.Context(), db, "system", "update", "rule", id, nil, map[string]any{
		"id": id, "name": payload.Name, "action": payload.Action, "priority": payload.Priority, "enabled": enabled,
	})
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
}

func publishPolicy(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, policyID string) {
	ctx := r.Context()
	nextVersion, err := doPublish(ctx, db, rdb, policyID, "system")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeAuditLog(r.Context(), db, "system", "publish", "policy", policyID, nil, map[string]any{
		"policy_id": policyID, "version": nextVersion,
	})
	writeJSON(w, http.StatusAccepted, map[string]any{"policy_id": policyID, "version": nextVersion, "status": "published"})
}

func doPublish(ctx context.Context, db *sql.DB, rdb *redis.Client, policyID, publishedBy string) (int64, error) {
	var nextVersion int64 = 1
	if err := db.QueryRowContext(ctx, `
SELECT COALESCE(MAX(version), 0) + 1
FROM policy_versions
WHERE policy_id = $1::uuid`, policyID).Scan(&nextVersion); err != nil {
		return 0, err
	}
	snapshot, err := buildPolicySnapshotJSON(ctx, db, policyID)
	if err != nil {
		return 0, err
	}
	versionID := uuid.NewString()
	if _, err := db.ExecContext(ctx, `
INSERT INTO policy_versions(id, policy_id, version, snapshot_json, published_by)
VALUES ($1::uuid, $2::uuid, $3, $4::jsonb, $5)`,
		versionID, policyID, nextVersion, snapshot, publishedBy); err != nil {
		return 0, err
	}
	if err := rdb.Publish(ctx, "policy_updates", fmt.Sprintf(`{"policy_id":"%s","version":%d}`, policyID, nextVersion)).Err(); err != nil {
		return 0, err
	}
	return nextVersion, nil
}

func owaspPacksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": owasp.ListPacks()})
}

func importOWASPHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req importOWASPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.PackID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pack_id is required"})
		return
	}
	if req.PolicyName == "" {
		req.PolicyName = "OWASP CRS Lite"
	}
	if req.Mode == "" {
		req.Mode = "block"
	}
	if !isValidMode(req.Mode) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be block or log"})
		return
	}
	if req.Priority == 0 {
		req.Priority = 50
	}
	publisher := req.PublishedBy
	if publisher == "" {
		publisher = "system"
	}

	pack, err := owasp.LoadPack(req.PackID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	ctx := r.Context()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer func() { _ = tx.Rollback() }()

	policyID := uuid.NewString()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO policies(id, name, mode, priority, enabled)
VALUES ($1::uuid, $2, $3, $4, TRUE)`,
		policyID, req.PolicyName, req.Mode, req.Priority); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	ruleCount := 0
	for _, pr := range pack.Rules {
		if err := validateRuleAction(pr.Action); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("pack rule %q: %v", pr.Name, err)})
			return
		}
		ruleName := pr.Name
		if pr.CRSRuleID != "" {
			ruleName = "[" + pr.CRSRuleID + "] " + pr.Name
		}
		tf := string(pr.Transform)
		if tf == "" {
			tf = "{}"
		}
		ruleID := uuid.NewString()
		if _, err := tx.ExecContext(ctx, `
INSERT INTO rules(id, policy_id, name, action, priority, condition_json, transform_json, enabled)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb, $7::jsonb, TRUE)`,
			ruleID, policyID, ruleName, pr.Action, pr.Priority, string(pr.Condition), tf); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		ruleCount++
	}

	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeAuditLog(ctx, db, publisher, "import", "policy", policyID, nil, map[string]any{
		"pack_id": req.PackID, "policy_name": req.PolicyName, "rules": ruleCount,
	})

	resp := map[string]any{
		"policy_id":  policyID,
		"pack_id":    pack.PackID,
		"rules":      ruleCount,
		"published":  false,
		"publish_version": nil,
	}

	if req.Publish {
		nextVersion, err := doPublish(ctx, db, rdb, policyID, publisher)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeAuditLog(ctx, db, publisher, "publish", "policy", policyID, nil, map[string]any{
			"policy_id": policyID, "version": nextVersion,
		})
		resp["published"] = true
		resp["publish_version"] = nextVersion
	}

	writeJSON(w, http.StatusCreated, resp)
}

func buildPolicySnapshotJSON(ctx context.Context, db *sql.DB, policyID string) ([]byte, error) {
	var name, mode string
	var priority int
	var enabled bool
	err := db.QueryRowContext(ctx, `
SELECT name, mode, priority, enabled FROM policies WHERE id=$1::uuid`, policyID).Scan(&name, &mode, &priority, &enabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errPolicyNotFound
		}
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT id::text, name, action, priority, condition_json, COALESCE(transform_json, '{}'::jsonb), enabled
FROM rules
WHERE policy_id = $1::uuid
ORDER BY priority ASC, created_at ASC`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type ruleSnapshot struct {
		ID            string          `json:"id"`
		Name          string          `json:"name"`
		Action        string          `json:"action"`
		Priority      int             `json:"priority"`
		Enabled       bool            `json:"enabled"`
		ConditionJSON json.RawMessage `json:"condition_json"`
		TransformJSON json.RawMessage `json:"transform_json"`
	}
	type policySnapshot struct {
		ID       string         `json:"id"`
		Name     string         `json:"name"`
		Mode     string         `json:"mode"`
		Priority int            `json:"priority"`
		Enabled  bool           `json:"enabled"`
		Rules    []ruleSnapshot `json:"rules"`
	}
	ps := policySnapshot{ID: policyID, Name: name, Mode: mode, Priority: priority, Enabled: enabled}
	for rows.Next() {
		var rs ruleSnapshot
		if err := rows.Scan(&rs.ID, &rs.Name, &rs.Action, &rs.Priority, &rs.ConditionJSON, &rs.TransformJSON, &rs.Enabled); err != nil {
			return nil, err
		}
		ps.Rules = append(ps.Rules, rs)
	}
	return json.Marshal(ps)
}

func validateRuleAction(action string) error {
	switch action {
	case "allow", "block", "log", "redirect", "replace":
		return nil
	default:
		return errors.New("invalid action")
	}
}

func validateRulePayload(payload ruleCreateRequest) error {
	if payload.Name == "" {
		return errors.New("name is required")
	}
	return validateRuleAction(payload.Action)
}

func defaultPriority(p int) int {
	if p == 0 {
		return 100
	}
	return p
}

func jsonOrEmpty(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

func isValidMode(mode string) bool {
	return mode == "block" || mode == "log"
}

func writeAuditLog(ctx context.Context, db *sql.DB, actor, operation, entityType, entityID string, before any, after any) {
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	_, err := db.ExecContext(ctx, `
INSERT INTO audit_logs(actor, operation, entity_type, entity_id, before_json, after_json)
VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb)`,
		actor, operation, entityType, entityID, string(beforeJSON), string(afterJSON))
	if err != nil {
		log.Printf("failed to write audit log: %v", err)
	}
}
