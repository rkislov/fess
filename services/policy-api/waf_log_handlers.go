package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"fence/pkg/routing"
)

const wafRuleHitsMaxPage = 200

type wafRuleHitAgg struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	PolicyID    string `json:"policy_id"`
	PolicyName  string `json:"policy_name"`
	Action      string `json:"action"`
	Count       int64  `json:"count"`
	LastAt      string `json:"last_hit_at"`
}

func wafRuleHitsHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	hours := parseHoursQuery(r.URL.Query().Get("hours"), 168)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	limit, offset, pageErr := parseWafFlexiblePagination(r)
	if pageErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": pageErr.Error()})
		return
	}

	ctx := r.Context()

	var total int64
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM (
  SELECT 1 FROM waf_logs wl
  WHERE wl.created_at >= $1 AND wl.rule_id IS NOT NULL
  GROUP BY wl.rule_id, wl.action
) t`, since).Scan(&total); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	rows, err := db.QueryContext(ctx, `
SELECT COALESCE(MAX(wl.rule_id::text), '') AS rule_id,
       wl.action,
       COUNT(*)::bigint AS cnt,
       MAX(wl.created_at) AS last_at,
       MAX(COALESCE(r.name, '')) AS rule_name,
       COALESCE(MAX(wl.policy_id::text), '') AS policy_id,
       MAX(COALESCE(p.name, '')) AS policy_name
FROM waf_logs wl
LEFT JOIN rules r ON r.id = wl.rule_id
LEFT JOIN policies p ON p.id = wl.policy_id
WHERE wl.created_at >= $1 AND wl.rule_id IS NOT NULL
GROUP BY wl.rule_id, wl.action
ORDER BY cnt DESC
LIMIT $2 OFFSET $3`, since, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	var items []wafRuleHitAgg
	for rows.Next() {
		var it wafRuleHitAgg
		var last time.Time
		if err := rows.Scan(&it.RuleID, &it.Action, &it.Count, &last, &it.RuleName, &it.PolicyID, &it.PolicyName); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		it.LastAt = last.UTC().Format(time.RFC3339Nano)
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": total, "limit": limit, "offset": offset, "hours": hours,
		"since": since.Format(time.RFC3339Nano),
	})
}

func parseHoursQuery(raw string, maxHours int) int {
	if raw == "" {
		return 24
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 24
	}
	if n > maxHours {
		n = maxHours
	}
	return n
}

// Pagination for explorer: default 50, max 200.
func parseWafFlexiblePagination(r *http.Request) (limit, offset int, err error) {
	q := r.URL.Query()
	ls := strings.TrimSpace(q.Get("limit"))
	os := strings.TrimSpace(q.Get("offset"))
	limit = 50
	if ls != "" {
		limit, err = strconv.Atoi(ls)
		if err != nil || limit < 1 {
			return 0, 0, fmt.Errorf("invalid limit")
		}
		if limit > wafRuleHitsMaxPage {
			limit = wafRuleHitsMaxPage
		}
	}
	offset = 0
	if os != "" {
		offset, err = strconv.Atoi(os)
		if err != nil || offset < 0 {
			return 0, 0, fmt.Errorf("invalid offset")
		}
	}
	return limit, offset, nil
}

func wafLogEventsPathRouter(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/waf-log-events")
	p = strings.Trim(p, "/")
	if p == "" {
		wafLogEventsListHandler(w, r, db)
		return
	}
	parts := strings.Split(p, "/")
	idStr := parts[0]
	eventID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || eventID < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid event id"})
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			wafLogEventDetailHandler(w, r, db, eventID)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "ai-review" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		wafLogEventAIReviewHandler(w, r, db, eventID)
		return
	}
	if len(parts) == 2 && parts[1] == "unblock" {
		wafLogEventUnblockHandler(w, r, db, rdb, eventID)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func wafLogEventsListHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := validateWafLogFilters(r); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	limit, offset, perr := parseWafFlexiblePagination(r)
	if perr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": perr.Error()})
		return
	}

	since, useSince := parseOptionalHours(r.URL.Query().Get("hours"), 168, true)
	qb := buildWafLogsQuery(r, 168)
	where := qb.whereSQL()
	args := qb.argsSlice()
	ctx := r.Context()

	var total int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM waf_logs `+where, args...).Scan(&total); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	lim := len(args) + 1
	off := len(args) + 2
	listArgs := append(append([]any{}, args...), limit, offset)
	rows, err := db.QueryContext(ctx, `
SELECT id, request_id, COALESCE(policy_id::text, ''), COALESCE(rule_id::text, ''),
       action, source_ip, method, path, COALESCE(host,''), ai_analysis,
       COALESCE(details, '{}'::jsonb), created_at
FROM waf_logs `+where+fmt.Sprintf(`
ORDER BY created_at DESC
LIMIT $%d OFFSET $%d`, lim, off), listArgs...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type row struct {
		ID          int64           `json:"id"`
		RequestID   string          `json:"request_id"`
		PolicyID    string          `json:"policy_id"`
		RuleID      string          `json:"rule_id"`
		Action      string          `json:"action"`
		SourceIP    string          `json:"source_ip"`
		Method      string          `json:"method"`
		Path        string          `json:"path"`
		Host        string          `json:"host"`
		AIAnalysis  string          `json:"ai_analysis"`
		Details     json.RawMessage `json:"details"`
		CreatedAt   time.Time       `json:"created_at"`
	}
	var out []row
	for rows.Next() {
		var it row
		if err := rows.Scan(&it.ID, &it.RequestID, &it.PolicyID, &it.RuleID, &it.Action, &it.SourceIP, &it.Method, &it.Path, &it.Host, &it.AIAnalysis, &it.Details, &it.CreatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, it)
	}
	meta := map[string]any{"items": out, "total": total, "limit": limit, "offset": offset}
	if useSince && since != nil {
		meta["since"] = since.Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, meta)
}

type siteBrief struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	HostPattern string `json:"host_pattern"`
	PolicyID    string `json:"policy_id"`
}

func sitesMatchingHost(ctx context.Context, db *sql.DB, host string) ([]siteBrief, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
SELECT id::text, name, host_pattern, COALESCE(policy_id::text, '')
FROM sites WHERE enabled = true ORDER BY priority ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []siteBrief
	for rows.Next() {
		var s siteBrief
		if err := rows.Scan(&s.ID, &s.Name, &s.HostPattern, &s.PolicyID); err != nil {
			return nil, err
		}
		if routing.HostMatch(s.HostPattern, host) {
			out = append(out, s)
		}
	}
	return out, rows.Err()
}

type ruleBrief struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Action   string `json:"action"`
	Priority int    `json:"priority"`
	Enabled  bool   `json:"enabled"`
	PolicyID string `json:"policy_id"`
}

type policyBrief struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Mode   string `json:"mode"`
	Active bool   `json:"enabled"`
}

func wafLogEventDetailHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, eventID int64) {
	ctx := r.Context()
	var (
		requestID string
		policyID  string
		ruleID    string
		action    string
		sourceIP  string
		method    string
		path      string
		host      string
		aiText    string
		details   json.RawMessage
		created   time.Time
	)
	err := db.QueryRowContext(ctx, `
SELECT request_id, COALESCE(policy_id::text, ''), COALESCE(rule_id::text, ''),
       action, source_ip, method, path, COALESCE(host,''), COALESCE(ai_analysis,''),
       COALESCE(details, '{}'::jsonb), created_at
FROM waf_logs WHERE id = $1`, eventID).Scan(
		&requestID, &policyID, &ruleID, &action, &sourceIP, &method, &path, &host, &aiText, &details, &created,
	)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	sites, _ := sitesMatchingHost(ctx, db, host)

	var rb *ruleBrief
	var pol *policyBrief
	if ruleID != "" {
		if rid, err := uuid.Parse(ruleID); err == nil {
			var name, ra, pid string
			var pri int
			var en bool
			qerr := db.QueryRowContext(ctx, `
SELECT name, action, priority, enabled, policy_id::text FROM rules WHERE id = $1::uuid`, rid.String()).Scan(&name, &ra, &pri, &en, &pid)
			if qerr == nil {
				rb = &ruleBrief{ID: ruleID, Name: name, Action: ra, Priority: pri, Enabled: en, PolicyID: pid}
			}
			if pid != "" {
				var pn, pm string
				var pe bool
				if qerr := db.QueryRowContext(ctx, `
SELECT name, mode, enabled FROM policies WHERE id = $1::uuid`, pid).Scan(&pn, &pm, &pe); qerr == nil {
					pol = &policyBrief{ID: pid, Name: pn, Mode: pm, Active: pe}
				}
			}
		}
	} else if policyID != "" {
		var pn, pm string
		var pe bool
		if qerr := db.QueryRowContext(ctx, `
SELECT name, mode, enabled FROM policies WHERE id = $1::uuid`, policyID).Scan(&pn, &pm, &pe); qerr == nil {
			pol = &policyBrief{ID: policyID, Name: pn, Mode: pm, Active: pe}
		}
	}

	unblockCtx := enrichUnblockContext(ctx, db, sourceIP, action)

	payload := map[string]any{
		"id":             eventID,
		"request_id":     requestID,
		"policy_id":      policyID,
		"policy":         pol,
		"rule_id":        ruleID,
		"rule":           rb,
		"action":         action,
		"source_ip":      sourceIP,
		"origin_label":   "Клиентский IP после учёта прокси (как записал шлюз)",
		"method":         method,
		"path":           path,
		"virtual_host":   host,
		"matching_sites": sites,
		"details":        details,
		"ai_analysis":    aiText,
		"created_at":     created.UTC().Format(time.RFC3339Nano),
		"unblock":        unblockCtx,
	}
	writeJSON(w, http.StatusOK, payload)
}

func enrichUnblockContext(ctx context.Context, db *sql.DB, sourceIP, action string) map[string]any {
	out := map[string]any{
		"can_unblock":       strings.TrimSpace(sourceIP) != "",
		"bypass_active":     false,
		"in_threat_feed":    false,
		"remove_from_feed": false,
	}
	if strings.TrimSpace(sourceIP) == "" {
		return out
	}
	active, bypassCIDR, err := ipBypassActive(ctx, db, sourceIP)
	if err == nil {
		out["bypass_active"] = active
		if active {
			out["bypass_cidr"] = bypassCIDR
		}
	}
	inFeed, _, err := ipInThreatFeed(ctx, db, sourceIP)
	if err == nil {
		out["in_threat_feed"] = inFeed
		out["remove_from_feed"] = inFeed
	}
	switch {
	case strings.HasPrefix(action, "threat_feed"):
		out["unblock_hint"] = "Добавит IP в обход и опционально удалит из блоклиста Q-feed."
	case strings.HasPrefix(action, "bot_"):
		out["unblock_hint"] = "Добавит IP в обход и сбросит счётчик rate limit в Redis."
	case action == "waf_block":
		out["unblock_hint"] = "Добавит IP в обход: правила WAF, threat feed и bot protection не применяются."
	case action == "malware_block":
		out["can_unblock"] = false
		out["unblock_hint"] = "Блокировка антивирусом — обход IP здесь не отключает ICAP."
	default:
		out["unblock_hint"] = "Добавит IP в список обхода на шлюзе."
	}
	return out
}

func wafLogEventAIReviewHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, eventID int64) {
	cfg, err := resolveAIConfig(r.Context(), db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !cfg.configured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": aiNotConfiguredMessage()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), cfg.Timeout)
	defer cancel()

	var (
		requestID, policyID, ruleID, action, sourceIP, method, path, host, existingAI string
		details                                                                        json.RawMessage
		created                                                                        time.Time
	)
	err = db.QueryRowContext(ctx, `
SELECT request_id, COALESCE(policy_id::text, ''), COALESCE(rule_id::text, ''),
       action, source_ip, method, path, COALESCE(host,''), COALESCE(ai_analysis,''),
       COALESCE(details, '{}'::jsonb), created_at
FROM waf_logs WHERE id = $1`, eventID).Scan(
		&requestID, &policyID, &ruleID, &action, &sourceIP, &method, &path, &host, &existingAI, &details, &created,
	)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(existingAI) != "" {
		writeJSON(w, http.StatusOK, map[string]any{"analysis": existingAI, "model": cfg.Model, "cached": true})
		return
	}

	var ruleName, policyName string
	if ruleID != "" {
		_ = db.QueryRowContext(ctx, `SELECT name FROM rules WHERE id = $1::uuid`, ruleID).Scan(&ruleName)
	}
	if policyID != "" {
		_ = db.QueryRowContext(ctx, `SELECT name FROM policies WHERE id = $1::uuid`, policyID).Scan(&policyName)
	}
	sites, _ := sitesMatchingHost(ctx, db, host)
	sitesJSON, _ := json.Marshal(sites)

	userPrompt := fmt.Sprintf(`Срабатывание WAF (id=%d):
- время: %s
- виртуальный хост: %q
- подходящие сайты (JSON): %s
- политика: %s (%s)
- правило: %s (%s)
- записанное действие: %s
- источник (IP): %s
- запрос: %s %s
- details: %s`,
		eventID, created.UTC().Format(time.RFC3339), host, string(sitesJSON),
		policyName, policyID, ruleName, ruleID, action, sourceIP, method, path, string(details))

	systemPrompt := `Ты аналитик безопасности Fence WAF. По одному срабатыванию дай краткий ответ на русском:
1) Что произошло (сайт/хост, правило, запрос).
2) Вероятная угроза или ложное срабатывание (false positive) — аргументы.
3) Рекомендация: включить правило / отключить / перевести политику или правило в режим только логирования (log) / оставить block — без автоматического применения.
Будь конкретен, не выдумывай UUID.`

	analysis, err := callChatCompletions(ctx, cfg, systemPrompt, userPrompt)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if _, err := db.ExecContext(ctx, `UPDATE waf_logs SET ai_analysis = $2 WHERE id = $1`, eventID, analysis); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"analysis": analysis, "model": cfg.Model, "cached": false})
}

type ruleQuickActionRequest struct {
	Action string `json:"action"` // enable | disable | log_only | block
}

func ruleQuickActionHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/")
	id = strings.TrimSuffix(id, "/quick-action")
	if id == "" || strings.Contains(id, "/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if _, err := uuid.Parse(id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rule id"})
		return
	}

	var body ruleQuickActionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	act := strings.TrimSpace(strings.ToLower(body.Action))
	switch act {
	case "enable", "disable", "log_only", "block":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action must be enable, disable, log_only, or block"})
		return
	}

	ctx := r.Context()
	var name, curAction string
	var priority int
	var cond, transform []byte
	var enabled bool
	var policyID string
	err := db.QueryRowContext(ctx, `
SELECT name, action, priority, condition_json, COALESCE(transform_json, '{}'::jsonb), enabled, policy_id::text
FROM rules WHERE id = $1::uuid`, id).Scan(&name, &curAction, &priority, &cond, &transform, &enabled, &policyID)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	newEnabled := enabled
	newAction := curAction
	switch act {
	case "enable":
		newEnabled = true
	case "disable":
		newEnabled = false
	case "log_only":
		newEnabled = true
		newAction = "log"
	case "block":
		newEnabled = true
		newAction = "block"
	}

	res, err := db.ExecContext(ctx, `
UPDATE rules SET enabled = $2, action = $3, updated_at = NOW() WHERE id = $1::uuid`,
		id, newEnabled, newAction)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}

	var publishedVersion int64
	if policyID != "" {
		publishedVersion, err = doPublish(ctx, db, rdb, policyID, "ui-quick-action")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rule updated but publish failed: " + err.Error()})
			return
		}
	}

	writeAuditLog(ctx, db, "ui", "quick_action", "rule", id, map[string]any{
		"enabled": enabled, "action": curAction,
	}, map[string]any{
		"quick_action": act, "enabled": newEnabled, "action": newAction, "published_version": publishedVersion,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "enabled": newEnabled, "action": newAction, "published_version": publishedVersion,
	})
}