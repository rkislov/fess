package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	aiMaxProxyRows  = 100
	aiMaxWafRows    = 100
	aiDefaultRows   = 40
	aiHTTPTimeout   = 120 * time.Second
	aiMaxCondRunes  = 600
	aiMaxPathRunes  = 200
	aiMaxUARunes    = 160
)

type aiSettingsResponse struct {
	Configured bool   `json:"configured"`
	Model      string `json:"model"`
	BaseURL    string `json:"base_url"`
}

type aiAnalyzeRequest struct {
	IncludeProxyLogs        bool   `json:"include_proxy_logs"`
	IncludeWafLogs          bool   `json:"include_waf_logs"`
	IncludePolicySnapshot   bool   `json:"include_policy_snapshot"`
	ProxyLimit              int    `json:"proxy_limit"`
	WafLimit                int    `json:"waf_limit"`
	ExtraContext            string `json:"extra_context"`
}

type aiAnalyzeResponse struct {
	Analysis string `json:"analysis"`
	Model    string `json:"model"`
}

func aiSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	key := strings.TrimSpace(os.Getenv("FENCE_AI_API_KEY"))
	writeJSON(w, http.StatusOK, aiSettingsResponse{
		Configured: key != "",
		Model:      aiModel(),
		BaseURL:    aiBaseURL(),
	})
}

func aiAnalyzeHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	key := strings.TrimSpace(os.Getenv("FENCE_AI_API_KEY"))
	if key == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "ИИ не настроен: задайте переменную окружения FENCE_AI_API_KEY для сервиса policy-api (см. README).",
		})
		return
	}

	var req aiAnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	pl := req.ProxyLimit
	if pl <= 0 {
		pl = aiDefaultRows
	}
	if pl > aiMaxProxyRows {
		pl = aiMaxProxyRows
	}
	wl := req.WafLimit
	if wl <= 0 {
		wl = aiDefaultRows
	}
	if wl > aiMaxWafRows {
		wl = aiMaxWafRows
	}
	if !req.IncludeProxyLogs && !req.IncludeWafLogs && !req.IncludePolicySnapshot && strings.TrimSpace(req.ExtraContext) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "включите хотя бы один источник данных или заполните дополнительный контекст",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), aiHTTPTimeout)
	defer cancel()

	var parts []string
	if req.IncludePolicySnapshot {
		snap, err := fetchPoliciesRulesSummary(ctx, db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		parts = append(parts, "### Текущие политики и правила Fence\n"+snap)
	}
	if req.IncludeProxyLogs {
		s, err := fetchProxyLogsSnippet(ctx, db, pl)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		parts = append(parts, fmt.Sprintf("### Последние записи журнала соединений (до %d строк)\n%s", pl, s))
	}
	if req.IncludeWafLogs {
		s, err := fetchWafLogsSnippet(ctx, db, wl)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		parts = append(parts, fmt.Sprintf("### Последние записи журнала срабатываний WAF / вредоносного ПО (до %d строк)\n%s", wl, s))
	}
	if xc := strings.TrimSpace(req.ExtraContext); xc != "" {
		if len(xc) > 12000 {
			xc = xc[:12000] + "\n…(обрезано)"
		}
		parts = append(parts, "### Дополнительный контекст от оператора\n"+xc)
	}
	userPrompt := strings.Join(parts, "\n\n")

	systemPrompt := `Ты помощник администратора веб‑шлюза Fence (reverse proxy с WAF, политиками и антивирусом через ICAP).

Тебе переданы выдержки из журналов соединений (proxy_access_logs), из журнала срабатываний (waf_logs) и/или список политик и правил.

Задачи:
1. Кратко опиши картину трафика и срабатываний (если данных мало — так и скажи).
2. Предложи, какие правила или политики имеет смысл **включить**, **выключить**, **ослабить** или **добавить** (с привязкой к UUID правил/политик из данных, если они есть).
3. Отдельно оцени **риск ложных срабатываний (false positives)**: по каким признакам запросы могут быть легитимными; что уточнить или как безопасно проверить (например log‑режим, сужение условия, исключения по пути или методу).
4. Если рекомендуешь блокировки — укажи осторожность и поэтапное внедрение.

Отвечай на русском языке, структурировано (заголовки, списки). Не выдумывай UUID: используй только те, что в данных.`

	analysis, err := callChatCompletions(ctx, key, systemPrompt, userPrompt)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, aiAnalyzeResponse{Analysis: analysis, Model: aiModel()})
}

func aiBaseURL() string {
	u := strings.TrimSpace(os.Getenv("FENCE_AI_BASE_URL"))
	if u == "" {
		return "https://api.openai.com/v1"
	}
	return strings.TrimRight(u, "/")
}

func aiModel() string {
	m := strings.TrimSpace(os.Getenv("FENCE_AI_MODEL"))
	if m == "" {
		return "gpt-4o-mini"
	}
	return m
}

func truncateRunes(s string, max int) string {
	if max <= 0 || s == "" {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

func fetchPoliciesRulesSummary(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx, `
SELECT p.id::text, p.name, p.mode, p.priority, p.enabled,
       COALESCE(r.id::text, ''), COALESCE(r.name, ''), COALESCE(r.action, ''), COALESCE(r.priority, 0), COALESCE(r.enabled, false),
       LEFT(COALESCE(r.condition_json::text, '{}'), 2000)
FROM policies p
LEFT JOIN rules r ON r.policy_id = p.id
ORDER BY p.priority ASC, p.created_at ASC, r.priority ASC, r.created_at ASC`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var b strings.Builder
	lastPolicy := ""
	for rows.Next() {
		var pid, pname, mode string
		var pp int
		var pen bool
		var rid, rname, action string
		var rp int
		var ren bool
		var cond string
		if err := rows.Scan(&pid, &pname, &mode, &pp, &pen, &rid, &rname, &action, &rp, &ren, &cond); err != nil {
			return "", err
		}
		if pid != lastPolicy {
			fmt.Fprintf(&b, "\nПолитика %q id=%s mode=%s priority=%d enabled=%v\n", pname, pid, mode, pp, pen)
			lastPolicy = pid
		}
		if rid != "" {
			fmt.Fprintf(&b, "  • Правило %q id=%s action=%s priority=%d enabled=%v\n    condition (фрагмент): %s\n",
				rname, rid, action, rp, ren, truncateRunes(cond, aiMaxCondRunes))
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "(политик нет)", nil
	}
	return out, nil
}

func fetchProxyLogsSnippet(ctx context.Context, db *sql.DB, limit int) (string, error) {
	rows, err := db.QueryContext(ctx, `
SELECT host, method, path, COALESCE(client_ip,''), COALESCE(outcome,''), COALESCE(country_code,''),
       COALESCE(user_agent,''), created_at
FROM proxy_access_logs
ORDER BY created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var host, method, path, ip, out, cc, ua string
		var ts time.Time
		if err := rows.Scan(&host, &method, &path, &ip, &out, &cc, &ua, &ts); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s | %s %s | client_ip=%s | %s | %s | ua=%s\n",
			ts.UTC().Format(time.RFC3339), method, truncateRunes(path, aiMaxPathRunes), ip, out, cc, truncateRunes(ua, aiMaxUARunes))
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	s := strings.TrimSpace(b.String())
	if s == "" {
		return "(записей нет)", nil
	}
	return s, nil
}

func fetchWafLogsSnippet(ctx context.Context, db *sql.DB, limit int) (string, error) {
	rows, err := db.QueryContext(ctx, `
SELECT created_at, action, COALESCE(policy_id::text,''), COALESCE(rule_id::text,''),
       COALESCE(source_ip,''), COALESCE(method,''), COALESCE(path,''),
       LEFT(COALESCE(details::text,'{}'), 800)
FROM waf_logs
ORDER BY created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var ts time.Time
		var action, pol, rule, sip, meth, path, det string
		if err := rows.Scan(&ts, &action, &pol, &rule, &sip, &meth, &path, &det); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s | %s | policy=%s rule=%s | %s %s | details=%s\n",
			ts.UTC().Format(time.RFC3339), action, pol, rule, sip, meth, truncateRunes(path, aiMaxPathRunes), truncateRunes(det, 800))
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	s := strings.TrimSpace(b.String())
	if s == "" {
		return "(записей нет)", nil
	}
	return s, nil
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatReq struct {
	Model       string            `json:"model"`
	Messages    []openAIMessage   `json:"messages"`
	Temperature float64           `json:"temperature"`
	MaxTokens   int               `json:"max_tokens"`
}

type openAIChatResp struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func callChatCompletions(ctx context.Context, apiKey, systemPrompt, userPrompt string) (string, error) {
	url := aiBaseURL() + "/chat/completions"
	body, err := json.Marshal(openAIChatReq{
		Model:       aiModel(),
		Temperature: 0.35,
		MaxTokens:   4096,
		Messages: []openAIMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	})
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: aiHTTPTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("запрос к ИИ: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("ИИ вернул HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var parsed openAIChatResp
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("разбор ответа ИИ: %w", err)
	}
	if parsed.Error != nil && parsed.Error.Message != "" {
		return "", fmt.Errorf("ИИ: %s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 || strings.TrimSpace(parsed.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("пустой ответ от ИИ")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}
