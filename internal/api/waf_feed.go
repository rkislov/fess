package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fence/pkg/appsecadapt"
	"fence/pkg/auth"
	"fence/pkg/policy"
	"fence/pkg/wafpack"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type wafCatalog struct {
	Format string    `json:"format"`
	Packs  []wafMeta `json:"packs"`
}
type wafMeta struct {
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	Title       string   `json:"title"`
	RuleCount   int      `json:"rule_count"`
	SHA         string   `json:"sha256"`
	Limitations []string `json:"limitations"`
}

func fetchWAF(ctx context.Context, db *sql.DB, path string) ([]byte, error) {
	cfg, e := loadThreatFeedConfig(ctx, db)
	if e != nil {
		return nil, e
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("настройте API-ключ подписки FESS Feed")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, cfg.ResolvedFessFeedBase()+"/feeds/v1/waf/"+path, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("X-Api-Key", cfg.APIKey)
	// Never forward a subscription key to redirect targets.
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("Feed недоступен")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Feed HTTP %d", resp.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("ответ превышает 1 МиБ")
	}
	return raw, nil
}
func loadWAFCatalog(ctx context.Context, db *sql.DB) (wafCatalog, error) {
	var c wafCatalog
	b, e := fetchWAF(ctx, db, "catalog.json")
	if e != nil {
		return c, e
	}
	e = json.Unmarshal(b, &c)
	if e == nil && (c.Format != "security-feed-waf-catalog-v1" || len(c.Packs) > 64) {
		e = fmt.Errorf("invalid catalog")
	}
	return c, e
}

// The import is atomic, idempotent by content hash, disabled and never published.
func importWAFPacks(ctx context.Context, db *sql.DB, raws [][]byte) ([]string, error) {
	packs := make([]wafpack.Pack, len(raws))
	for i, b := range raws {
		p, e := wafpack.Parse(b)
		if e != nil {
			return nil, e
		}
		packs[i] = p
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	ids := []string{}
	for i, p := range packs {
		id := uuid.NewSHA1(uuid.NameSpaceURL, []byte("fess-waf:"+p.ID+":"+p.Version+":"+wafpack.Digest(raws[i]))).String()
		ids = append(ids, id)
		var count int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies WHERE id=$1::uuid", id).Scan(&count); e != nil {
			return nil, e
		}
		if count > 0 {
			continue
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO policies(id,name,mode,priority,enabled) VALUES($1::uuid,$2,'log',50,FALSE)`, id, p.Title+" · "+p.Version); e != nil {
			return nil, e
		}
		for _, r := range p.Rules {
			if _, e = tx.ExecContext(ctx, `INSERT INTO rules(id,policy_id,name,action,priority,condition_json,transform_json,enabled) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6::jsonb,'{}'::jsonb,TRUE)`, uuid.NewString(), id, "["+r.ID+"] "+r.Name, r.Action, r.Priority, string(r.Condition)); e != nil {
				return nil, e
			}
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	for i, id := range ids {
		writeAuditLog(ctx, db, auth.ActorFromContext(ctx), "import_waf_feed", "policy", id, nil, map[string]any{"pack_id": packs[i].ID, "version": packs[i].Version, "sha256": wafpack.Digest(raws[i]), "license": packs[i].License, "mode": "log", "published": false})
	}
	return ids, nil
}
func wafFeedHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	fail := func(status int, e error) { writeJSON(w, status, map[string]string{"error": e.Error()}) }
	switch r.URL.Path {
	case "/api/v1/waf-feed/catalog":
		if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		c, e := loadWAFCatalog(r.Context(), db)
		if e != nil {
			fail(502, e)
			return
		}
		writeJSON(w, 200, c)
	case "/api/v1/waf-feed/import":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		var q struct {
			ID      string `json:"id"`
			Version string `json:"version"`
		}
		if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&q); e != nil {
			fail(400, e)
			return
		}
		if !wafpack.Identifier.MatchString(q.ID) || !wafpack.Identifier.MatchString(q.Version) {
			fail(400, fmt.Errorf("invalid pack id/version"))
			return
		}
		c, e := loadWAFCatalog(r.Context(), db)
		if e != nil {
			fail(502, e)
			return
		}
		sum := ""
		for _, m := range c.Packs {
			if m.ID == q.ID && m.Version == q.Version {
				sum = m.SHA
			}
		}
		if sum == "" {
			fail(404, fmt.Errorf("pack not in catalog"))
			return
		}
		b, e := fetchWAF(r.Context(), db, "packs/"+q.ID+"/"+q.Version+".json")
		if e != nil {
			fail(502, e)
			return
		}
		if wafpack.Digest(b) != sum {
			fail(400, fmt.Errorf("SHA-256 mismatch"))
			return
		}
		p, e := wafpack.Parse(b)
		if e != nil {
			fail(400, e)
			return
		}
		if p.ID != q.ID || p.Version != q.Version {
			fail(400, fmt.Errorf("pack metadata mismatch"))
			return
		}
		ids, e := importWAFPacks(r.Context(), db, [][]byte{b})
		if e != nil {
			fail(400, e)
			return
		}
		writeJSON(w, 201, map[string]any{"policy_ids": ids, "enabled": false, "mode": "log", "published": false})
	case "/api/v1/waf-feed/offline":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
		if e != nil {
			fail(400, e)
			return
		}
		raws, e := wafpack.DecodeArchive(b)
		if e != nil {
			fail(400, e)
			return
		}
		ids, e := importWAFPacks(r.Context(), db, raws)
		if e != nil {
			fail(400, e)
			return
		}
		writeJSON(w, 201, map[string]any{"policy_ids": ids, "enabled": false, "mode": "log", "published": false})
	case "/api/v1/waf-feed/crowdsec/preview":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if e != nil {
			fail(400, e)
			return
		}
		report := appsecadapt.Adapt(b)
		out := map[string]any{"report": report}
		if report.Supported {
			cond, _ := json.Marshal(map[string]any{"appsec": report.Expression})
			p := wafpack.Pack{Format: "security-feed-waf-v1", Engine: "fess-native-v2", ID: "crowdsec-" + report.SHA256[:16], Version: "1.0.0", Title: report.Name, License: "MIT (CrowdSec Hub; verify source license)", Rules: []wafpack.Rule{{ID: "CS-" + report.SHA256[:16], Name: report.Name, Action: "block", Priority: 50, Condition: cond}}}
			out["pack"] = p
		}
		writeJSON(w, 200, out)
	case "/api/v1/waf-feed/adaptation/hits":
		if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		pid := r.URL.Query().Get("policy_id")
		if _, e := uuid.Parse(pid); e != nil {
			fail(400, e)
			return
		}
		rows, e := db.QueryContext(r.Context(), `SELECT wl.rule_id::text,COALESCE(wl.host,''),wl.path,wl.method,COUNT(*) FROM waf_logs wl JOIN policies p ON p.id=wl.policy_id JOIN rules r ON r.id=wl.rule_id AND r.policy_id=p.id WHERE p.id=$1::uuid AND p.mode='log' AND wl.created_at >= $2 AND wl.action IN ('log','waf_log') GROUP BY wl.rule_id,wl.host,wl.path,wl.method ORDER BY COUNT(*) DESC LIMIT 100`, pid, time.Now().UTC().Add(-24*time.Hour))
		if e != nil {
			fail(500, e)
			return
		}
		defer rows.Close()
		type hit struct {
			RuleID string `json:"rule_id"`
			Host   string `json:"host"`
			Path   string `json:"path"`
			Method string `json:"method"`
			Count  int    `json:"count"`
		}
		items := []hit{}
		for rows.Next() {
			var h hit
			if e = rows.Scan(&h.RuleID, &h.Host, &h.Path, &h.Method, &h.Count); e != nil {
				fail(500, e)
				return
			}
			items = append(items, h)
		}
		if e = rows.Err(); e != nil {
			fail(500, e)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items, "hours": 24, "note": "Только первое сработавшее правило. Частота не доказывает ложное срабатывание."})
	case "/api/v1/waf-feed/adaptation/exception":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		var q struct {
			RuleID    string               `json:"rule_id"`
			Confirmed bool                 `json:"confirmed"`
			Exception policy.RuleException `json:"exception"`
		}
		if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&q); e != nil {
			fail(400, e)
			return
		}
		if _, e := uuid.Parse(q.RuleID); e != nil || !q.Confirmed {
			fail(400, fmt.Errorf("rule_id and explicit confirmation required"))
			return
		}
		if h, _, err := net.SplitHostPort(q.Exception.Host); err == nil {
			q.Exception.Host = h
		}
		q.Exception.Host = strings.ToLower(strings.TrimSuffix(q.Exception.Host, "."))
		tx, e := db.BeginTx(r.Context(), nil)
		if e != nil {
			fail(500, e)
			return
		}
		defer tx.Rollback()
		var raw []byte
		var mode string
		if e = tx.QueryRowContext(r.Context(), `SELECT r.condition_json,p.mode FROM rules r JOIN policies p ON p.id=r.policy_id WHERE r.id=$1::uuid`, q.RuleID).Scan(&raw, &mode); e != nil {
			fail(404, fmt.Errorf("rule not found"))
			return
		}
		if mode != "log" {
			fail(409, fmt.Errorf("adaptation requires log mode"))
			return
		}
		var c map[string]json.RawMessage
		if e = json.Unmarshal(raw, &c); e != nil {
			fail(400, e)
			return
		}
		var ex []policy.RuleException
		if b := c["exceptions"]; len(b) > 0 {
			if e = json.Unmarshal(b, &ex); e != nil {
				fail(400, e)
				return
			}
		}
		exists := false
		for _, v := range ex {
			if v == q.Exception {
				exists = true
			}
		}
		if !exists {
			ex = append(ex, q.Exception)
		}
		c["exceptions"], _ = json.Marshal(ex)
		next, _ := json.Marshal(c)
		if _, e = policy.CompileCondition(next); e != nil {
			fail(400, e)
			return
		}
		res, e := tx.ExecContext(r.Context(), `UPDATE rules SET condition_json=$2::jsonb,updated_at=NOW() WHERE id=$1::uuid AND condition_json=$3::jsonb`, q.RuleID, string(next), string(raw))
		if e != nil {
			fail(500, e)
			return
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			fail(409, fmt.Errorf("rule changed; reload and retry"))
			return
		}
		if e = tx.Commit(); e != nil {
			fail(500, e)
			return
		}
		writeAuditLog(r.Context(), db, auth.ActorFromContext(r.Context()), "adaptation_exception_draft", "rule", q.RuleID, json.RawMessage(raw), json.RawMessage(next))
		writeJSON(w, 200, map[string]any{"published": false, "exception": q.Exception})
	default:
		w.WriteHeader(404)
	}
}
