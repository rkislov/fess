package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fencedb "fence/db"
	"fence/internal/api"
	"fence/internal/gateway"
	"fence/internal/runtimebus"
)

func openBackend(t *testing.T, backend string) *sql.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "fess.db")
	if backend == "postgres" {
		base := os.Getenv("FESS_TEST_POSTGRES")
		if base == "" {
			t.Skip("set FESS_TEST_POSTGRES for PostgreSQL integration")
		}
		admin, err := sql.Open("postgres", base)
		if err != nil {
			t.Fatal(err)
		}
		schema := fmt.Sprintf("fess_test_%d", time.Now().UnixNano())
		if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); admin.Close() })
		u, err := url.Parse(base)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		dsn = u.String()
	}
	d, err := fencedb.Open(context.Background(), backend, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err = fencedb.ApplyMigrations(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if err = fencedb.ApplyMigrations(context.Background(), d); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}
	return d
}
func TestNativeBackends(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			t.Setenv("FENCE_AUTH_DISABLED", "1")
			t.Setenv("FENCE_GEOIP_DATA_DIR", t.TempDir())
			d := openBackend(t, backend)
			ctx, cancel := context.WithCancel(context.Background())
			bus := runtimebus.New()
			t.Cleanup(func() { cancel(); bus.Close(); gateway.Close() })
			management, err := api.New(ctx, d, bus)
			if err != nil {
				t.Fatal(err)
			}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "origin-ok") }))
			defer origin.Close()
			call := func(method, path string, payload any) map[string]any {
				t.Helper()
				var body bytes.Buffer
				if payload != nil {
					json.NewEncoder(&body).Encode(payload)
				}
				rec := httptest.NewRecorder()
				management.ServeHTTP(rec, httptest.NewRequest(method, "http://admin"+path, &body))
				if rec.Code < 200 || rec.Code >= 300 {
					t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body.String())
				}
				var result map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
					t.Fatalf("decode %s: %v", path, err)
				}
				return result
			}
			// Check login/password hashing and stored token timestamps, even with API auth disabled.
			call("POST", "/api/v1/auth/login", map[string]any{"username": "admin", "password": "fessfess"})
			policy := call("POST", "/api/v1/policies", map[string]any{"name": "native-policy", "mode": "block", "priority": 10})
			pid := policy["id"].(string)
			call("POST", "/api/v1/policies/"+pid+"/rules", map[string]any{"name": "blocked-path", "action": "block", "priority": 1, "condition_json": map[string]any{"path_prefix": "/blocked"}})
			call("POST", "/api/v1/policies/"+pid+"/publish", map[string]any{})
			site := call("POST", "/api/v1/sites", map[string]any{"name": "app", "host_pattern": "app.test", "priority": 1, "policy_id": pid})
			sid := site["id"].(string)
			be := call("POST", "/api/v1/sites/"+sid+"/backends", map[string]any{"name": "origin", "base_url": origin.URL, "priority": 1})
			bid := be["id"].(string)
			call("POST", "/api/v1/backends/"+bid+"/paths", map[string]any{"path_prefix": "/extra", "priority": 1})
			gw, _, err := gateway.New(ctx, d, bus)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				path string
				code int
			}{{"/", 200}, {"/blocked", 403}, {"/extra", 200}} {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest("GET", "http://app.test"+tc.path, nil)
				gw.ServeHTTP(rec, req)
				if rec.Code != tc.code {
					t.Fatalf("gateway %s: %d %s", tc.path, rec.Code, rec.Body.String())
				}
			}
			// Exercise SQL reporting on nonempty logs, including dates, JSON and binning.
			for _, path := range []string{"/policies", "/policies/" + pid, "/sites", "/sites/" + sid + "/backends", "/backends/" + bid + "/paths", "/logs", "/logs?search=blocked", "/proxy-access-logs", "/proxy-access-logs?search=app", "/malware-scan-logs", "/dashboard/summary", "/dashboard/system", "/waf-rule-hits", "/waf-log-events", "/certificates", "/settings/acme", "/settings/auth", "/settings/siem-export", "/settings/ai", "/settings/malware", "/settings/bot-protection", "/settings/threat-feed", "/settings/rate-limit", "/ip-bypass", "/users"} {
				call("GET", "/api/v1"+path, nil)
			}
			// Runtime update: a rule change must reach the gateway without restart.
			call("PUT", "/api/v1/policies/"+pid, map[string]any{"name": "native-policy", "mode": "log", "priority": 10, "enabled": true})
			call("POST", "/api/v1/policies/"+pid+"/publish", map[string]any{})
			deadline := time.Now().Add(3 * time.Second)
			for {
				rec := httptest.NewRecorder()
				gw.ServeHTTP(rec, httptest.NewRequest("GET", "http://app.test/blocked", nil))
				if rec.Code == 200 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("policy update was not applied")
				}
				time.Sleep(10 * time.Millisecond)
			}
			// Rate limiting uses local counters, independent of any external service.
			call("PUT", "/api/v1/settings/rate-limit", map[string]any{"config": map[string]any{"enabled": true, "requests_per_window": 1, "window_sec": 60, "scope": "ip"}})
			deadline = time.Now().Add(3 * time.Second)
			for {
				rec := httptest.NewRecorder()
				gw.ServeHTTP(rec, httptest.NewRequest("GET", "http://app.test/limit", nil))
				if rec.Code == 429 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("rate limit not applied, status=%d", rec.Code)
				}
				time.Sleep(10 * time.Millisecond)
			}
			// Clamd transport errors remain unavailable in logs, never a clean scan.
			cfg := call("GET", "/api/v1/settings/malware", nil)
			cfg["clamd"] = map[string]any{"enabled": true, "socket": "/nonexistent/fess-clamd.sock", "fail_open": false, "timeout_ms": 100}
			call("PUT", "/api/v1/settings/malware", cfg)
			call("PUT", "/api/v1/settings/rate-limit", map[string]any{"config": map[string]any{"enabled": false}})
			time.Sleep(30 * time.Millisecond)
			req := httptest.NewRequest("POST", "http://app.test/upload", strings.NewReader("sample"))
			req.Header.Set("Content-Type", "application/octet-stream")
			rec := httptest.NewRecorder()
			gw.ServeHTTP(rec, req)
			if rec.Code != 403 {
				t.Fatalf("missing clamd must block uploads: %d", rec.Code)
			}
			call("GET", "/api/v1/malware-scan-logs", nil)
			call("GET", "/api/v1/dashboard/summary", nil)
		})
	}
}

func TestSQLiteTransfer(t *testing.T) {
	if os.Getenv("FESS_TEST_POSTGRES") == "" {
		t.Skip("set FESS_TEST_POSTGRES")
	}
	src := openBackend(t, "sqlite")
	dst := openBackend(t, "postgres")
	ctx := context.Background()
	const id = "11111111-1111-1111-1111-111111111111"
	if _, err := src.Exec(`INSERT INTO policies(id,name,mode) VALUES($1,'copied','block')`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Exec(`INSERT INTO waf_logs(request_id,action,details) VALUES('test','block','{"key":9007199254740993}')`); err != nil {
		t.Fatal(err)
	}
	report, err := fencedb.TransferToPostgres(ctx, src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if report.Tables < 20 || report.Rows < 2 {
		t.Fatalf("bad report: %+v", report)
	}
	var name string
	if err = dst.QueryRow(`SELECT name FROM policies WHERE id=$1`, id).Scan(&name); err != nil || name != "copied" {
		t.Fatalf("policy lost: %q %v", name, err)
	}
	var newID int64
	if err = dst.QueryRow(`INSERT INTO waf_logs(request_id,action) VALUES('new','block') RETURNING id`).Scan(&newID); err != nil || newID < 2 {
		t.Fatalf("sequence not restored: %d %v", newID, err)
	}
	if _, err = fencedb.TransferToPostgres(ctx, src, dst); err == nil {
		t.Fatal("must reject destination containing application data")
	}
}

func TestSQLiteTransferRollback(t *testing.T) {
	if os.Getenv("FESS_TEST_POSTGRES") == "" {
		t.Skip("set FESS_TEST_POSTGRES")
	}
	src := openBackend(t, "sqlite")
	dst := openBackend(t, "postgres")
	if _, err := src.Exec(`INSERT INTO policies(id,name,mode) VALUES('invalid-uuid','invalid','block')`); err != nil {
		t.Fatal(err)
	}
	if _, err := fencedb.TransferToPostgres(context.Background(), src, dst); err == nil {
		t.Fatal("expected rejected invalid UUID")
	}
	var n int
	if err := dst.QueryRow(`SELECT COUNT(*) FROM policies`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial data committed: %d %v", n, err)
	}
	if err := dst.QueryRow(`SELECT COUNT(*) FROM auth_settings`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("defaults were lost on rollback: %d %v", n, err)
	}
}
