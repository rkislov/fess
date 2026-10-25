package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	fencedb "fence/db"
	"fence/internal/xdpguard"
	"fence/internal/xdphistory"
	"fence/pkg/auth"
)

func TestXDPHistoryCollectorPersistenceAndAPI(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "fess.db")
	db, err := fencedb.Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { db.Close() }()
	if err = fencedb.ApplyMigrations(ctx, db); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rates := map[string]float64{}
	for _, key := range xdpguard.CounterNames {
		rates[key] = 7
	}
	stats := &xdpguard.Statistics{PID: 42, ProgramID: 10, Interface: "ens3", StartedAt: now.Add(-time.Minute), SampledAt: now.Add(-time.Second), IntervalSeconds: 10, Rates: rates}
	client := &http.Client{Transport: historyTransport(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/status" {
			t.Fatalf("collector mutated controller: %s %s", req.Method, req.URL.Path)
		}
		w := httptest.NewRecorder()
		json.NewEncoder(w).Encode(map[string]any{"service": map[string]string{"ActiveState": "active"}, "statistics": stats})
		return w.Result(), nil
	})}
	// No browser or history request exists when collection takes place.
	if err = collectXDPHistory(ctx, db, client, now); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = fencedb.Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err = collectXDPHistory(ctx, db, client, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		role, method, period string
		code                 int
	}{
		{"admin", "GET", "hour", 200}, {"admin", "GET", "day", 200}, {"admin", "GET", "week", 200},
		{"admin", "GET", "", 200}, {"admin", "GET", "year", 400}, {"admin", "POST", "hour", 405},
		{"viewer", "GET", "hour", 403}, {"operator", "GET", "week", 403}, {"", "GET", "hour", 403},
	} {
		r := httptest.NewRequest(tc.method, "/api/v1/dashboard/xdp/history?period="+tc.period, nil)
		r = r.WithContext(auth.WithClaims(r.Context(), auth.Claims{Role: tc.role}))
		w := httptest.NewRecorder()
		xdpHistoryHandler(w, r, db)
		if w.Code != tc.code {
			t.Fatalf("%+v: %d %s", tc, w.Code, w.Body.String())
		}
		if tc.code == 200 {
			var h xdphistory.History
			if err = json.Unmarshal(w.Body.Bytes(), &h); err != nil || len(h.Points) != 1 || h.Points[0].Rates["seen"] != 7 || h.Points[0].CoverageSeconds != 10 {
				t.Fatalf("history after restart: %+v %v", h, err)
			}
		}
	}
	stats.Stale = true
	stats.SampledAt = now
	if err = collectXDPHistory(ctx, db, client, now); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM xdp_samples`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("stale sample persisted: %d %v", count, err)
	}
}

type historyTransport func(*http.Request) (*http.Response, error)

func (f historyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
