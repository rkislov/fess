package api

import (
	"context"
	"encoding/json"
	"fence/db"
	"fence/pkg/wafpack"

	"os"
	"path/filepath"

	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestWAFImportDisabledIdempotentAndInvalidBatchAtomic(t *testing.T) {
	ctx := context.Background()
	d, e := db.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "fess.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = db.ApplyMigrations(ctx, d); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile("../../pkg/wafpack/testdata/generic-web-1.0.0.json")
	if e != nil {
		t.Fatal(e)
	}
	ids, e := importWAFPacks(ctx, d, [][]byte{b})
	if e != nil {
		t.Fatal(e)
	}
	ids2, e := importWAFPacks(ctx, d, [][]byte{b})
	if e != nil || ids[0] != ids2[0] {
		t.Fatal(ids2, e)
	}
	var mode string
	var enabled bool
	var n int
	d.QueryRow("SELECT mode,enabled FROM policies WHERE id=$1::uuid", ids[0]).Scan(&mode, &enabled)
	if enabled || mode != "log" {
		t.Fatal(mode, enabled)
	}
	d.QueryRow("SELECT COUNT(*) FROM policies").Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
	var p wafpack.Pack
	json.Unmarshal(b, &p)
	p.Version = "2.0.0"
	newPack, _ := json.Marshal(p)
	if _, e = importWAFPacks(ctx, d, [][]byte{newPack, []byte(`{}`)}); e == nil {
		t.Fatal("invalid accepted")
	}
	d.QueryRow("SELECT COUNT(*) FROM policies").Scan(&n)
	if n != 1 {
		t.Fatal("partial import")
	}
}

func TestFileImportEndpointsAreAbsent(t *testing.T) {
	for _, path := range []string{"/api/v1/waf-feed/offline", "/api/v1/waf-feed/crowdsec/preview"} {
		w := httptest.NewRecorder()
		wafFeedHandler(w, httptest.NewRequest("POST", path, strings.NewReader("ignored")), nil)
		if w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
}

func TestWAFCatalogMatchesOnlyImportedRevision(t *testing.T) {
	ctx := context.Background()
	d, err := db.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "catalog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.ApplyMigrations(ctx, d); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../pkg/wafpack/testdata/generic-web-1.0.0.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := wafpack.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	meta := wafMeta{ID: p.ID, Version: p.Version, SHA: wafpack.Digest(raw), PolicyID: "untrusted-feed-value"}
	var revised atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/feeds/v1/waf/catalog.json" || r.Header.Get("X-Api-Key") != "test-key" {
			t.Error("unexpected feed request", r.URL.Path)
		}
		entry := meta
		if revised.Load() {
			entry.SHA = wafpack.Digest([]byte("new revision"))
		}
		json.NewEncoder(w).Encode(wafCatalog{Format: "security-feed-waf-catalog-v1", Packs: []wafMeta{entry}})
	}))
	defer upstream.Close()
	cfg, _ := json.Marshal(map[string]string{"api_key": "test-key", "fess_feed_base_url": upstream.URL})
	if _, err := d.Exec("UPDATE threat_feed_settings SET config=$1::jsonb WHERE singleton='global'", string(cfg)); err != nil {
		t.Fatal(err)
	}
	checkPolicy := func(want string) {
		t.Helper()
		w := httptest.NewRecorder()
		wafFeedHandler(w, httptest.NewRequest("GET", "/api/v1/waf-feed/catalog", nil), d)
		var result wafCatalog
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Packs) != 1 || result.Packs[0].PolicyID != want {
			t.Fatalf("expected policy %q, got %d %s", want, w.Code, w.Body.String())
		}
	}
	checkPolicy("")
	ids, err := importWAFPacks(ctx, d, [][]byte{raw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("UPDATE policies SET name='renamed' WHERE id=$1::uuid", ids[0]); err != nil {
		t.Fatal(err)
	}
	checkPolicy(ids[0])
	revised.Store(true)
	checkPolicy("")
	body, _ := json.Marshal(meta)
	w := httptest.NewRecorder()
	wafFeedHandler(w, httptest.NewRequest("POST", "/api/v1/waf-feed/import", strings.NewReader(string(body))), d)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale selection: %d %s", w.Code, w.Body.String())
	}
}
func TestAdaptationRequiresActiveFeedSubscription(t *testing.T) {
	ctx := context.Background()
	d, e := db.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "fess.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = db.ApplyMigrations(ctx, d); e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	wafFeedHandler(w, httptest.NewRequest("GET", "/api/v1/waf-feed/adaptation/hits", nil), d)
	if w.Code != 403 {
		t.Fatal(w.Code, w.Body.String())
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "subscription-key" {
			t.Error("missing subscription key")
		}
		w.WriteHeader(403)
	}))
	defer upstream.Close()
	cfg, _ := json.Marshal(map[string]any{"api_key": "subscription-key", "fess_feed_base_url": upstream.URL})
	if _, e = d.Exec("UPDATE threat_feed_settings SET config=$1::jsonb WHERE singleton='global'", string(cfg)); e != nil {
		t.Fatal(e)
	}
	w = httptest.NewRecorder()
	wafFeedHandler(w, httptest.NewRequest("POST", "/api/v1/waf-feed/adaptation/exception", strings.NewReader(`{}`)), d)
	if w.Code != 403 {
		t.Fatal("expired subscription accepted", w.Code, w.Body.String())
	}
}
