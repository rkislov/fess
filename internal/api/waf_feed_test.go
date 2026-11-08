package api

import (
	"context"
	"encoding/json"
	"fence/db"
	"fence/pkg/wafpack"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	var rid string
	d.QueryRow("SELECT id FROM rules LIMIT 1").Scan(&rid)
	_, e = d.Exec(`INSERT INTO waf_logs(request_id,policy_id,rule_id,action,method,path,host,created_at) VALUES('test',$1::uuid,$2::uuid,'log','GET','/probe','example.com',$3)`, ids[0], rid, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/waf-feed/adaptation/hits?policy_id="+ids[0], nil)
	wafFeedHandler(w, r, d)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "example.com") {
		t.Fatal(w.Code, w.Body.String())
	}
	body := `{"rule_id":"` + rid + `","confirmed":true,"exception":{"host":"example.com","path":"/probe","method":"GET"}}`
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/v1/waf-feed/adaptation/exception", strings.NewReader(body))
	wafFeedHandler(w, r, d)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var cond string
	d.QueryRow("SELECT condition_json FROM rules WHERE id=$1::uuid", rid).Scan(&cond)
	if !strings.Contains(cond, "exceptions") {
		t.Fatal(cond)
	}
}
