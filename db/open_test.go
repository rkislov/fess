package db

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteReportingDialect(t *testing.T) {
	ctx := context.Background()
	d, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = ApplyMigrations(ctx, d); err != nil {
		t.Fatal(err)
	}
	var literal string
	if err = d.QueryRow(`SELECT 'NOW() $1 ::uuid ILIKE'`).Scan(&literal); err != nil || literal != "NOW() $1 ::uuid ILIKE" {
		t.Fatalf("changed literal: %q %v", literal, err)
	}
	for _, q := range []string{`SELECT NOW() + ($1 * INTERVAL '1 second') AS expires_at`, `SELECT NOW() + ($1 || ' days')::interval AS expires_at`} {
		var ts time.Time
		if err = d.QueryRow(q, 60).Scan(&ts); err != nil || !ts.After(time.Now()) {
			t.Fatalf("interval: %v %v", ts, err)
		}
	}
	var b time.Time
	var n int
	if _, err = d.Exec(`INSERT INTO proxy_access_logs(host,method,path,client_ip,upstream_base,outcome) VALUES('app','GET','/','127.0.0.1','','proxied')`); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT date_bin($2::interval, created_at, TIMESTAMPTZ '2000-01-01') AS b, COUNT(*)::bigint FROM proxy_access_logs WHERE created_at >= $1 GROUP BY b`, time.Now().Add(-time.Hour), "5 minutes").Scan(&b, &n); err != nil || n != 1 {
		t.Fatalf("binning: %v %d %v", b, n, err)
	}
	var raw json.RawMessage
	if err = d.QueryRow(`SELECT config FROM malware_settings`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE malware_settings SET config=jsonb_set(config,'{geoip,mmdb_last_installed_at}',to_jsonb($1::text),true)`, "now"); err != nil {
		t.Fatal(err)
	}
	var stamp string
	if err = d.QueryRow(`SELECT config->'geoip'->>'mmdb_last_installed_at' FROM malware_settings`).Scan(&stamp); err != nil || stamp != "now" {
		t.Fatalf("GeoIP JSON update: %q %v", stamp, err)
	}
}
func TestJSONTransferPreservesLargeIntegers(t *testing.T) {
	v, err := normalizeCell(`{"n":9007199254740993}`, "jsonb")
	if err != nil || v != `{"n":9007199254740993}` {
		t.Fatalf("integer changed: %v %v", v, err)
	}
	if !cellsEqual(`{"n":1e2}`, `{"n":100}`, "jsonb") {
		t.Fatal("equivalent numeric JSON rejected")
	}
}
