package api

import (
	"context"
	"fence/db"
	"fence/pkg/threatfeed"
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineImportReplacesAllCategoriesAndRollbackPreservesSnapshot(t *testing.T) {
	ctx := context.Background()
	d, e := db.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "fess.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = db.ApplyMigrations(ctx, d); e != nil {
		t.Fatal(e)
	}
	b := threatfeed.OfflineBundle{HasBotLists: true, ASNs: []uint{12345}, BotCIDRs: []string{"185.220.101.0/24"}, IPs: []string{"185.220.101.1"}, Hashes: []string{"da39a3ee5e6b4b0d3255bfef95601890afd80709"}, Domains: []string{"malware-host.xyz"}, URLs: []string{"https://malware-host.xyz/Case?Token=AbC#/Login"}}
	n, e := replaceOfflineData(ctx, d, b, time.Now())
	if e != nil || n != 4 {
		t.Fatalf("import: %d %v", n, e)
	}
	for _, table := range []string{"threat_feed_indicators", "threat_feed_file_hashes", "threat_feed_web_iocs", "bot_protection_asn", "bot_protection_cidr"} {
		var count int
		if e = d.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); e != nil || count == 0 {
			t.Fatalf("missing %s: %v", table, e)
		}
	}
	// Database constraint failure after deleting the old snapshot must roll back.
	b.IPs = []string{"9.9.9.9"}
	b.Hashes = []string{"invalid", "invalid"}
	if _, e = replaceOfflineData(ctx, d, b, time.Now()); e == nil {
		t.Fatal("expected constraint error")
	}
	var ip string
	if e = d.QueryRow("SELECT indicator FROM threat_feed_indicators").Scan(&ip); e != nil || ip != "185.220.101.1" {
		t.Fatal("last snapshot was damaged", ip, e)
	}
}
