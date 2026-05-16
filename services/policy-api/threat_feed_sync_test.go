package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeAPIQFeedsURLInjectsAPIKeyAndFixesPortalURL(t *testing.T) {
	got := normalizeAPIQFeedsURL("https://api.qfeeds.com/feeds?feed_type=malware_ip&limit100000&download=1", "tip_secret")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/api.php" {
		t.Fatalf("path = %q, want /api.php", u.Path)
	}
	q := u.Query()
	if q.Get("api_token") != "tip_secret" {
		t.Fatalf("api_token = %q, want injected key", q.Get("api_token"))
	}
	if q.Get("limit") != "100000" {
		t.Fatalf("limit = %q, want 100000", q.Get("limit"))
	}
	if _, ok := q["limit100000"]; ok {
		t.Fatal("malformed limit100000 key should be removed")
	}
}

func TestNormalizeAPIQFeedsURLRootDefaultsToMalwareIP(t *testing.T) {
	got := normalizeAPIQFeedsURL("https://api.qfeeds.com/", "tip_secret")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/api.php" {
		t.Fatalf("path = %q, want /api.php", u.Path)
	}
	q := u.Query()
	if q.Get("api_token") != "tip_secret" {
		t.Fatalf("api_token = %q, want injected key", q.Get("api_token"))
	}
	if q.Get("feed_type") != "malware_ip" {
		t.Fatalf("feed_type = %q, want malware_ip", q.Get("feed_type"))
	}
	if q.Get("type") != "text" {
		t.Fatalf("type = %q, want text", q.Get("type"))
	}
	if q.Get("ipv6") != "0" {
		t.Fatalf("ipv6 = %q, want 0", q.Get("ipv6"))
	}
}

func TestNormalizeAPIQFeedsURLKeepsExplicitToken(t *testing.T) {
	got := normalizeAPIQFeedsURL("https://api.qfeeds.com/api.php?feed_type=malware_ip&api_token=from_url", "from_field")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("api_token") != "from_url" {
		t.Fatalf("api_token = %q, want URL token to win", u.Query().Get("api_token"))
	}
}

func TestQFeedsDefaultAuthorizationHeaderIsSuppressed(t *testing.T) {
	if got := qFeedsHeaderName("tip_secret", "Authorization"); got != "" {
		t.Fatalf("header = %q, want empty", got)
	}
	if got := qFeedsHeaderName("tip_secret", "X-API-Key"); got != "X-API-Key" {
		t.Fatalf("header = %q, want X-API-Key", got)
	}
}

func TestSanitizeThreatFeedErrorRedactsAPIToken(t *testing.T) {
	in := `Get "https://api.qfeeds.com/api.php?feed_type=malware_ip&api_token=tip_secret&type=text": context deadline exceeded`
	got := sanitizeThreatFeedError(in)
	if strings.Contains(got, "tip_secret") {
		t.Fatalf("secret leaked: %s", got)
	}
	if !strings.Contains(got, "api_token=***") {
		t.Fatalf("missing redaction: %s", got)
	}
}
