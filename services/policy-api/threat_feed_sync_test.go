package main

import (
	"net/url"
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
