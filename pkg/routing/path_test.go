package routing

import (
	"net/url"
	"testing"
)

func TestPathMatchesPrefix(t *testing.T) {
	if !PathMatchesPrefix("/api/ws/foo", "/api/ws") {
		t.Fatal("expected prefix match")
	}
	if PathMatchesPrefix("/api/wsfoo", "/api/ws") {
		t.Fatal("must not match partial segment")
	}
	if !PathMatchesPrefix("/anything", "") {
		t.Fatal("empty prefix matches all")
	}
	if !PathMatchesPrefix("/admin/foo", "*") {
		t.Fatal("* prefix matches all")
	}
}

func TestStripPathPrefix(t *testing.T) {
	if got := StripPathPrefix("/ws/chat", "/ws"); got != "/chat" {
		t.Fatalf("got %q want /chat", got)
	}
	if got := StripPathPrefix("/ws", "/ws"); got != "/" {
		t.Fatalf("got %q want /", got)
	}
}

func TestSnapshotPickBackend_longestPrefix(t *testing.T) {
	u, _ := url.Parse("http://a:1")
	u2, _ := url.Parse("http://b:2")
	site := ResolvedSite{
		HostPattern: "*",
		Backends: []ResolvedBackend{
			{PathPrefix: "*", PathPriority: 100, BackendPriority: 100, Backend: u, BackendName: "default"},
			{PathPrefix: "/api", PathPriority: 50, BackendPriority: 50, Backend: u2, BackendName: "api"},
		},
	}
	br := site.pickBackend("/api/ws")
	if br == nil || br.BackendName != "api" {
		t.Fatalf("got %+v", br)
	}
	br = site.pickBackend("/other")
	if br == nil || br.BackendName != "default" {
		t.Fatalf("got %+v", br)
	}
}
