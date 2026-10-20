package ratelimit

import "testing"

func TestResolveHierarchy(t *testing.T) {
	global := Config{Enabled: true, RequestsPerWindow: 100, WindowSec: 60, Scope: "ip_host"}
	backend := Override{Set: true, Config: Config{Enabled: true, RequestsPerWindow: 50, WindowSec: 30, Scope: "ip"}}
	path := Override{Set: true, Config: Config{Enabled: true, RequestsPerWindow: 10, WindowSec: 10, Scope: "ip_path"}}

	got := Resolve(global, backend, Override{Set: false})
	if got.RequestsPerWindow != 50 {
		t.Fatalf("backend override: got %d", got.RequestsPerWindow)
	}
	got = Resolve(global, Override{Set: false}, path)
	if got.RequestsPerWindow != 10 {
		t.Fatalf("path override: got %d", got.RequestsPerWindow)
	}
	got = Resolve(global, Override{Set: false}, Override{Set: false})
	if got.RequestsPerWindow != 100 {
		t.Fatalf("global: got %d", got.RequestsPerWindow)
	}
}

func TestParseOverrideInherit(t *testing.T) {
	o, err := ParseOverrideJSON(nil)
	if err != nil || o.Set {
		t.Fatal("expected inherit")
	}
}
