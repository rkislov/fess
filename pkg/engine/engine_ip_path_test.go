package engine

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"fence/pkg/policy"
)

func TestPathPrefixAndClientIPIn(t *testing.T) {
	ev := NewEvaluator()
	pfx, _ := netip.ParsePrefix("10.0.0.0/8")
	rule := policy.CompiledRule{
		ID:         "1",
		Action:     "block",
		PathPrefix: "/api/",
		ClientIPIn: []netip.Prefix{pfx},
	}
	pol := policy.CompiledPolicy{
		ID:       "p1",
		Name:     "p",
		Mode:     "block",
		Priority: 1,
		Rules:    []policy.CompiledRule{rule},
	}
	snap := policy.Snapshot{Policies: []policy.CompiledPolicy{pol}}

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	d := ev.Evaluate(req, snap, "", "10.1.2.3")
	if d.Action != "block" {
		t.Fatalf("expected block for inside 10/8, got %q", d.Action)
	}
	d2 := ev.Evaluate(req, snap, "", "8.8.8.8")
	if d2.Action != "allow" {
		t.Fatalf("expected allow for outside 10/8, got %q", d2.Action)
	}
}

func TestClientIPNotInSkipsRuleForTrusted(t *testing.T) {
	ev := NewEvaluator()
	trust, _ := netip.ParsePrefix("10.0.0.0/8")
	rule := policy.CompiledRule{
		ID:            "r",
		Action:        "block",
		PathPrefix:    "/admin",
		ClientIPNotIn: []netip.Prefix{trust},
	}
	pol := policy.CompiledPolicy{ID: "p", Mode: "block", Priority: 1, Rules: []policy.CompiledRule{rule}}
	snap := policy.Snapshot{Policies: []policy.CompiledPolicy{pol}}

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	d := ev.Evaluate(req, snap, "", "10.0.0.1")
	if d.Action != "allow" {
		t.Fatalf("trusted should skip rule, got %q", d.Action)
	}
	d2 := ev.Evaluate(req, snap, "", "203.0.113.1")
	if d2.Action != "block" {
		t.Fatalf("untrusted must match rule, got %q", d2.Action)
	}
}
