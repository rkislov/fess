package engine

import (
	"encoding/json"
	"fence/pkg/policy"
	"net/http/httptest"
	"testing"
)

func TestExceptionIsExactAndDoesNotAllowOtherRules(t *testing.T) {
	c, e := policy.CompileCondition(json.RawMessage(`{"appsec":{"zones":["URI"],"match":{"type":"startsWith","value":"/upload"}},"exceptions":[{"host":"files.example.com","path":"/upload","method":"POST"}]}`))
	if e != nil {
		t.Fatal(e)
	}
	c.ID = "first"
	c.Action = "block"
	other := policy.CompiledRule{ID: "second", Action: "block", BodyContains: "malware"}
	snap := policy.Snapshot{Policies: []policy.CompiledPolicy{{ID: "p", Mode: "log", Rules: []policy.CompiledRule{c, other}}}}
	for _, x := range []struct{ host, path, method, body, want string }{{"files.example.com:443", "/upload", "POST", "", ""}, {"other.example.com", "/upload", "POST", "", "first"}, {"files.example.com", "/upload/a", "POST", "", "first"}, {"files.example.com", "/upload", "GET", "", "first"}, {"files.example.com", "/upload", "POST", "malware", "second"}} {
		r := httptest.NewRequest(x.method, "https://"+x.host+x.path, nil)
		d := NewEvaluator().EvaluateBody(r, snap, "p", "", []byte(x.body))
		if d.RuleID != x.want {
			t.Fatal(x, d)
		}
	}
}
