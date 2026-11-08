package wafpack

import (
	"encoding/json"
	"fence/pkg/engine"
	"fence/pkg/policy"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDistributedPacksAgainstNativeEngine(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.json")
	if len(files) != 11 {
		t.Fatal(len(files))
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			b, _ := os.ReadFile(f)
			p, e := Parse(b)
			if e != nil {
				t.Fatal(e)
			}
			cp := policy.CompiledPolicy{ID: p.ID, Mode: "log"}
			for _, r := range p.Rules {
				c, e := policy.CompileCondition(r.Condition)
				if e != nil {
					t.Fatal(e)
				}
				c.ID = r.ID
				c.Action = r.Action
				cp.Rules = append(cp.Rules, c)
			}
			var doc struct {
				Tests []struct {
					Method string
					Path   string
					Match  bool
				}
			}
			json.Unmarshal(b, &doc)
			if len(doc.Tests) == 0 {
				t.Fatal("no test cases")
			}
			for _, x := range doc.Tests {
				d := engine.NewEvaluator().EvaluateBody(httptest.NewRequest(x.Method, x.Path, nil), policy.Snapshot{Policies: []policy.CompiledPolicy{cp}}, "", "", nil)
				if (d.Action != "allow") != x.Match {
					t.Errorf("%s %s: got %s want match=%v", x.Method, x.Path, d.Action, x.Match)
				}
			}
		})
	}
}
func TestRejectUnsafeConditions(t *testing.T) {
	b, _ := os.ReadFile("testdata/generic-web-1.0.0.json")
	var p Pack
	json.Unmarshal(b, &p)
	for _, c := range []string{`{}`, `{"unknown":true}`, `{"path_regex":"["}`, `{"appsec":{"zones":["URI"],"match":{"type":"contains","value":"x","not":true}}}`, `{"exceptions":[{"host":"*","path":"/","method":"GET"}]}`} {
		p.Rules[0].Condition = json.RawMessage(c)
		raw, _ := json.Marshal(p)
		if _, e := Parse(raw); e == nil {
			t.Fatal("accepted", c)
		}
	}
}
