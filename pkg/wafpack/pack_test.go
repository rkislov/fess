package wafpack

import (
	"archive/zip"
	"bytes"
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
	if len(files) != 9 {
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
func TestArchiveChecksum(t *testing.T) {
	b, _ := os.ReadFile("testdata/generic-web-1.0.0.json")
	for _, valid := range []bool{true, false} {
		var out bytes.Buffer
		z := zip.NewWriter(&out)
		sum := Digest(b)
		if !valid {
			sum = "bad"
		}
		m, _ := json.Marshal(map[string]any{"format": "security-feed-waf-catalog-v1", "packs": []any{map[string]any{"id": "generic-web", "version": "1.0.0", "sha256": sum}}})
		w, _ := z.Create("catalog.json")
		w.Write(m)
		w, _ = z.Create("generic-web-1.0.0.json")
		w.Write(b)
		z.Close()
		p, e := DecodeArchive(out.Bytes())
		if valid && (e != nil || len(p) != 1) {
			t.Fatal(e)
		}
		if !valid && e == nil {
			t.Fatal("bad checksum accepted")
		}
	}
}
