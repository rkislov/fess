package engine

import (
	"bytes"
	"fence/pkg/policy"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

type forbiddenRead struct{}

func (forbiddenRead) Read([]byte) (int, error) { panic("EvaluateBody must not read request.Body") }
func (forbiddenRead) Close() error             { return nil }
func TestEvaluateProvidedBody(t *testing.T) {
	r := httptest.NewRequest("POST", "http://test/upload", nil)
	r.Body = forbiddenRead{}
	s := policy.Snapshot{Policies: []policy.CompiledPolicy{{ID: "policy", Mode: "block", Rules: []policy.CompiledRule{{ID: "rule", Action: "block", BodyContains: "malware"}}}}}
	d := NewEvaluator().EvaluateBody(r, s, "", "", []byte("prefix malware suffix"))
	if d.Action != "block" || d.RuleID != "rule" {
		t.Fatalf("wrong decision: %+v", d)
	}
}
func TestEvaluateStandalonePreservesBody(t *testing.T) {
	r := httptest.NewRequest("POST", "http://test/", strings.NewReader("original"))
	NewEvaluator().Evaluate(r, policy.Snapshot{}, "", "")
	body, err := io.ReadAll(r.Body)
	if err != nil || string(body) != "original" {
		t.Fatalf("body changed: %q %v", body, err)
	}
}

func BenchmarkBodyEvaluation(b *testing.B) {
	body := []byte(strings.Repeat("a", 65536))
	snapshot := policy.Snapshot{Policies: []policy.CompiledPolicy{{ID: "policy", Mode: "block", Rules: []policy.CompiledRule{{ID: "rule", Action: "block", BodyContains: "needle-not-present"}}}}}
	evaluator := NewEvaluator()
	for _, buffered := range []bool{false, true} {
		name := "compatibility-read"
		if buffered {
			name = "reuse-buffer"
		}
		b.Run(name, func(b *testing.B) {
			r := httptest.NewRequest("POST", "http://test/upload", nil)
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r.Body = io.NopCloser(bytes.NewReader(body))
				if buffered {
					evaluator.EvaluateBody(r, snapshot, "", "", body)
				} else {
					evaluator.Evaluate(r, snapshot, "", "")
				}
			}
		})
	}
}
