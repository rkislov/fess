package engine

import (
	"io"
	"net/http"
	"strings"

	"fence/pkg/policy"
)

type Decision struct {
	Action      string
	PolicyID    string
	PolicyMode  string
	RuleID      string
	Reason      string
	RedirectURL string
}

type Evaluator struct{}

func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// Evaluate runs the WAF rule chain. If sitePolicyID is non-empty, only that policy id is considered
// (per-virtual-host binding). Empty sitePolicyID keeps legacy behavior: all enabled policies by priority.
func (e *Evaluator) Evaluate(r *http.Request, snapshot policy.Snapshot, sitePolicyID string) Decision {
	body := readBodySafely(r)
	path := r.URL.Path
	query := r.URL.Query()

	uri := r.URL.RequestURI()

	for _, p := range snapshot.Policies {
		if sitePolicyID != "" && p.ID != sitePolicyID {
			continue
		}
		for _, rule := range p.Rules {
			if rule.Method != "" && !strings.EqualFold(rule.Method, r.Method) {
				continue
			}
			if rule.RequestURIContains != "" && !strings.Contains(uri, rule.RequestURIContains) {
				continue
			}
			if rule.PathExact != "" && rule.PathExact != path {
				continue
			}
			if rule.PathContains != "" && !strings.Contains(path, rule.PathContains) {
				continue
			}
			if rule.PathRegex != nil && !rule.PathRegex.MatchString(path) {
				continue
			}
			if rule.BodyContains != "" && !strings.Contains(body, rule.BodyContains) {
				continue
			}
			if !matchQuery(rule.QueryEquals, query) {
				continue
			}
			if !matchHeaders(rule.HeaderContain, r.Header) {
				continue
			}
			return Decision{
				Action:      rule.Action,
				PolicyID:    p.ID,
				PolicyMode:  p.Mode,
				RuleID:      rule.ID,
				Reason:      rule.Name,
				RedirectURL: rule.RedirectURL,
			}
		}
	}
	return Decision{Action: "allow", Reason: "default allow"}
}

func readBodySafely(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(strings.NewReader(string(b)))
	return string(b)
}

func matchQuery(expect map[string]string, actual map[string][]string) bool {
	for k, v := range expect {
		got, ok := actual[k]
		if !ok || len(got) == 0 || got[0] != v {
			return false
		}
	}
	return true
}

func matchHeaders(expect map[string]string, actual http.Header) bool {
	for k, v := range expect {
		got := actual.Get(k)
		if got == "" || !strings.Contains(strings.ToLower(got), strings.ToLower(v)) {
			return false
		}
	}
	return true
}
