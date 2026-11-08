// Package wafpack validates portable native rule packs before import.
package wafpack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fence/pkg/policy"
	"fmt"
	"regexp"
)

type Rule struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Category  string          `json:"category"`
	Action    string          `json:"action"`
	Priority  int             `json:"priority"`
	Condition json.RawMessage `json:"condition"`
}
type Pack struct {
	Format  string `json:"format"`
	Engine  string `json:"engine"`
	ID      string `json:"pack_id"`
	Version string `json:"version"`
	Title   string `json:"title"`
	License string `json:"license"`
	Rules   []Rule `json:"rules"`
}

var Identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$`)

func Parse(raw []byte) (Pack, error) {
	var p Pack
	if len(raw) == 0 || len(raw) > 1<<20 {
		return p, fmt.Errorf("pack must be at most 1 MiB")
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if p.Format != "security-feed-waf-v1" || (p.Engine != "fess-native-v1" && p.Engine != "fess-native-v2") || !Identifier.MatchString(p.ID) || !Identifier.MatchString(p.Version) || p.Title == "" || len(p.Title) > 240 || len(p.Rules) == 0 || len(p.Rules) > 256 {
		return p, fmt.Errorf("invalid pack metadata, engine or rule count")
	}
	ids := map[string]bool{}
	for _, r := range p.Rules {
		if r.ID == "" || ids[r.ID] || r.Name == "" || len(r.Name) > 240 || (r.Action != "block" && r.Action != "log") {
			return p, fmt.Errorf("invalid or duplicate rule %q", r.ID)
		}
		ids[r.ID] = true
		if _, err := policy.CompileCondition(r.Condition); err != nil {
			return p, fmt.Errorf("%s: %w", r.ID, err)
		}
	}
	return p, nil
}
func Digest(raw []byte) string { v := sha256.Sum256(raw); return hex.EncodeToString(v[:]) }
