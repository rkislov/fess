package owasp

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed data/crs_lite_v1.json
var crsLiteV1JSON []byte

//go:embed data/crs_bundle_v1.json
var crsBundleV1JSON []byte

// Pack is an OWASP CRS–inspired rule bundle (Fence condition schema).
type Pack struct {
	PackID      string     `json:"pack_id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Rules       []PackRule `json:"rules"`
}

type PackRule struct {
	Name        string          `json:"name"`
	CRSRuleID   string          `json:"crs_rule_id"`
	Category    string          `json:"category"`
	Action      string          `json:"action"`
	Priority    int             `json:"priority"`
	Condition   json.RawMessage `json:"condition"`
	Transform   json.RawMessage `json:"transform"`
}

// PackMeta is returned by ListPacks.
type PackMeta struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	RuleCount   int    `json:"rule_count"`
}

// ListPacks returns known embedded packs.
func ListPacks() []PackMeta {
	var out []PackMeta
	for _, raw := range [][]byte{crsBundleV1JSON, crsLiteV1JSON} {
		p, err := ParsePack(raw)
		if err != nil {
			continue
		}
		out = append(out, PackMeta{
			ID:          p.PackID,
			Title:       p.Title,
			Description: p.Description,
			RuleCount:   len(p.Rules),
		})
	}
	return out
}

// LoadPack returns a pack by id (e.g. crs-bundle-v1, crs-lite-v1).
func LoadPack(id string) (*Pack, error) {
	switch id {
	case "crs-bundle-v1":
		return ParsePack(crsBundleV1JSON)
	case "crs-lite-v1":
		return ParsePack(crsLiteV1JSON)
	default:
		return nil, fmt.Errorf("unknown pack_id: %s (try crs-bundle-v1 or crs-lite-v1)", id)
	}
}

func ParsePack(raw []byte) (*Pack, error) {
	var p Pack
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse owasp pack: %w", err)
	}
	if p.PackID == "" {
		return nil, fmt.Errorf("pack missing pack_id")
	}
	for i := range p.Rules {
		if p.Rules[i].Name == "" || p.Rules[i].Action == "" {
			return nil, fmt.Errorf("pack rule %d: name and action required", i)
		}
		if len(p.Rules[i].Condition) == 0 {
			return nil, fmt.Errorf("pack rule %q: condition required", p.Rules[i].Name)
		}
		if p.Rules[i].Priority == 0 {
			p.Rules[i].Priority = 1000 + i
		}
	}
	return &p, nil
}
