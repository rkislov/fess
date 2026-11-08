// Package wafpack validates portable native rule packs before import.
package wafpack

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fence/pkg/policy"
	"fmt"
	"io"
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

// DecodeArchive reads entries in memory, never extracts paths, and validates every
// checksum and rule before returning any pack to the transactional importer.
func DecodeArchive(raw []byte) ([][]byte, error) {
	if len(raw) > 8<<20 {
		return nil, fmt.Errorf("archive too large")
	}
	if len(raw) < 4 || string(raw[:2]) != "PK" {
		if _, e := Parse(raw); e != nil {
			return nil, e
		}
		return [][]byte{raw}, nil
	}
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		return nil, e
	}
	if len(z.File) > 66 {
		return nil, fmt.Errorf("too many entries")
	}
	entries := map[string][]byte{}
	total := 0
	for _, f := range z.File {
		if _, ok := entries[f.Name]; ok {
			return nil, fmt.Errorf("duplicate entry")
		}
		if f.UncompressedSize64 > 1<<20 {
			return nil, fmt.Errorf("entry too large")
		}
		h, e := f.Open()
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(h, (1<<20)+1))
		h.Close()
		if e != nil {
			return nil, e
		}
		total += len(b)
		if len(b) > 1<<20 || total > 8<<20 {
			return nil, fmt.Errorf("archive too large")
		}
		entries[f.Name] = b
	}
	var c struct {
		Format string `json:"format"`
		Packs  []struct {
			ID      string `json:"id"`
			Version string `json:"version"`
			SHA     string `json:"sha256"`
		} `json:"packs"`
	}
	if e = json.Unmarshal(entries["catalog.json"], &c); e != nil || c.Format != "security-feed-waf-catalog-v1" || len(c.Packs) == 0 || len(c.Packs) > 64 {
		return nil, fmt.Errorf("invalid archive catalog")
	}
	out := [][]byte{}
	seen := map[string]bool{}
	for _, m := range c.Packs {
		name := m.ID + "-" + m.Version + ".json"
		if seen[name] {
			return nil, fmt.Errorf("duplicate pack")
		}
		seen[name] = true
		b := entries[name]
		if Digest(b) != m.SHA {
			return nil, fmt.Errorf("checksum mismatch: %s", name)
		}
		p, e := Parse(b)
		if e != nil {
			return nil, e
		}
		if p.ID != m.ID || p.Version != m.Version {
			return nil, fmt.Errorf("metadata mismatch")
		}
		out = append(out, b)
	}
	return out, nil
}
