package ratelimit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Config is the effective rate limit policy (system default or resolved override).
type Config struct {
	Enabled           bool   `json:"enabled"`
	RequestsPerWindow int    `json:"requests_per_window"`
	WindowSec         int    `json:"window_sec"`
	Scope             string `json:"scope"` // ip, ip_host, ip_path, backend
}

// Override is an optional per-backend or per-path policy. Set=false means inherit parent.
type Override struct {
	Set    bool
	Config Config
}

// APIOverride is the JSON shape for backend/path overrides (null = inherit).
type APIOverride struct {
	Enabled           *bool  `json:"enabled,omitempty"`
	RequestsPerWindow *int   `json:"requests_per_window,omitempty"`
	WindowSec         *int   `json:"window_sec,omitempty"`
	Scope             string `json:"scope,omitempty"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		RequestsPerWindow: 120,
		WindowSec:         60,
		Scope:             "ip_host",
	}
}

func NormalizeConfig(c Config) Config {
	if c.RequestsPerWindow <= 0 {
		c.RequestsPerWindow = 120
	}
	if c.WindowSec <= 0 {
		c.WindowSec = 60
	}
	scope := strings.ToLower(strings.TrimSpace(c.Scope))
	switch scope {
	case "ip", "ip_host", "ip_path", "backend":
		c.Scope = scope
	default:
		c.Scope = "ip_host"
	}
	return c
}

// ParseConfig parses global settings JSONB.
func ParseConfig(raw []byte) (Config, error) {
	c := DefaultConfig()
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return c, nil
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	return NormalizeConfig(c), nil
}

// ParseOverrideJSON returns inherit when raw is null/empty.
func ParseOverrideJSON(raw []byte) (Override, error) {
	raw = bytesTrim(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return Override{Set: false}, nil
	}
	var api APIOverride
	if err := json.Unmarshal(raw, &api); err != nil {
		return Override{}, err
	}
	base := DefaultConfig()
	if api.Enabled != nil {
		base.Enabled = *api.Enabled
	}
	if api.RequestsPerWindow != nil {
		base.RequestsPerWindow = *api.RequestsPerWindow
	}
	if api.WindowSec != nil {
		base.WindowSec = *api.WindowSec
	}
	if strings.TrimSpace(api.Scope) != "" {
		base.Scope = api.Scope
	}
	return Override{Set: true, Config: NormalizeConfig(base)}, nil
}

// MarshalOverrideJSON encodes override for DB; nil inherit → SQL NULL.
func MarshalOverrideJSON(o Override) ([]byte, error) {
	if !o.Set {
		return nil, nil
	}
	c := NormalizeConfig(o.Config)
	return json.Marshal(c)
}

// Resolve picks path → backend → global.
func Resolve(global Config, backend, path Override) Config {
	if path.Set {
		return NormalizeConfig(path.Config)
	}
	if backend.Set {
		return NormalizeConfig(backend.Config)
	}
	return NormalizeConfig(global)
}

// EncodeAPIOverride builds JSON for API responses.
func EncodeAPIOverride(o Override) any {
	if !o.Set {
		return nil
	}
	c := NormalizeConfig(o.Config)
	return c
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

// ValidateOverridePayload validates PUT body; inherit=true clears override.
type OverridePayload struct {
	Inherit           *bool  `json:"inherit"`
	Enabled           *bool  `json:"enabled"`
	RequestsPerWindow *int   `json:"requests_per_window"`
	WindowSec         *int   `json:"window_sec"`
	Scope             string `json:"scope"`
}

func OverrideFromPayload(p *OverridePayload) (Override, error) {
	if p == nil {
		return Override{Set: false}, nil
	}
	if p.Inherit != nil && *p.Inherit {
		return Override{Set: false}, nil
	}
	hasField := p.Enabled != nil || p.RequestsPerWindow != nil || p.WindowSec != nil || strings.TrimSpace(p.Scope) != ""
	if !hasField {
		return Override{Set: false}, nil
	}
	base := DefaultConfig()
	if p.Enabled != nil {
		base.Enabled = *p.Enabled
	}
	if p.RequestsPerWindow != nil {
		if *p.RequestsPerWindow <= 0 {
			return Override{}, fmt.Errorf("requests_per_window must be positive")
		}
		base.RequestsPerWindow = *p.RequestsPerWindow
	}
	if p.WindowSec != nil {
		if *p.WindowSec <= 0 {
			return Override{}, fmt.Errorf("window_sec must be positive")
		}
		base.WindowSec = *p.WindowSec
	}
	if strings.TrimSpace(p.Scope) != "" {
		base.Scope = p.Scope
	}
	return Override{Set: true, Config: NormalizeConfig(base)}, nil
}
