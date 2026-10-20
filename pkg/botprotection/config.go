package botprotection

import (
	"encoding/json"
	"strings"
)

// Config is stored in bot_protection_settings.config (JSONB).
type Config struct {
	Enabled bool `json:"enabled"`
	LogHits bool `json:"log_hits"`

	RateLimit  RateLimitConfig  `json:"rate_limit"`
	Scoring    ScoringConfig    `json:"scoring"`
	Challenge  ChallengeConfig  `json:"challenge"`
	GeoBlock   GeoBlockConfig   `json:"geo_block"`
	ASNBlock   ASNBlockConfig   `json:"asn_block"`
	CIDRBlock  CIDRBlockConfig  `json:"cidr_block"`
	TLSScoring TLSScoringConfig `json:"tls_scoring"`
}

type RateLimitConfig struct {
	Enabled           bool   `json:"enabled"`
	RequestsPerWindow int    `json:"requests_per_window"`
	WindowSec         int    `json:"window_sec"`
	Scope             string `json:"scope"` // ip, ip_host, ip_path
}

type ScoringConfig struct {
	Enabled            bool `json:"enabled"`
	BlockThreshold     int  `json:"block_threshold"`
	ChallengeThreshold int  `json:"challenge_threshold"`
}

type ChallengeConfig struct {
	Enabled    bool   `json:"enabled"`
	CookieName string `json:"cookie_name"`
	TTLSec     int    `json:"ttl_sec"`
	Secret     string `json:"secret"`
}

type GeoBlockConfig struct {
	Enabled          bool     `json:"enabled"`
	BlockedCountries []string `json:"blocked_countries"`
}

type ASNBlockConfig struct {
	Enabled bool `json:"enabled"`
}

type CIDRBlockConfig struct {
	Enabled bool `json:"enabled"`
}

type TLSScoringConfig struct {
	Enabled          bool     `json:"enabled"`
	BlockLegacyTLS   bool     `json:"block_legacy_tls"`
	TrustJA3Header   bool     `json:"trust_ja3_header"`
	BlockedJA3Hashes []string `json:"blocked_ja3_hashes"`
}

func DefaultConfig() Config {
	return Config{
		LogHits: true,
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerWindow: 120,
			WindowSec:         60,
			Scope:             "ip_host",
		},
		Scoring: ScoringConfig{
			Enabled:            true,
			BlockThreshold:     70,
			ChallengeThreshold: 45,
		},
		Challenge: ChallengeConfig{
			CookieName: "fence_bot",
			TTLSec:     86400,
		},
		TLSScoring: TLSScoringConfig{
			Enabled:        true,
			BlockLegacyTLS: true,
			TrustJA3Header: true,
		},
	}
}

func ParseConfig(raw []byte) (Config, error) {
	c := DefaultConfig()
	if len(raw) == 0 || string(raw) == "{}" {
		return c, nil
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	normalizeConfig(&c)
	return c, nil
}

func normalizeConfig(c *Config) {
	if c.RateLimit.RequestsPerWindow <= 0 {
		c.RateLimit.RequestsPerWindow = 120
	}
	if c.RateLimit.WindowSec <= 0 {
		c.RateLimit.WindowSec = 60
	}
	scope := strings.ToLower(strings.TrimSpace(c.RateLimit.Scope))
	switch scope {
	case "ip", "ip_host", "ip_path":
		c.RateLimit.Scope = scope
	default:
		c.RateLimit.Scope = "ip_host"
	}
	if c.Scoring.BlockThreshold <= 0 {
		c.Scoring.BlockThreshold = 70
	}
	if c.Scoring.ChallengeThreshold <= 0 {
		c.Scoring.ChallengeThreshold = 45
	}
	if c.Scoring.ChallengeThreshold > c.Scoring.BlockThreshold {
		c.Scoring.ChallengeThreshold = c.Scoring.BlockThreshold - 1
		if c.Scoring.ChallengeThreshold < 1 {
			c.Scoring.ChallengeThreshold = 1
		}
	}
	if strings.TrimSpace(c.Challenge.CookieName) == "" {
		c.Challenge.CookieName = "fence_bot"
	}
	if c.Challenge.TTLSec <= 0 {
		c.Challenge.TTLSec = 86400
	}
	bc := make([]string, 0, len(c.GeoBlock.BlockedCountries))
	for _, cc := range c.GeoBlock.BlockedCountries {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if len(cc) == 2 {
			bc = append(bc, cc)
		}
	}
	c.GeoBlock.BlockedCountries = bc
	ja3 := make([]string, 0, len(c.TLSScoring.BlockedJA3Hashes))
	for _, h := range c.TLSScoring.BlockedJA3Hashes {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			ja3 = append(ja3, h)
		}
	}
	c.TLSScoring.BlockedJA3Hashes = ja3
}

// BlockedCountrySet returns ISO country codes to block.
func (c Config) BlockedCountrySet() map[string]struct{} {
	if !c.GeoBlock.Enabled || len(c.GeoBlock.BlockedCountries) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(c.GeoBlock.BlockedCountries))
	for _, cc := range c.GeoBlock.BlockedCountries {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if len(cc) != 2 {
			continue
		}
		m[cc] = struct{}{}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// BlockedJA3Set returns normalized JA3 hashes from config.
func (c Config) BlockedJA3Set() map[string]struct{} {
	if len(c.TLSScoring.BlockedJA3Hashes) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(c.TLSScoring.BlockedJA3Hashes))
	for _, h := range c.TLSScoring.BlockedJA3Hashes {
		m[h] = struct{}{}
	}
	return m
}
