package threatfeed

import (
	"encoding/json"
	"strings"
)

// GatewayConfig is the subset persisted for gateway enforcement (minimal JSON from policy-api reload).
type GatewayConfig struct {
	Enabled bool `json:"enabled"`
	Block   bool `json:"block"`
	LogHits bool `json:"log_hits"`
}

// Config is stored in threat_feed_settings.config (JSONB).
type Config struct {
	Enabled           bool     `json:"enabled"`
	Block             bool     `json:"block"`
	LogHits           bool     `json:"log_hits"`
	FeedURL           string   `json:"feed_url"`
	PollIntervalSec   int      `json:"poll_interval_sec"`
	HTTPTimeoutSec    int      `json:"http_timeout_sec"`
	Sources           []string `json:"sources"` // allowlist by feed "source" field; empty = all sources
	Format            string   `json:"format"` // auto, csv, plain, ndjson
	CSVIndicatorCol   string   `json:"csv_indicator_column"`
	CSVSourceCol      string   `json:"csv_source_column"`
	APIKey            string   `json:"api_key"`
	APIKeyHeader      string   `json:"api_key_header"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:         false,
		Block:           true,
		LogHits:         true,
		PollIntervalSec: 12 * 3600, // min interval for automatic URL sync (policy-api caps at 12h)
		HTTPTimeoutSec:  120,
		Sources:         nil,
		Format:          "auto",
		APIKeyHeader:    "Authorization",
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
	if c.PollIntervalSec <= 0 {
		c.PollIntervalSec = 12 * 3600
	}
	if c.PollIntervalSec < 12*3600 {
		c.PollIntervalSec = 12 * 3600
	}
	if c.HTTPTimeoutSec <= 0 {
		c.HTTPTimeoutSec = 120
	}
	f := strings.ToLower(strings.TrimSpace(c.Format))
	if f == "" {
		f = "auto"
	}
	c.Format = f
	if strings.TrimSpace(c.APIKeyHeader) == "" {
		c.APIKeyHeader = "Authorization"
	}
	return c, nil
}

func (c Config) SourcesAllowlist() map[string]struct{} {
	if len(c.Sources) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(c.Sources))
	for _, s := range c.Sources {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			m[s] = struct{}{}
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func (c Config) Gateway() GatewayConfig {
	return GatewayConfig{
		Enabled: c.Enabled,
		Block:   c.Block,
		LogHits: c.LogHits,
	}
}
