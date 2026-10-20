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
	Enabled         bool     `json:"enabled"`
	Block           bool     `json:"block"`
	LogHits         bool     `json:"log_hits"`
	Provider        string   `json:"provider"` // "fess_feed", "threatfox" or "url"
	FeedURL         string   `json:"feed_url"`
	HashFeedURL     string   `json:"hash_feed_url"`
	FessFeedBaseURL string   `json:"fess_feed_base_url"`
	PollIntervalSec int      `json:"poll_interval_sec"`
	HTTPTimeoutSec  int      `json:"http_timeout_sec"`
	Sources         []string `json:"sources"`
	Format          string   `json:"format"`
	CSVIndicatorCol string   `json:"csv_indicator_column"`
	CSVSourceCol    string   `json:"csv_source_column"`
	APIKey          string   `json:"api_key"`
	APIKeyHeader    string   `json:"api_key_header"`
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
		FessFeedBaseURL: DefaultFessFeedBaseURL,
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
	if strings.TrimSpace(c.FessFeedBaseURL) == "" {
		c.FessFeedBaseURL = DefaultFessFeedBaseURL
	}
	c.FessFeedBaseURL = strings.TrimRight(strings.TrimSpace(c.FessFeedBaseURL), "/")
	if strings.TrimSpace(c.APIKeyHeader) == "" {
		switch {
		case c.UsesThreatFox():
			c.APIKeyHeader = "Auth-Key"
		case c.UsesFessFeed():
			c.APIKeyHeader = "X-Api-Key"
		default:
			c.APIKeyHeader = "Authorization"
		}
	}
	return c, nil
}

func (c Config) UsesThreatFox() bool {
	return strings.EqualFold(strings.TrimSpace(c.Provider), ThreatFoxProvider)
}

func (c Config) UsesFessFeed() bool {
	p := strings.ToLower(strings.TrimSpace(c.Provider))
	return p == FessFeedProvider || p == "feed"
}

func (c Config) AutoSyncConfigured() bool {
	if c.UsesThreatFox() || c.UsesFessFeed() {
		return strings.TrimSpace(c.APIKey) != ""
	}
	return strings.TrimSpace(c.FeedURL) != ""
}

func (c Config) ResolvedFessFeedBase() string {
	b := strings.TrimRight(strings.TrimSpace(c.FessFeedBaseURL), "/")
	if b == "" {
		return DefaultFessFeedBaseURL
	}
	return b
}

func (c Config) ResolvedIPFeedURL() string {
	if u := strings.TrimSpace(c.FeedURL); u != "" && !c.UsesFessFeed() {
		return u
	}
	if u := strings.TrimSpace(c.FeedURL); c.UsesFessFeed() && u != "" {
		return u
	}
	if c.UsesFessFeed() {
		return c.ResolvedFessFeedBase() + "/feeds/v1/ips.txt"
	}
	return strings.TrimSpace(c.FeedURL)
}

func (c Config) ResolvedHashFeedURL() string {
	if u := strings.TrimSpace(c.HashFeedURL); u != "" {
		return u
	}
	if c.UsesFessFeed() {
		return c.ResolvedFessFeedBase() + "/feeds/v1/hashes.txt"
	}
	return ""
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
