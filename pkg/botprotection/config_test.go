package botprotection

import "testing"

func TestParseConfigDefaults(t *testing.T) {
	c, err := ParseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.RateLimit.RequestsPerWindow != 120 {
		t.Fatalf("rpm = %d", c.RateLimit.RequestsPerWindow)
	}
	if c.Scoring.BlockThreshold != 70 {
		t.Fatalf("block = %d", c.Scoring.BlockThreshold)
	}
}

func TestBlockedCountrySet(t *testing.T) {
	c := Config{
		GeoBlock: GeoBlockConfig{
			Enabled:          true,
			BlockedCountries: []string{" ru ", "CN", "xxx"},
		},
	}
	m := c.BlockedCountrySet()
	if len(m) != 2 {
		t.Fatalf("len = %d", len(m))
	}
	if _, ok := m["RU"]; !ok {
		t.Fatal("missing RU")
	}
}
