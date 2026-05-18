package botprotection

import (
	"net/http/httptest"
	"testing"
)

func TestChallengeTokenRoundTrip(t *testing.T) {
	cfg := ChallengeConfig{Enabled: true, Secret: "test-secret", TTLSec: 3600}
	ip := "203.0.113.5"
	tok := IssueChallengeToken(cfg.Secret, ip, cfg.TTLSec)
	if !validateChallengeToken(cfg.Secret, ip, tok, cfg.TTLSec) {
		t.Fatal("token should validate")
	}
	if validateChallengeToken(cfg.Secret, "1.2.3.4", tok, cfg.TTLSec) {
		t.Fatal("wrong IP should fail")
	}
	r := httptest.NewRequest("GET", "/", nil)
	if ChallengeValid(r, cfg, ip) {
		t.Fatal("no cookie yet")
	}
}
