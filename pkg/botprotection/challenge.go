package botprotection

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ChallengeQueryParam is the query key for one-shot browser verification.
const ChallengeQueryParam = "__fence_cv"

// ChallengeValid reports whether the request already passed cookie/session challenge.
func ChallengeValid(r *http.Request, cfg ChallengeConfig, clientIP string) bool {
	if !cfg.Enabled || strings.TrimSpace(cfg.Secret) == "" {
		return true
	}
	name := cookieName(cfg)
	if c, err := r.Cookie(name); err == nil && validateChallengeToken(cfg.Secret, clientIP, c.Value, cfg.TTLSec) {
		return true
	}
	q := strings.TrimSpace(r.URL.Query().Get(ChallengeQueryParam))
	return q != "" && validateChallengeToken(cfg.Secret, clientIP, q, cfg.TTLSec)
}

func cookieName(cfg ChallengeConfig) string {
	n := strings.TrimSpace(cfg.CookieName)
	if n == "" {
		return "fence_bot"
	}
	return n
}

// IssueChallengeToken creates a signed token for cookie or query validation.
func IssueChallengeToken(secret, clientIP string, ttlSec int) string {
	if ttlSec <= 0 {
		ttlSec = 86400
	}
	exp := time.Now().UTC().Add(time.Duration(ttlSec) * time.Second).Unix()
	payload := fmt.Sprintf("%s|%d", strings.TrimSpace(clientIP), exp)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + sig))
}

func validateChallengeToken(secret, clientIP, token string, ttlSec int) bool {
	secret = strings.TrimSpace(secret)
	if secret == "" || token == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return false
	}
	ipPart, expPart, sigPart := parts[0], parts[1], parts[2]
	if strings.TrimSpace(clientIP) != strings.TrimSpace(ipPart) {
		return false
	}
	exp, err := strconv.ParseInt(expPart, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().UTC().Unix() > exp {
		return false
	}
	payload := ipPart + "|" + expPart
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	expect := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expect), []byte(sigPart))
}

// SetChallengeCookie writes the validated session cookie.
func SetChallengeCookie(w http.ResponseWriter, cfg ChallengeConfig, clientIP string, secure bool) {
	if !cfg.Enabled || strings.TrimSpace(cfg.Secret) == "" {
		return
	}
	ttl := cfg.TTLSec
	if ttl <= 0 {
		ttl = 86400
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName(cfg),
		Value:    IssueChallengeToken(cfg.Secret, clientIP, ttl),
		Path:     "/",
		MaxAge:   ttl,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
}

// ChallengePageHTML is a minimal auto-redirect page for browsers.
func ChallengePageHTML(verifyURL string) string {
	verifyURL = strings.ReplaceAll(verifyURL, "'", "%27")
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Checking…</title></head><body>
<p>Verifying your browser…</p>
<script>location.replace('` + verifyURL + `');</script>
<noscript><p><a href="` + verifyURL + `">Continue</a></p></noscript>
</body></html>`
}

// BuildChallengeVerifyURL returns same path with signed query token.
func BuildChallengeVerifyURL(r *http.Request, cfg ChallengeConfig, clientIP string) string {
	if r == nil || r.URL == nil {
		return "/?" + ChallengeQueryParam + "="
	}
	token := IssueChallengeToken(cfg.Secret, clientIP, cfg.TTLSec)
	q := r.URL.Query()
	q.Set(ChallengeQueryParam, token)
	u := *r.URL
	u.RawQuery = q.Encode()
	return u.RequestURI()
}
