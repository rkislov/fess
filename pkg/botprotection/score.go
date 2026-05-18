package botprotection

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

// ScoreInput is collected on the gateway hot path.
type ScoreInput struct {
	UserAgent      string
	Accept         string
	AcceptLanguage string
	SecFetchSite   string
	SecFetchMode   string
	HeaderCount    int
	JA3Header      string
	TLS            *tls.ConnectionState
	InterRequestMS int64 // <0 if unknown
}

// ScoreResult is behavioral score 0–100 and human-readable reasons.
type ScoreResult struct {
	Score   int
	Reasons []string
}

// ComputeScore returns 0–100 suspicion score from headers, TLS, and timing.
func ComputeScore(cfg Config, in ScoreInput) ScoreResult {
	if !cfg.Scoring.Enabled && !cfg.TLSScoring.Enabled {
		return ScoreResult{}
	}
	var score int
	var reasons []string
	add := func(n int, why string) {
		score += n
		if why != "" {
			reasons = append(reasons, why)
		}
	}

	ua := strings.TrimSpace(in.UserAgent)
	if ua == "" {
		add(35, "missing User-Agent")
	} else {
		low := strings.ToLower(ua)
		switch {
		case strings.Contains(low, "bot"), strings.Contains(low, "crawler"), strings.Contains(low, "spider"),
			strings.Contains(low, "scraper"), strings.Contains(low, "curl/"), strings.Contains(low, "wget/"),
			strings.Contains(low, "python-requests"), strings.Contains(low, "go-http-client"),
			strings.Contains(low, "java/"), strings.Contains(low, "headless"):
			add(25, "suspicious User-Agent")
		}
		if len(ua) < 12 {
			add(10, "short User-Agent")
		}
	}

	if strings.TrimSpace(in.Accept) == "" {
		add(12, "missing Accept")
	}
	if strings.TrimSpace(in.AcceptLanguage) == "" {
		add(15, "missing Accept-Language")
	}

	// Modern browsers usually send Sec-Fetch-* on navigations.
	if ua != "" && strings.Contains(strings.ToLower(ua), "chrome") && strings.TrimSpace(in.SecFetchSite) == "" {
		add(20, "Chrome without Sec-Fetch-*")
	}

	if in.HeaderCount > 0 && in.HeaderCount < 6 {
		add(15, "few request headers")
	}

	if cfg.TLSScoring.Enabled {
		if in.TLS != nil {
			ver := in.TLS.Version
			if cfg.TLSScoring.BlockLegacyTLS && ver > 0 && ver < tls.VersionTLS12 {
				add(40, "legacy TLS version")
			}
		}
		if cfg.TLSScoring.TrustJA3Header {
			ja3 := strings.ToLower(strings.TrimSpace(in.JA3Header))
			if ja3 != "" {
				if blocked := cfg.BlockedJA3Set(); blocked != nil {
					if _, ok := blocked[ja3]; ok {
						add(50, "blocked JA3 fingerprint")
					}
				}
			}
		}
	}

	if in.InterRequestMS >= 0 && in.InterRequestMS < 30 {
		add(25, "very fast repeat requests")
	} else if in.InterRequestMS >= 0 && in.InterRequestMS < 80 {
		add(12, "fast repeat requests")
	}

	if score > 100 {
		score = 100
	}
	return ScoreResult{Score: score, Reasons: reasons}
}

// CollectScoreInput builds ScoreInput from an HTTP request.
func CollectScoreInput(r *http.Request, interRequest time.Duration) ScoreInput {
	if r == nil {
		return ScoreInput{InterRequestMS: -1}
	}
	var interMS int64 = -1
	if interRequest >= 0 {
		interMS = interRequest.Milliseconds()
	}
	ja3 := ""
	if r.Header != nil {
		ja3 = firstHeader(r, "X-JA3-Hash", "X-JA3-Fingerprint", "X-TLS-Fingerprint", "X-SSL-JA3")
	}
	var tlsState *tls.ConnectionState
	if r.TLS != nil {
		t := *r.TLS
		tlsState = &t
	}
	return ScoreInput{
		UserAgent:      r.Header.Get("User-Agent"),
		Accept:         r.Header.Get("Accept"),
		AcceptLanguage: r.Header.Get("Accept-Language"),
		SecFetchSite:   r.Header.Get("Sec-Fetch-Site"),
		SecFetchMode:   r.Header.Get("Sec-Fetch-Mode"),
		HeaderCount:    headerCount(r),
		JA3Header:      ja3,
		TLS:            tlsState,
		InterRequestMS: interMS,
	}
}

func firstHeader(r *http.Request, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(r.Header.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

func headerCount(r *http.Request) int {
	n := 0
	for k := range r.Header {
		if strings.TrimSpace(k) != "" {
			n++
		}
	}
	return n
}
