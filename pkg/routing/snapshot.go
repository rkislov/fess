package routing

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// tlsSkipVerifyKey is the context key for per-request upstream TLS InsecureSkipVerify (HTTPS backends only).
type tlsSkipVerifyKey struct{}

// WithTLSSkipVerify returns ctx carrying whether the active upstream should use InsecureSkipVerify.
func WithTLSSkipVerify(ctx context.Context, skip bool) context.Context {
	return context.WithValue(ctx, tlsSkipVerifyKey{}, skip)
}

// TLSSkipVerifyFromContext reports the per-backend TLS skip flag (default false).
func TLSSkipVerifyFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(tlsSkipVerifyKey{}).(bool)
	return v
}

// Snapshot is immutable routing state for the gateway.
type Snapshot struct {
	Default *url.URL
	Sites   []ResolvedSite
}

// ResolvedBackend is one upstream path rule (flattened backend + path row).
type ResolvedBackend struct {
	PathPrefix       string
	PathPriority     int
	BackendPriority  int
	Backend          *url.URL
	BackendName      string
	TLSSkipVerify    bool
	WebSocketEnabled bool
	TimeoutSec       int // 0 = no limit
	IdleTimeoutSec   int // 0 = transport default
	IPAllowMode      string
	AllowedPrefixes  []netip.Prefix
}

// ResolvedSite is one enabled site with backends and optional WAF policy scope.
type ResolvedSite struct {
	HostPattern string
	Priority    int
	PolicyID    string
	Backends    []ResolvedBackend
}

// MatchResult is the routing + policy scope for a request Host and path.
type MatchResult struct {
	Backend            *url.URL
	BackendName        string
	PolicyID           string
	TLSSkipVerify      bool
	WebSocketEnabled   bool
	TimeoutSec         int
	IdleTimeoutSec     int
	IPAllowMode        string
	AllowedPrefixes    []netip.Prefix
	MatchedPathPrefix  string // normalized prefix used for this backend ("" = default)
}

// Match returns upstream URL and optional policy filter for the HTTP Host header and request path.
func (s Snapshot) Match(hostHeader, requestPath string) MatchResult {
	h := strings.TrimSpace(strings.ToLower(hostHeader))
	if h2, _, err := net.SplitHostPort(h); err == nil {
		h = strings.ToLower(h2)
	}
	reqPath := RequestPath(requestPath)

	for _, site := range s.Sites {
		if !HostMatch(site.HostPattern, h) {
			continue
		}
		if br := site.pickBackend(reqPath); br != nil && br.Backend != nil {
			return MatchResult{
				Backend:           br.Backend,
				BackendName:       br.BackendName,
				PolicyID:          site.PolicyID,
				TLSSkipVerify:     br.TLSSkipVerify,
				WebSocketEnabled:  br.WebSocketEnabled,
				TimeoutSec:        br.TimeoutSec,
				IdleTimeoutSec:    br.IdleTimeoutSec,
				IPAllowMode:       br.IPAllowMode,
				AllowedPrefixes:   br.AllowedPrefixes,
				MatchedPathPrefix: NormalizePathPrefix(br.PathPrefix),
			}
		}
	}
	return MatchResult{Backend: s.Default, PolicyID: ""}
}

func (site ResolvedSite) pickBackend(reqPath string) *ResolvedBackend {
	if len(site.Backends) == 0 {
		return nil
	}
	var best *ResolvedBackend
	bestLen := -1
	var defaults []*ResolvedBackend

	for i := range site.Backends {
		b := &site.Backends[i]
		if b.Backend == nil {
			continue
		}
		prefix := NormalizePathPrefix(b.PathPrefix)
		if IsCatchAllPath(prefix) {
			defaults = append(defaults, b)
			continue
		}
		if !PathMatchesPrefix(reqPath, prefix) {
			continue
		}
		plen := len(prefix)
		if plen > bestLen {
			best = b
			bestLen = plen
			continue
		}
		if plen == bestLen && best != nil {
			if b.PathPriority < best.PathPriority {
				best = b
			} else if b.PathPriority == best.PathPriority && b.BackendPriority < best.BackendPriority {
				best = b
			}
		}
	}
	if best != nil {
		return best
	}
	if len(defaults) == 0 {
		return nil
	}
	def := defaults[0]
	for _, b := range defaults[1:] {
		if b.PathPriority < def.PathPriority {
			def = b
		} else if b.PathPriority == def.PathPriority && b.BackendPriority < def.BackendPriority {
			def = b
		}
	}
	return def
}

// HostMatch reports whether reqHost matches pattern (same rules as gateway routing: *, exact, or *.example.com).
func HostMatch(pattern, reqHost string) bool {
	pat := strings.TrimSpace(strings.ToLower(pattern))
	if pat == "*" || pat == "" {
		return true
	}
	if strings.HasPrefix(pat, "*.") {
		root := strings.TrimPrefix(pat, "*.")
		if reqHost == root {
			return false
		}
		return reqHost == root || strings.HasSuffix(reqHost, "."+root)
	}
	return pat == reqHost
}

// LoadSnapshot reads enabled sites and all enabled backends for path-aware matching.
func LoadSnapshot(ctx context.Context, db *sql.DB, defaultUpstream *url.URL) (Snapshot, error) {
	out := Snapshot{Default: defaultUpstream}

	rows, err := db.QueryContext(ctx, `
SELECT s.host_pattern, s.priority, COALESCE(s.policy_id::text, ''),
  b.name, b.base_url, b.priority, b.tls_skip_verify,
  COALESCE(p.path_prefix, '*'), p.priority, p.websocket_enabled,
  p.timeout_sec, p.idle_timeout_sec, p.ip_allow_mode, p.allowed_cidrs
FROM sites s
JOIN backends b ON b.site_id = s.id AND b.enabled = TRUE
JOIN backend_paths p ON p.backend_id = b.id AND p.enabled = TRUE
WHERE s.enabled = TRUE
ORDER BY s.priority ASC, s.created_at ASC, b.priority ASC, b.created_at ASC, p.priority ASC, p.created_at ASC`)
	if err != nil {
		return out, fmt.Errorf("routing query: %w", err)
	}
	defer rows.Close()

	type siteKey struct {
		host string
		pri  int
	}
	siteIndex := make(map[siteKey]int)
	var order []siteKey

	for rows.Next() {
		var hostPat string
		var sitePri int
		var policyID string
		var backendName, base string
		var backendPri, pathPri int
		var tlsSkip, wsEn bool
		var pathPrefix string
		var timeoutSec, idleTimeoutSec int
		var ipAllowMode, allowedCIDRsJSON string
		if err := rows.Scan(&hostPat, &sitePri, &policyID, &backendName, &base, &backendPri, &tlsSkip, &pathPrefix, &pathPri, &wsEn, &timeoutSec, &idleTimeoutSec, &ipAllowMode, &allowedCIDRsJSON); err != nil {
			return out, err
		}
		u, err := url.Parse(strings.TrimSpace(base))
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		key := siteKey{host: hostPat, pri: sitePri}
		idx, ok := siteIndex[key]
		if !ok {
			order = append(order, key)
			idx = len(out.Sites)
			siteIndex[key] = idx
			out.Sites = append(out.Sites, ResolvedSite{
				HostPattern: hostPat,
				Priority:    sitePri,
				PolicyID:    strings.TrimSpace(policyID),
			})
		}
		ipMode := strings.TrimSpace(strings.ToLower(ipAllowMode))
		if ipMode == "" {
			ipMode = IPAllowNone
		}
		var allowed []netip.Prefix
		if ipMode == IPAllowCustom {
			parsed, perr := ParseAllowedCIDRsJSON(allowedCIDRsJSON)
			if perr != nil {
				log.Printf("routing: backend %q allowed_cidrs invalid: %v", backendName, perr)
				ipMode = IPAllowNone
			} else {
				allowed = parsed
			}
		}
		out.Sites[idx].Backends = append(out.Sites[idx].Backends, ResolvedBackend{
			PathPrefix:       NormalizePathPrefix(pathPrefix),
			PathPriority:     pathPri,
			BackendPriority:  backendPri,
			Backend:          u,
			BackendName:      strings.TrimSpace(backendName),
			TLSSkipVerify:    tlsSkip,
			WebSocketEnabled: wsEn,
			TimeoutSec:       timeoutSec,
			IdleTimeoutSec:   idleTimeoutSec,
			IPAllowMode:      ipMode,
			AllowedPrefixes:  allowed,
		})
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return out, nil
}
