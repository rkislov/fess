package routing

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Snapshot is immutable routing state for the gateway.
type Snapshot struct {
	Default *url.URL
	Sites   []ResolvedSite
}

// ResolvedSite is one enabled site with its primary backend and optional WAF policy scope.
type ResolvedSite struct {
	HostPattern string
	Priority    int
	Backend     *url.URL
	// PolicyID is a published policy UUID, or empty string = run all enabled policies for this host.
	PolicyID string
}

// MatchResult is the routing + policy scope for a request Host.
type MatchResult struct {
	Backend  *url.URL
	PolicyID string
}

// Match returns upstream URL and optional policy filter for the HTTP Host header (port stripped for matching).
func (s Snapshot) Match(hostHeader string) MatchResult {
	h := strings.TrimSpace(strings.ToLower(hostHeader))
	if h2, _, err := net.SplitHostPort(h); err == nil {
		h = strings.ToLower(h2)
	}

	for _, site := range s.Sites {
		if hostMatch(site.HostPattern, h) {
			if site.Backend != nil {
				return MatchResult{Backend: site.Backend, PolicyID: site.PolicyID}
			}
		}
	}
	return MatchResult{Backend: s.Default, PolicyID: ""}
}

func hostMatch(pattern, reqHost string) bool {
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

// LoadSnapshot reads enabled sites with their first enabled backend (by priority).
func LoadSnapshot(ctx context.Context, db *sql.DB, defaultUpstream *url.URL) (Snapshot, error) {
	out := Snapshot{Default: defaultUpstream}

	rows, err := db.QueryContext(ctx, `
SELECT s.host_pattern, s.priority, sub.base_url, COALESCE(s.policy_id::text, '')
FROM sites s
JOIN LATERAL (
  SELECT base_url
  FROM backends
  WHERE site_id = s.id AND enabled = TRUE
  ORDER BY priority ASC, created_at ASC
  LIMIT 1
) sub ON TRUE
WHERE s.enabled = TRUE
ORDER BY s.priority ASC, s.created_at ASC`)
	if err != nil {
		return out, fmt.Errorf("routing query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var hostPat string
		var pri int
		var base string
		var policyID string
		if err := rows.Scan(&hostPat, &pri, &base, &policyID); err != nil {
			return out, err
		}
		u, err := url.Parse(strings.TrimSpace(base))
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		out.Sites = append(out.Sites, ResolvedSite{
			HostPattern: hostPat,
			Priority:    pri,
			Backend:     u,
			PolicyID:    strings.TrimSpace(policyID),
		})
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return out, nil
}
