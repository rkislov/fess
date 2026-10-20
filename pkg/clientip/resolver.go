// Package clientip resolves the original client address when the gateway sits behind
// load balancers / reverse proxies that set X-Forwarded-For or X-Real-IP.
//
// Trust model: forwarded headers are honored only if the immediate TCP peer (RemoteAddr)
// matches one of the configured trusted CIDRs. Otherwise RemoteAddr is used (no header trust).
package clientip

import (
	"log"
	"net"
	"net/http"
	"strings"
)

// Resolver holds trusted proxy / load-balancer source CIDRs.
type Resolver struct {
	trusted []*net.IPNet
}

// ParseTrustedProxies parses a comma-separated list of CIDRs (e.g. "10.0.0.0/8,172.18.0.0/16").
// Empty string returns a Resolver that only uses the direct TCP peer (same as no LB).
// Invalid tokens are skipped with a log line.
func ParseTrustedProxies(list string) *Resolver {
	list = strings.TrimSpace(list)
	if list == "" {
		return &Resolver{}
	}
	var nets []*net.IPNet
	for _, tok := range strings.Split(list, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		// Single IP without mask → /32 or /128
		if !strings.Contains(tok, "/") {
			ip := net.ParseIP(tok)
			if ip == nil {
				log.Printf("clientip: skip invalid trusted entry %q", tok)
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				tok = ip4.String() + "/32"
			} else {
				tok = ip.String() + "/128"
			}
		}
		_, n, err := net.ParseCIDR(tok)
		if err != nil {
			log.Printf("clientip: skip invalid CIDR %q: %v", tok, err)
			continue
		}
		nets = append(nets, n)
	}
	return &Resolver{trusted: nets}
}

// TrustsForwardedHeaders reports whether X-Forwarded-For / X-Real-IP may be honored
// (trusted proxy CIDRs were configured).
func (r *Resolver) TrustsForwardedHeaders() bool {
	if r == nil {
		return false
	}
	return !r.empty()
}

// TrustsRequest reports whether this request arrived from a configured trusted proxy.
// Forwarded headers should only be honored when this is true.
func (r *Resolver) TrustsRequest(req *http.Request) bool {
	if r.empty() || req == nil {
		return false
	}
	peer := peerIP(req)
	return peer != nil && r.contains(peer)
}

func (r *Resolver) empty() bool {
	return r == nil || len(r.trusted) == 0
}

func ipUnmap(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

func (r *Resolver) contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip = ipUnmap(ip)
	for _, n := range r.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// peerIP returns the host part of RemoteAddr as a parsed IP.
func peerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return net.ParseIP(host)
}

// ClientHost returns the client IP string (no port) for logging / GeoIP.
// Without trusted proxies, this is always the TCP peer.
func (r *Resolver) ClientHost(req *http.Request) string {
	peer := peerIP(req)
	if !r.TrustsRequest(req) {
		if peer != nil {
			return peer.String()
		}
		h, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			return strings.TrimSpace(req.RemoteAddr)
		}
		return h
	}

	if xff := strings.TrimSpace(req.Header.Get("X-Forwarded-For")); xff != "" {
		if ip := parseXForwardedFor(xff, r); ip != "" {
			return ip
		}
	}
	if xr := strings.TrimSpace(req.Header.Get("X-Real-IP")); xr != "" {
		if ip := parseIP(xr); ip != nil {
			return ip.String()
		}
	}
	if tc := strings.TrimSpace(req.Header.Get("True-Client-IP")); tc != "" {
		if ip := parseIP(tc); ip != nil {
			return ip.String()
		}
	}
	if cf := strings.TrimSpace(req.Header.Get("CF-Connecting-IP")); cf != "" {
		if ip := parseIP(cf); ip != nil {
			return ip.String()
		}
	}
	if peer != nil {
		return peer.String()
	}
	return ""
}

func parseIP(s string) net.IP {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ipUnmap(ip)
}

// PeerHost returns the immediate TCP peer address (host only, no port).
func PeerHost(req *http.Request) string {
	p := peerIP(req)
	if p != nil {
		return p.String()
	}
	h, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(req.RemoteAddr)
	}
	return h
}

// parseXForwardedFor walks comma-separated entries left-to-right and returns the first
// IP that is not in the trusted set (the original client before our trusted chain).
func parseXForwardedFor(xff string, r *Resolver) string {
	parts := strings.Split(xff, ",")
	for _, p := range parts {
		ip := parseIP(p)
		if ip == nil {
			continue
		}
		if !r.contains(ip) {
			return ip.String()
		}
	}
	// Every hop in the list is trusted (unusual); use the leftmost valid IP.
	for _, p := range parts {
		if ip := parseIP(p); ip != nil {
			return ip.String()
		}
	}
	return ""
}
