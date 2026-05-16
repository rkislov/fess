package main

import (
	"net"
	"net/http"
	"strings"

	"fence/pkg/clientip"
)

// publicHostHeader returns the externally visible host for routing/CORS-aware upstreams.
// X-Forwarded-Host is honored only from configured trusted proxies.
func publicHostHeader(r *http.Request, ipRes *clientip.Resolver) string {
	if r == nil {
		return ""
	}
	if ipRes != nil && ipRes.TrustsRequest(r) {
		if h := firstForwardedHost(r.Header.Get("X-Forwarded-Host")); h != "" {
			return h
		}
	}
	return hostHeader(r)
}

func firstForwardedHost(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	// Some proxies append just like X-Forwarded-For. The leftmost value is the original host.
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	v = strings.Trim(v, "\"")
	return strings.TrimSpace(v)
}

// applyUpstreamClientHeaders sets headers so backends see the same public request context as Fence
// (client IP, public host, original scheme). When no trusted proxy list is configured, inbound
// X-Forwarded-For is not trusted and is replaced with the TCP peer so spoofed chains are not forwarded.
func applyUpstreamClientHeaders(req *http.Request, ipRes *clientip.Resolver, originalHost, originalScheme string) {
	if req == nil || ipRes == nil {
		return
	}
	originalHost = strings.TrimSpace(originalHost)
	originalScheme = strings.TrimSpace(strings.ToLower(originalScheme))
	if originalScheme == "" {
		originalScheme = requestScheme(req)
	}

	client := strings.TrimSpace(ipRes.ClientHost(req))
	if client == "" {
		return
	}

	req.Header.Set("X-Real-IP", client)

	if !ipRes.TrustsForwardedHeaders() {
		req.Header.Set("X-Forwarded-For", client)
	} else if strings.TrimSpace(req.Header.Get("X-Forwarded-For")) == "" {
		req.Header.Set("X-Forwarded-For", client)
	}

	if strings.TrimSpace(req.Header.Get("X-Forwarded-Proto")) == "" {
		req.Header.Set("X-Forwarded-Proto", originalScheme)
	}
	if originalHost != "" {
		req.Header.Set("X-Forwarded-Host", originalHost)
		req.Header.Set("X-Original-Host", originalHost)
		if _, p, err := net.SplitHostPort(originalHost); err == nil {
			req.Header.Set("X-Forwarded-Port", p)
		} else if originalScheme == "https" {
			req.Header.Set("X-Forwarded-Port", "443")
		} else if originalScheme == "http" {
			req.Header.Set("X-Forwarded-Port", "80")
		}
	}
}
