package main

import (
	"net/http"
	"strings"

	"fence/pkg/clientip"
)

// applyUpstreamClientHeaders sets headers so backends see the same effective client IP as Fence
// (logging / WAF). When no trusted proxy list is configured, inbound X-Forwarded-For is not
// trusted and is replaced with the TCP peer so spoofed chains are not forwarded.
func applyUpstreamClientHeaders(req *http.Request, ipRes *clientip.Resolver) {
	if req == nil || ipRes == nil {
		return
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
		req.Header.Set("X-Forwarded-Proto", requestScheme(req))
	}
}
