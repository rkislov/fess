package main

import (
	"context"
	"database/sql"
	"log"
	"net"
	"net/http"
	"strings"

	"fence/pkg/clientip"
	"fence/pkg/prommetrics"
	"fence/pkg/routing"
)

const maxUserAgentBytes = 1024

func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 && s[len(s)-1]&0xC0 == 0x80 {
		s = s[:len(s)-1]
	}
	return s
}

func writeProxyAccessLog(ctx context.Context, db *sql.DB, r *http.Request, mr routing.MatchResult, outcome string, ipRes *clientip.Resolver) {
	host := publicHostHeader(r, ipRes)
	up := ""
	if mr.Backend != nil {
		up = mr.Backend.String()
	}
	ip := ipRes.ClientHost(r)
	if ip == "" {
		if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ip = h
		} else {
			ip = r.RemoteAddr
		}
	}
	tcpPeer := clientip.PeerHost(r)
	be := strings.TrimSpace(mr.BackendName)
	scheme := requestScheme(r)
	cc := countryCodeForRequest(r, ip)
	ua := truncateUTF8(strings.TrimSpace(r.Header.Get("User-Agent")), maxUserAgentBytes)
	_, err := db.ExecContext(ctx, `
INSERT INTO proxy_access_logs(host, method, path, client_ip, tcp_peer, backend_name, upstream_base, outcome, protocol, country_code, user_agent)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		host, r.Method, r.URL.Path, ip, tcpPeer, be, up, outcome, scheme, cc, ua)
	if err != nil {
		log.Printf("proxy access log insert failed: %v", err)
	}
	prommetrics.RecordGatewayOutcome(outcome)
}
