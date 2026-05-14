package main

import (
	"context"
	"database/sql"
	"log"
	"net"
	"net/http"

	"fence/pkg/clientip"
	"fence/pkg/routing"
)

func writeProxyAccessLog(ctx context.Context, db *sql.DB, r *http.Request, mr routing.MatchResult, outcome string, ipRes *clientip.Resolver) {
	host := hostHeader(r)
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
	scheme := requestScheme(r)
	cc := countryCodeForRequest(r, ip)
	_, err := db.ExecContext(ctx, `
INSERT INTO proxy_access_logs(host, method, path, client_ip, upstream_base, outcome, protocol, country_code)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		host, r.Method, r.URL.Path, ip, up, outcome, scheme, cc)
	if err != nil {
		log.Printf("proxy access log insert failed: %v", err)
	}
}
