package main

import (
	"database/sql"
	"net/http"
	"strings"

	"fence/pkg/clientip"
	"fence/pkg/routing"
)

func enforceBackendIPAllow(w http.ResponseWriter, r *http.Request, mr routing.MatchResult, db *sql.DB, ipRes *clientip.Resolver) bool {
	mode := strings.TrimSpace(strings.ToLower(mr.IPAllowMode))
	if mode == "" || mode == routing.IPAllowNone {
		return true
	}
	clientHost := ipRes.ClientHost(r)
	if strings.TrimSpace(clientHost) == "" {
		clientHost = clientip.PeerHost(r)
	}
	if routing.ClientIPAllowed(clientHost, mode, mr.AllowedPrefixes) {
		return true
	}
	writeProxyAccessLog(r.Context(), db, r, mr, "backend_ip_deny", ipRes)
	http.Error(w, "forbidden: client IP not allowed for this path", http.StatusForbidden)
	return false
}
