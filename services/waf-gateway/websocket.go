package main

import (
	"database/sql"
	"net/http"
	"strings"

	"fence/pkg/clientip"
	"fence/pkg/engine"
	"fence/pkg/policy"
	"fence/pkg/routing"
)

func isWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	conn := strings.ToLower(r.Header.Get("Connection"))
	return strings.Contains(conn, "upgrade")
}

// serveWebSocketUpgrade proxies a handshake without buffering the body (ICAP/malware skip).
func serveWebSocketUpgrade(
	w http.ResponseWriter,
	r *http.Request,
	mr routing.MatchResult,
	db *sql.DB,
	store *policy.Store,
	evaluator *engine.Evaluator,
	proxy http.Handler,
	failMode string,
	gateTF threatFeedGateResult,
	ipRes *clientip.Resolver,
) {
	if !enforceBackendIPAllow(w, r, mr, db, ipRes) {
		return
	}
	if !mr.WebSocketEnabled {
		writeProxyAccessLog(r.Context(), db, r, mr, "websocket_disabled", ipRes)
		http.Error(w, "WebSocket is not enabled for this backend/path", http.StatusForbidden)
		return
	}

	snapshot := store.Current()
	clientHost := ipRes.ClientHost(r)
	if strings.TrimSpace(clientHost) == "" {
		clientHost = clientip.PeerHost(r)
	}
	decision := evaluator.Evaluate(r, snapshot, mr.PolicyID, clientHost)
	effectiveAction := decision.Action
	if decision.PolicyMode == "log" && (decision.Action == "block" || decision.Action == "redirect" || decision.Action == "replace") {
		effectiveAction = "log"
	}
	writeWAFLog(r.Context(), db, r, decision, effectiveAction, ipRes)

	accessOutcome := "websocket_proxied"
	switch effectiveAction {
	case "block":
		accessOutcome = "waf_block"
	case "redirect":
		accessOutcome = "redirect"
	}
	if accessOutcome == "websocket_proxied" && gateTF.ProxyOutcomeHint != "" {
		accessOutcome = gateTF.ProxyOutcomeHint
	}
	writeProxyAccessLog(r.Context(), db, r, mr, accessOutcome, ipRes)

	switch effectiveAction {
	case "block":
		http.Error(w, "blocked by WAF policy", http.StatusForbidden)
	case "redirect":
		target := decision.RedirectURL
		if target == "" {
			target = "/"
		}
		http.Redirect(w, r, target, http.StatusFound)
	case "replace":
		proxy.ServeHTTP(w, r)
	default:
		if decision.Action == "deny_on_error" && strings.EqualFold(failMode, "close") {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r)
	}
}
