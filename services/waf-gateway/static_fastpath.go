package main

import (
	"database/sql"
	"net/http"
	"strings"

	"fence/pkg/clientip"
	"fence/pkg/routing"
)

// staticAssetExtensions are proxied on a fast path (GET/HEAD only): no WAF rule evaluation.
// DocumentServer/OnlyOffice loads hundreds of .js/.css/.wasm assets; OWASP path rules can false-positive.
var staticAssetExtensions = []string{
	".js", ".mjs", ".css", ".wasm", ".map",
	".json", ".woff2", ".woff", ".ttf", ".eot", ".otf",
	".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bin",
}

func isStaticAssetRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	path := strings.ToLower(r.URL.Path)
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	for _, ext := range staticAssetExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func serveStaticFastPath(w http.ResponseWriter, r *http.Request, mr routing.MatchResult, db *sql.DB, proxy http.Handler, ipRes *clientip.Resolver, outcomeHint string) {
	if outcomeHint != "" {
		writeProxyAccessLog(r.Context(), db, r, mr, outcomeHint, ipRes)
	} else {
		writeProxyAccessLog(r.Context(), db, r, mr, "proxied_static", ipRes)
	}
	proxy.ServeHTTP(w, r)
}
