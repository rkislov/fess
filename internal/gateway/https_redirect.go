package gateway

import (
	"net"
	"net/http"
	"strings"
)

// Redirect only configured TLS hosts; never reflect an arbitrary Host header.
func httpsRedirect(w http.ResponseWriter, r *http.Request, hosts map[string]string, knownTLS func(string) bool) bool {
	if r.TLS != nil {
		return false
	}
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	target, ok := hosts[host]
	if !ok && knownTLS != nil && knownTLS(host) {
		target = host
		ok = true
	}
	if !ok {
		return false
	}
	http.Redirect(w, r, "https://"+target+r.URL.RequestURI(), http.StatusPermanentRedirect)
	return true
}
