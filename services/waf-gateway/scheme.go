package main

import (
	"net/http"
	"strings"
)

func requestScheme(r *http.Request) string {
	if p := strings.TrimSpace(strings.ToLower(r.Header.Get("X-Forwarded-Proto"))); p != "" {
		if strings.HasPrefix(p, "https") {
			return "https"
		}
		return "http"
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
