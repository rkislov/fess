package main

import (
	"net/http"

	"fence/pkg/auth"
)

func requireWriteRole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if auth.IsPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		claims, ok := auth.ClaimsFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if !auth.CanWrite(claims.Role) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "read-only role"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
