package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

var publicPaths = map[string]bool{
	"/healthz":                true,
	"/api/v1/auth/login":      true,
	"/api/v1/auth/refresh":    true,
}

func IsPublicPath(path string) bool {
	return publicPaths[path]
}

func Middleware(svc *Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if svc.AuthDisabled() || IsPublicPath(r.URL.Path) {
			if svc.AuthDisabled() {
				r = r.WithContext(WithClaims(r.Context(), Claims{UserID: "dev", Username: "dev", Role: RoleAdmin}))
			}
			next.ServeHTTP(w, r)
			return
		}
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeAuthError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		claims, err := svc.ParseAccessToken(token)
		if err != nil {
			status := http.StatusUnauthorized
			msg := "invalid token"
			if err == ErrExpiredToken {
				msg = "token expired"
			}
			writeAuthError(w, status, msg)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
	})
}

func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
