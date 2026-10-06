package main

import (
	"database/sql"
	"log"
	"net/http"
	"strings"
)

func serveACMEHTTP01(w http.ResponseWriter, r *http.Request, db *sql.DB) bool {
	if r == nil || r.URL == nil || db == nil {
		return false
	}
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	token = strings.Trim(token, "/")
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return true
	}
	var keyAuth string
	err := db.QueryRowContext(r.Context(), `
SELECT key_authorization FROM acme_http01_challenges
WHERE token=$1 AND expires_at > NOW()`, token).Scan(&keyAuth)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return true
	}
	if err != nil {
		log.Printf("acme http-01: %v", err)
		http.Error(w, "challenge unavailable", http.StatusInternalServerError)
		return true
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(keyAuth))
	return true
}
