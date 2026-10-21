package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"fence/pkg/auth"
)

type mapSettings struct {
	Provider string `json:"provider"`
	APIKey   string `json:"api_key"`
}

// Browser map keys are intentionally readable by dashboard users. Providers should
// restrict these public keys to the installation's domain.
func mapSettingsHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	switch r.Method {
	case http.MethodGet:
		var s mapSettings
		if err := db.QueryRowContext(r.Context(), `SELECT provider, api_key FROM map_settings WHERE singleton='global'`).Scan(&s.Provider, &s.APIKey); err != nil {
			writeJSON(w, 500, map[string]string{"error": "cannot load map settings"})
			return
		}
		writeJSON(w, 200, s)
	case http.MethodPut:
		claims, ok := auth.ClaimsFromContext(r.Context())
		if !ok || !auth.CanAdmin(claims.Role) {
			writeJSON(w, 403, map[string]string{"error": "admin required"})
			return
		}
		var s mapSettings
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&s); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
			return
		}
		s.APIKey = strings.TrimSpace(s.APIKey)
		if (s.Provider != "carto" && s.Provider != "yandex") || len(s.APIKey) > 1024 || strings.ContainsAny(s.APIKey, "\r\n") {
			writeJSON(w, 400, map[string]string{"error": "invalid provider or API key"})
			return
		}
		if _, err := db.ExecContext(r.Context(), `UPDATE map_settings SET provider=$1, api_key=$2 WHERE singleton='global'`, s.Provider, s.APIKey); err != nil {
			writeJSON(w, 500, map[string]string{"error": "cannot save map settings"})
			return
		}
		writeAuditLog(r.Context(), db, claims.Username, "update", "map_settings", "global", nil, map[string]any{"provider": s.Provider, "api_key_set": s.APIKey != ""})
		writeJSON(w, 200, s)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
