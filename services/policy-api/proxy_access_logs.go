package main

import (
	"database/sql"
	"net/http"
	"time"
)

func proxyAccessLogsHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rows, err := db.QueryContext(r.Context(), `
SELECT id, host, method, path, COALESCE(client_ip,''), COALESCE(tcp_peer,''), COALESCE(backend_name,''),
       upstream_base, outcome,
       COALESCE(protocol,'http'), COALESCE(country_code,''), created_at
FROM proxy_access_logs
ORDER BY created_at DESC
LIMIT 300`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type item struct {
		ID           int64     `json:"id"`
		Host         string    `json:"host"`
		Method       string    `json:"method"`
		Path         string    `json:"path"`
		ClientIP     string    `json:"client_ip"`
		TCPPeer      string    `json:"tcp_peer"`
		BackendName  string    `json:"backend_name"`
		UpstreamBase string    `json:"upstream_base"`
		Outcome      string    `json:"outcome"`
		Protocol     string    `json:"protocol"`
		CountryCode  string    `json:"country_code"`
		CreatedAt    time.Time `json:"created_at"`
	}
	var out []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.Host, &it.Method, &it.Path, &it.ClientIP, &it.TCPPeer, &it.BackendName, &it.UpstreamBase, &it.Outcome, &it.Protocol, &it.CountryCode, &it.CreatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}
