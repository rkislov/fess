package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"fence/pkg/auth"
)

type siemExportSettings struct {
	Enabled          bool   `json:"enabled"`
	Format           string `json:"format"`
	Host             string `json:"host"`
	Port             int    `json:"port"`
	Protocol         string `json:"protocol"`
	TLS              bool   `json:"tls"`
	ExportWAFLogs    bool   `json:"export_waf_logs"`
	ExportProxyLogs  bool   `json:"export_proxy_logs"`
	ExportAuditLogs  bool   `json:"export_audit_logs"`
	DeviceVendor     string `json:"device_vendor"`
	DeviceProduct    string `json:"device_product"`
	DeviceVersion    string `json:"device_version"`
	PollIntervalSec  int    `json:"poll_interval_sec"`
}

func loadSIEMSettings(ctx context.Context, db *sql.DB) (siemExportSettings, error) {
	var s siemExportSettings
	err := db.QueryRowContext(ctx, `
SELECT enabled, format, host, port, protocol, tls,
       export_waf_logs, export_proxy_logs, export_audit_logs,
       device_vendor, device_product, device_version, poll_interval_sec
FROM siem_export_settings WHERE singleton = 'global'`).Scan(
		&s.Enabled, &s.Format, &s.Host, &s.Port, &s.Protocol, &s.TLS,
		&s.ExportWAFLogs, &s.ExportProxyLogs, &s.ExportAuditLogs,
		&s.DeviceVendor, &s.DeviceProduct, &s.DeviceVersion, &s.PollIntervalSec,
	)
	return s, err
}

func saveSIEMSettings(ctx context.Context, db *sql.DB, s siemExportSettings) error {
	if s.Format == "" {
		s.Format = "cef"
	}
	if s.Protocol == "" {
		s.Protocol = "udp"
	}
	if s.Port <= 0 {
		s.Port = 514
	}
	if s.PollIntervalSec <= 0 {
		s.PollIntervalSec = 30
	}
	_, err := db.ExecContext(ctx, `
UPDATE siem_export_settings SET
  enabled = $1, format = $2, host = $3, port = $4, protocol = $5, tls = $6,
  export_waf_logs = $7, export_proxy_logs = $8, export_audit_logs = $9,
  device_vendor = $10, device_product = $11, device_version = $12,
  poll_interval_sec = $13, updated_at = NOW()
WHERE singleton = 'global'`,
		s.Enabled, s.Format, strings.TrimSpace(s.Host), s.Port, s.Protocol, s.TLS,
		s.ExportWAFLogs, s.ExportProxyLogs, s.ExportAuditLogs,
		s.DeviceVendor, s.DeviceProduct, s.DeviceVersion, s.PollIntervalSec,
	)
	return err
}

func siemExportSettingsHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || !auth.CanAdmin(claims.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		s, err := loadSIEMSettings(r.Context(), db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, s)
	case http.MethodPut:
		var incoming siemExportSettings
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if incoming.Format != "cef" && incoming.Format != "syslog" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format must be cef or syslog"})
			return
		}
		if incoming.Protocol != "udp" && incoming.Protocol != "tcp" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocol must be udp or tcp"})
			return
		}
		if err := saveSIEMSettings(r.Context(), db, incoming); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeAuditLog(r.Context(), db, claims.Username, "update", "siem_export_settings", "global", nil, map[string]any{"enabled": incoming.Enabled, "host": incoming.Host})
		writeJSON(w, http.StatusOK, incoming)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func getSIEMCursor(ctx context.Context, db *sql.DB, stream string) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, `SELECT last_id FROM siem_export_cursors WHERE stream = $1`, stream).Scan(&id)
	return id, err
}

func setSIEMCursor(ctx context.Context, db *sql.DB, stream string, id int64) error {
	_, err := db.ExecContext(ctx, `
INSERT INTO siem_export_cursors(stream, last_id) VALUES ($1, $2)
ON CONFLICT (stream) DO UPDATE SET last_id = EXCLUDED.last_id`, stream, id)
	return err
}
