package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

func runSIEMExporter(ctx context.Context, db *sql.DB) {
	for {
		settings, err := loadSIEMSettings(ctx, db)
		if err != nil {
			log.Printf("siem export: load settings: %v", err)
			sleepCtx(ctx, 30*time.Second)
			continue
		}
		interval := time.Duration(settings.PollIntervalSec) * time.Second
		if interval < 5*time.Second {
			interval = 5 * time.Second
		}
		if settings.Enabled && strings.TrimSpace(settings.Host) != "" {
			if err := exportSIEMBatch(ctx, db, settings); err != nil {
				log.Printf("siem export: %v", err)
			}
		}
		sleepCtx(ctx, interval)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func exportSIEMBatch(ctx context.Context, db *sql.DB, cfg siemExportSettings) error {
	addr := net.JoinHostPort(strings.TrimSpace(cfg.Host), strconv.Itoa(cfg.Port))
	var conn net.Conn
	var err error
	if cfg.Protocol == "tcp" {
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
	} else {
		conn, err = net.DialTimeout("udp", addr, 5*time.Second)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	if cfg.ExportWAFLogs {
		if err := exportWAFLogsCEF(ctx, db, conn, cfg); err != nil {
			return err
		}
	}
	if cfg.ExportProxyLogs {
		if err := exportProxyLogsCEF(ctx, db, conn, cfg); err != nil {
			return err
		}
	}
	if cfg.ExportAuditLogs {
		if err := exportAuditLogsCEF(ctx, db, conn, cfg); err != nil {
			return err
		}
	}
	return nil
}

func sendSIEMLine(conn net.Conn, cfg siemExportSettings, cefBody string) error {
	var msg string
	if cfg.Format == "syslog" {
		pri := 134 // local0.info
		ts := time.Now().UTC().Format(time.RFC3339)
		msg = fmt.Sprintf("<%d>1 %s fence-siem - - - - %s", pri, ts, cefBody)
	} else {
		msg = cefBody
	}
	_, err := conn.Write([]byte(msg + "\n"))
	return err
}

func formatCEF(vendor, product, version, signature, name string, severity int, extensions map[string]string) string {
	ext := make([]string, 0, len(extensions))
	for k, v := range extensions {
		v = strings.ReplaceAll(v, "\\", "\\\\")
		v = strings.ReplaceAll(v, "=", "\\=")
		ext = append(ext, k+"="+v)
	}
	return fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
		escapeCEF(vendor), escapeCEF(product), escapeCEF(version),
		escapeCEF(signature), escapeCEF(name), severity, strings.Join(ext, " "))
}

func escapeCEF(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func exportWAFLogsCEF(ctx context.Context, db *sql.DB, conn net.Conn, cfg siemExportSettings) error {
	last, err := getSIEMCursor(ctx, db, "waf_logs")
	if err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, `
SELECT id, request_id, action, source_ip, method, path, host, created_at
FROM waf_logs WHERE id > $1 ORDER BY id ASC LIMIT 500`, last)
	if err != nil {
		return err
	}
	defer rows.Close()
	var maxID int64 = last
	for rows.Next() {
		var id int64
		var requestID, action, srcIP, method, path, host string
		var created time.Time
		if err := rows.Scan(&id, &requestID, &action, &srcIP, &method, &path, &host, &created); err != nil {
			return err
		}
		cef := formatCEF(cfg.DeviceVendor, cfg.DeviceProduct, cfg.DeviceVersion, action, "WAF event", 5, map[string]string{
			"requestId": requestID,
			"src":       srcIP,
			"request":   method + " " + path,
			"dvchost":   host,
			"rt":        created.UTC().Format(time.RFC3339),
		})
		if err := sendSIEMLine(conn, cfg, cef); err != nil {
			return err
		}
		if id > maxID {
			maxID = id
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if maxID > last {
		return setSIEMCursor(ctx, db, "waf_logs", maxID)
	}
	return nil
}

func exportProxyLogsCEF(ctx context.Context, db *sql.DB, conn net.Conn, cfg siemExportSettings) error {
	last, err := getSIEMCursor(ctx, db, "proxy_access_logs")
	if err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, `
SELECT id, client_ip, method, path, host, outcome, created_at
FROM proxy_access_logs WHERE id > $1 ORDER BY id ASC LIMIT 500`, last)
	if err != nil {
		return err
	}
	defer rows.Close()
	var maxID int64 = last
	for rows.Next() {
		var id int64
		var srcIP, method, path, host, outcome string
		var created time.Time
		if err := rows.Scan(&id, &srcIP, &method, &path, &host, &outcome, &created); err != nil {
			return err
		}
		sev := 3
		if outcome != "proxied" {
			sev = 6
		}
		cef := formatCEF(cfg.DeviceVendor, cfg.DeviceProduct, cfg.DeviceVersion, outcome, "Proxy access", sev, map[string]string{
			"src":     srcIP,
			"request": method + " " + path,
			"dvchost": host,
			"outcome": outcome,
			"rt":      created.UTC().Format(time.RFC3339),
		})
		if err := sendSIEMLine(conn, cfg, cef); err != nil {
			return err
		}
		if id > maxID {
			maxID = id
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if maxID > last {
		return setSIEMCursor(ctx, db, "proxy_access_logs", maxID)
	}
	return nil
}

func exportAuditLogsCEF(ctx context.Context, db *sql.DB, conn net.Conn, cfg siemExportSettings) error {
	last, err := getSIEMCursor(ctx, db, "audit_logs")
	if err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, `
SELECT id, actor, operation, entity_type, entity_id, created_at
FROM audit_logs WHERE id > $1 ORDER BY id ASC LIMIT 500`, last)
	if err != nil {
		return err
	}
	defer rows.Close()
	var maxID int64 = last
	for rows.Next() {
		var id int64
		var actor, op, entityType, entityID string
		var created time.Time
		if err := rows.Scan(&id, &actor, &op, &entityType, &entityID, &created); err != nil {
			return err
		}
		cef := formatCEF(cfg.DeviceVendor, cfg.DeviceProduct, cfg.DeviceVersion, op, "Audit", 4, map[string]string{
			"suser":   actor,
			"cs1":     entityType,
			"cs1Label": "entity",
			"cs2":     entityID,
			"rt":      created.UTC().Format(time.RFC3339),
		})
		if err := sendSIEMLine(conn, cfg, cef); err != nil {
			return err
		}
		if id > maxID {
			maxID = id
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if maxID > last {
		return setSIEMCursor(ctx, db, "audit_logs", maxID)
	}
	return nil
}
