package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/redis/go-redis/v9"
)

const (
	geoipMmdbFileName = "GeoLite2-Country.mmdb"
	geoipMaxBytes     = 100 << 20
)

func geoipDataDir() string {
	return strings.TrimSpace(getenv("FENCE_GEOIP_DATA_DIR", "/var/lib/fence/geoip"))
}

func geoipMmdbPath() string {
	return filepath.Join(geoipDataDir(), geoipMmdbFileName)
}

func ensureGeoIPDir() error {
	dir := geoipDataDir()
	return os.MkdirAll(dir, 0o755)
}

func validateGeoIPMMDB(path string) error {
	r, err := geoip2.Open(path)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = r.Country(net.ParseIP("8.8.8.8"))
	return err
}

func geoipMmdbFileMeta() (present bool, size int64, modRFC3339 string) {
	fi, err := os.Stat(geoipMmdbPath())
	if err != nil {
		return false, 0, ""
	}
	return true, fi.Size(), fi.ModTime().UTC().Format(time.RFC3339Nano)
}

func installGeoIPMMDB(ctx context.Context, db *sql.DB, rdb *redis.Client, body io.Reader, source string) error {
	if err := ensureGeoIPDir(); err != nil {
		return fmt.Errorf("geoip dir: %w", err)
	}
	final := geoipMmdbPath()
	tmp := final + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	n, err := io.Copy(f, io.LimitReader(body, geoipMaxBytes+1))
	_ = f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if n > geoipMaxBytes {
		_ = os.Remove(tmp)
		return fmt.Errorf("file exceeds max size (%d bytes)", geoipMaxBytes)
	}
	if n < 1024 {
		_ = os.Remove(tmp)
		return errors.New("file too small to be a valid MMDB")
	}
	if err := validateGeoIPMMDB(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("not a valid GeoIP2 Country database: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := setGeoIPInstalledAt(ctx, db, now); err != nil {
		return err
	}
	writeAuditLog(ctx, db, "system", "update", "geoip_mmdb", "global", nil, map[string]any{"bytes": n, "source": source})
	if err := rdb.Publish(ctx, "geoip_mmdb_updated", "{}").Err(); err != nil {
		return fmt.Errorf("redis publish: %w", err)
	}
	return nil
}

func setGeoIPInstalledAt(ctx context.Context, db *sql.DB, rfc string) error {
	_, err := db.ExecContext(ctx, `
UPDATE malware_settings
SET config = jsonb_set(config, '{geoip,mmdb_last_installed_at}', to_jsonb($1::text), true),
    updated_at = NOW()
WHERE singleton = 'global'`, rfc)
	return err
}

func forbiddenGeoFetchIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 0.0.0.0/8, etc.
		if ip4[0] == 0 {
			return true
		}
	}
	return false
}

func validateGeoFetchURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("invalid url")
	}
	if strings.ToLower(u.Scheme) != "https" {
		return nil, errors.New("only https URLs are allowed")
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "localhost" || host == "metadata.google.internal" {
		return nil, errors.New("host not allowed")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("dns: %w", err)
	}
	if len(ips) == 0 {
		return nil, errors.New("host resolves to no addresses")
	}
	for _, ip := range ips {
		if forbiddenGeoFetchIP(ip) {
			return nil, fmt.Errorf("resolved address %s is not allowed (private/internal)", ip)
		}
	}
	return u, nil
}

func postGeoIPMMDBUpload(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(geoipMaxBytes + (1 << 20)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "multipart parse failed: " + err.Error()})
		return
	}
	fh, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing form field \"file\""})
		return
	}
	defer fh.Close()
	if err := installGeoIPMMDB(r.Context(), db, rdb, fh, "upload"); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": true})
}

type geoipFetchRequest struct {
	URL string `json:"url"`
}

func postGeoIPMMDBFetch(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req geoipFetchRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	u := strings.TrimSpace(req.URL)
	if u == "" {
		cfg, err := loadMalwareConfig(r.Context(), db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		u = strings.TrimSpace(cfg.GeoIP.MmdbSourceURL)
	}
	parsed, err := validateGeoFetchURL(u)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	client := &http.Client{Timeout: 15 * time.Minute}
	resp, err := client.Get(parsed.String())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "download failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("HTTP %d", resp.StatusCode)})
		return
	}
	if err := installGeoIPMMDB(r.Context(), db, rdb, resp.Body, "url"); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": true})
}
