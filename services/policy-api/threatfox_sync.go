package main

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"fence/pkg/threatfeed"
)

var (
	errThreatFoxNoAuthKey = fmt.Errorf("threatfox: auth-key not configured")
	errThreatFeedNoSync   = fmt.Errorf("threat feed: sync not configured")
)

const (
	threatFoxIncrementalDays = 1
	threatFoxMaxExportBytes  = 96 << 20
)

func syncThreatFeedFromConfigRouter(ctx context.Context, db *sql.DB, cfg threatfeed.Config) error {
	if cfg.UsesFessFeed() {
		return syncFessFeed(ctx, db, cfg)
	}
	if cfg.UsesThreatFox() {
		return syncThreatFoxIncremental(ctx, db, cfg)
	}
	return syncThreatFeedFromConfig(ctx, db, cfg)
}

func syncThreatFoxFull(ctx context.Context, db *sql.DB, cfg threatfeed.Config) error {
	authKey := strings.TrimSpace(cfg.APIKey)
	if authKey == "" {
		return errThreatFoxNoAuthKey
	}
	now := time.Now().UTC()
	markThreatFeedAttempt(ctx, db, now)

	body, err := fetchThreatFoxFullExport(ctx, authKey, cfg)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	parsed, err := threatfeed.ParseThreatFoxCSV(body)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	_, err = replaceThreatFoxData(ctx, db, parsed, now)
	return err
}

func syncThreatFoxIncremental(ctx context.Context, db *sql.DB, cfg threatfeed.Config) error {
	authKey := strings.TrimSpace(cfg.APIKey)
	if authKey == "" {
		return errThreatFoxNoAuthKey
	}
	now := time.Now().UTC()
	markThreatFeedAttempt(ctx, db, now)

	body, err := fetchThreatFoxGetIOCs(ctx, authKey, threatFoxIncrementalDays, cfg)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	parsed, err := threatfeed.ParseThreatFoxAPI(body)
	if err != nil {
		if strings.Contains(err.Error(), "no IP/CIDR or file hash") {
			return recordThreatFeedSuccessNoRows(ctx, db, now)
		}
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	_, err = mergeThreatFoxData(ctx, db, parsed, now)
	return err
}

func fetchThreatFoxFullExport(ctx context.Context, authKey string, cfg threatfeed.Config) ([]byte, error) {
	urlStr := fmt.Sprintf(threatfeed.ThreatFoxFullExportV2, authKey)
	body, status, err := threatFeedHTTPGetOnce(ctx, urlStr, "", "", threatFeedRequestTimeout(cfg))
	if err == nil && status == http.StatusOK && len(body) > 2 && body[0] == 'P' && body[1] == 'K' {
		return unzipFirstCSV(body)
	}
	// fallback: query param style
	fallback := "https://threatfox-api.abuse.ch/files/exports/full.csv.zip?auth-key=" + authKey
	body, status, err = threatFeedHTTPGetOnce(ctx, fallback, "", "", threatFeedRequestTimeout(cfg))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("threatfox export HTTP %d", status)
	}
	return unzipFirstCSV(body)
}

func unzipFirstCSV(zipBytes []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("threatfox export: unzip: %w", err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := strings.ToLower(f.Name)
		if !strings.HasSuffix(name, ".csv") {
			continue
		}
		body, err := readZipEntryCSV(f)
		if err != nil {
			return nil, err
		}
		return body, nil
	}
	return nil, fmt.Errorf("threatfox export: no csv in archive")
}

func fetchThreatFoxGetIOCs(ctx context.Context, authKey string, days int, cfg threatfeed.Config) ([]byte, error) {
	if days < 1 {
		days = 1
	}
	if days > 7 {
		days = 7
	}
	payload, _ := json.Marshal(map[string]any{
		"query": "get_iocs",
		"days":  days,
	})
	reqCtx, cancel := context.WithTimeout(ctx, threatFeedRequestTimeout(cfg))
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, threatfeed.ThreatFoxAPIEndpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", authKey)
	req.Header.Set("User-Agent", "Fence-ThreatFeed/1.0")
	resp, err := threatFeedHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, threatFeedMaxPageBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatfox api HTTP %d: %s", resp.StatusCode, truncateForError(string(body), 200))
	}
	return body, nil
}

func threatFeedRequestTimeout(cfg threatfeed.Config) time.Duration {
	to := cfg.HTTPTimeoutSec
	if to <= 0 {
		to = 300
	}
	if cfg.UsesThreatFox() && to < 300 {
		to = 300
	}
	return time.Duration(to) * time.Second
}

func markThreatFeedAttempt(ctx context.Context, db *sql.DB, now time.Time) {
	_, _ = db.ExecContext(ctx, `
UPDATE threat_feed_sync_state SET last_attempt_at = $1 WHERE singleton = 'global'
`, now)
}

func replaceThreatFeedIndicators(ctx context.Context, db *sql.DB, inds []string, now time.Time) (int, error) {
	if len(inds) == 0 {
		detail := "no valid IP/CIDR indicators"
		recordThreatFeedFail(ctx, db, detail)
		return 0, fmt.Errorf("%s", detail)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM threat_feed_indicators`); err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return 0, err
	}
	for _, s := range inds {
		if _, err := tx.ExecContext(ctx, `INSERT INTO threat_feed_indicators(indicator) VALUES ($1)`, s); err != nil {
			recordThreatFeedFail(ctx, db, err.Error())
			return 0, err
		}
	}
	if err := finishThreatFeedSyncTx(ctx, tx, len(inds), now); err != nil {
		return 0, err
	}
	return len(inds), nil
}

func replaceThreatFoxData(ctx context.Context, db *sql.DB, p threatfeed.ThreatFoxParsed, now time.Time) (int, error) {
	if p.Total() == 0 {
		detail := "no valid IP/CIDR or file hash indicators"
		recordThreatFeedFail(ctx, db, detail)
		return 0, fmt.Errorf("%s", detail)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM threat_feed_indicators`); err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return 0, err
	}
	for _, s := range p.IPs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO threat_feed_indicators(indicator) VALUES ($1)`, s); err != nil {
			recordThreatFeedFail(ctx, db, err.Error())
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM threat_feed_file_hashes`); err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return 0, err
	}
	for _, h := range p.Hashes {
		alg := hashAlgForHex(h)
		if _, err := tx.ExecContext(ctx, `INSERT INTO threat_feed_file_hashes(hash, hash_alg) VALUES ($1, $2)`, h, alg); err != nil {
			recordThreatFeedFail(ctx, db, err.Error())
			return 0, err
		}
	}
	if err := finishThreatFeedSyncTx(ctx, tx, p.Total(), now); err != nil {
		return 0, err
	}
	return p.Total(), nil
}

func hashAlgForHex(h string) string {
	if len(h) == 32 {
		return "md5"
	}
	return "sha256"
}

func readZipEntryCSV(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, threatFoxMaxExportBytes))
}

func mergeThreatFeedIndicators(ctx context.Context, db *sql.DB, inds []string, now time.Time) (int, error) {
	if len(inds) == 0 {
		return 0, recordThreatFeedSuccessNoRows(ctx, db, now)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	added := 0
	for _, s := range inds {
		res, err := tx.ExecContext(ctx, `
INSERT INTO threat_feed_indicators(indicator) VALUES ($1)
ON CONFLICT (indicator) DO NOTHING`, s)
		if err != nil {
			recordThreatFeedFail(ctx, db, err.Error())
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}
	if err := finishThreatFeedSyncTx(ctx, tx, added, now); err != nil {
		return 0, err
	}
	return added, nil
}

func mergeThreatFoxData(ctx context.Context, db *sql.DB, p threatfeed.ThreatFoxParsed, now time.Time) (int, error) {
	if p.Total() == 0 {
		return 0, recordThreatFeedSuccessNoRows(ctx, db, now)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	added := 0
	for _, s := range p.IPs {
		res, err := tx.ExecContext(ctx, `
INSERT INTO threat_feed_indicators(indicator) VALUES ($1)
ON CONFLICT (indicator) DO NOTHING`, s)
		if err != nil {
			recordThreatFeedFail(ctx, db, err.Error())
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}
	for _, h := range p.Hashes {
		res, err := tx.ExecContext(ctx, `
INSERT INTO threat_feed_file_hashes(hash, hash_alg) VALUES ($1, $2)
ON CONFLICT (hash) DO NOTHING`, h, hashAlgForHex(h))
		if err != nil {
			recordThreatFeedFail(ctx, db, err.Error())
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}
	if err := finishThreatFeedSyncTx(ctx, tx, added, now); err != nil {
		return 0, err
	}
	return added, nil
}

func finishThreatFeedSyncTx(ctx context.Context, tx *sql.Tx, rowsIngested int, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE threat_feed_sync_state SET
  last_success_at = $1,
  last_error = '',
  rows_ingested = $2
WHERE singleton = 'global'
`, now, rowsIngested); err != nil {
		return err
	}
	return tx.Commit()
}

func recordThreatFeedSuccessNoRows(ctx context.Context, db *sql.DB, now time.Time) error {
	_, err := db.ExecContext(ctx, `
UPDATE threat_feed_sync_state SET
  last_success_at = $1,
  last_error = '',
  rows_ingested = 0
WHERE singleton = 'global'
`, now)
	return err
}

func threatFeedIndicatorCount(ctx context.Context, db *sql.DB) (int, error) {
	var cnt int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM threat_feed_indicators`).Scan(&cnt)
	return cnt, err
}

func threatFeedHashCount(ctx context.Context, db *sql.DB) (int, error) {
	var cnt int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM threat_feed_file_hashes`).Scan(&cnt)
	return cnt, err
}

func runThreatFeedBootstrap(ctx context.Context, db *sql.DB, rdb *redis.Client) {
	time.Sleep(12 * time.Second)
	bctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()

	cfg, err := loadThreatFeedConfig(bctx, db)
	if err != nil || !cfg.Enabled || !cfg.UsesThreatFox() || strings.TrimSpace(cfg.APIKey) == "" {
		return
	}
	ipCnt, err := threatFeedIndicatorCount(bctx, db)
	if err != nil {
		return
	}
	hashCnt, err := threatFeedHashCount(bctx, db)
	if err != nil || (ipCnt > 0 || hashCnt > 0) {
		return
	}
	log.Printf("threatfox: blocklist empty — starting full export bootstrap")
	if err := syncThreatFoxFull(bctx, db, cfg); err != nil {
		log.Printf("threatfox bootstrap: %v", err)
		return
	}
	_ = rdb.Publish(bctx, "threat_feed_updated", `{"source":"threatfox_bootstrap"}`).Err()
	log.Printf("threatfox bootstrap: complete")
}

func truncateForError(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
