package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"fence/pkg/threatfeed"
)

var errThreatFeedSkipped = errors.New("threat feed disabled or missing feed_url")

const (
	threatFeedMaxPageBytes   = 64 << 20
	threatFeedQFeedsPageSize = 4000
	threatFeedQFeedsMaxPages = 999
)

// syncThreatFeedFromConfig downloads the feed, applies source filtering, replaces indicators.
func syncThreatFeedFromConfig(ctx context.Context, db *sql.DB, cfg threatfeed.Config) error {
	urlStr := strings.TrimSpace(cfg.FeedURL)
	if !cfg.Enabled || urlStr == "" {
		return errThreatFeedSkipped
	}

	now := time.Now().UTC()
	_, _ = db.ExecContext(ctx, `
UPDATE threat_feed_sync_state SET last_attempt_at = $1 WHERE singleton = 'global'
`, now)

	to := cfg.HTTPTimeoutSec
	if to <= 0 {
		to = 120
	}
	reqTimeout := time.Duration(to) * time.Second

	body, err := fetchThreatFeedHTTP(ctx, urlStr, cfg, reqTimeout)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}

	rows, err := threatfeed.ParseFeedBody(body, cfg.Format, cfg.CSVIndicatorCol, cfg.CSVSourceCol)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	allow := cfg.SourcesAllowlist()
	filtered := threatfeed.FilterBySources(rows, allow)
	rawInd := threatfeed.UniqueIndicators(filtered)
	inds := threatfeed.ValidIPCIDR(rawInd)
	if len(inds) == 0 {
		recordThreatFeedFail(ctx, db, "no valid IP/CIDR indicators after filtering")
		return errors.New("no valid indicators parsed")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM threat_feed_indicators`); err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}

	for _, s := range inds {
		if _, err := tx.ExecContext(ctx, `INSERT INTO threat_feed_indicators(indicator) VALUES ($1)`, s); err != nil {
			recordThreatFeedFail(ctx, db, err.Error())
			return err
		}
	}

	if _, err := tx.ExecContext(ctx, `
UPDATE threat_feed_sync_state SET
  last_success_at = $1,
  last_error = '',
  rows_ingested = $2
WHERE singleton = 'global'
`, now, len(inds)); err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}

	if err := tx.Commit(); err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	return nil
}

func fetchThreatFeedHTTP(ctx context.Context, urlStr string, cfg threatfeed.Config, reqTimeout time.Duration) ([]byte, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	apiKey := strings.TrimSpace(cfg.APIKey)
	hdr := strings.TrimSpace(cfg.APIKeyHeader)
	if isQFeedsAPIPHP(u) {
		return fetchQFeedsPaginated(ctx, urlStr, apiKey, hdr, reqTimeout)
	}
	body, status, err := threatFeedHTTPGet(ctx, urlStr, apiKey, hdr, reqTimeout)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, feedHTTPStatusError(status, body)
	}
	return body, nil
}

func isQFeedsAPIPHP(u *url.URL) bool {
	if u == nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	path := strings.ToLower(u.Path)
	return host == "api.qfeeds.com" && strings.HasSuffix(path, "api.php")
}

// fetchQFeedsPaginated mirrors the official integrations (page + limit, up to thousands of IOCs).
func fetchQFeedsPaginated(ctx context.Context, baseURLStr string, apiKey, apiKeyHeader string, reqTimeout time.Duration) ([]byte, error) {
	u, err := url.Parse(baseURLStr)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	var combined [][]byte
	var total int
	for page := 1; page <= threatFeedQFeedsMaxPages; page++ {
		q.Set("page", strconv.Itoa(page))
		q.Set("limit", strconv.Itoa(threatFeedQFeedsPageSize))
		u.RawQuery = q.Encode()
		pageURL := u.String()

		body, status, err := threatFeedHTTPGet(ctx, pageURL, apiKey, apiKeyHeader, reqTimeout)
		if err != nil {
			return nil, err
		}
		if status < 200 || status >= 300 {
			if page == 1 {
				return nil, feedHTTPStatusError(status, body)
			}
			break
		}
		body = bytes.TrimSpace(body)
		if len(body) == 0 {
			break
		}
		lines := countNonBlankLines(body)
		if lines == 0 {
			break
		}
		next := total + len(body)
		if next > threatFeedMaxPageBytes {
			return nil, fmt.Errorf("feed: total size exceeds %d bytes (qfeeds pagination)", threatFeedMaxPageBytes)
		}
		total = next
		combined = append(combined, body)
		if lines < threatFeedQFeedsPageSize {
			break
		}
	}
	if len(combined) == 0 {
		return nil, errors.New("feed: empty response from Q-Feeds")
	}
	return bytes.Join(combined, []byte{'\n'}), nil
}

func countNonBlankLines(body []byte) int {
	n := 0
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

func threatFeedHTTPGet(ctx context.Context, urlStr string, apiKey string, apiKeyHeader string, reqTimeout time.Duration) ([]byte, int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, reqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, 0, err
	}
	// CDN/WAF часто режет дефолтный Go UA; браузероподобный запрос совместим с api.qfeeds.com.
	req.Header.Set("User-Agent", "Fence-ThreatFeed/1 (+https://github.com/) Mozilla/5.0 compatible")
	req.Header.Set("Accept", "text/plain, text/csv, application/json;q=0.9, */*;q=0.8")
	if apiKey != "" && apiKeyHeader != "" {
		req.Header.Set(apiKeyHeader, apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, threatFeedMaxPageBytes))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func feedHTTPStatusError(status int, body []byte) error {
	s := strings.TrimSpace(string(body))
	ls := strings.ToLower(s)
	if len(s) > 512 {
		s = s[:512] + "…"
	}
	if status == http.StatusNotFound &&
		(strings.HasPrefix(ls, "<!doctype html") ||
			strings.HasPrefix(ls, "<html") ||
			strings.Contains(ls, "<h1>not found</h1>")) {
		return fmt.Errorf("feed HTTP 404: вернулась HTML-страница (часто неверный путь). Для Q-Feeds используйте https://api.qfeeds.com/api.php?feed_type=malware_ip&api_token=… (путь /feeds не подходит)")
	}
	return fmt.Errorf("feed http %d: %s", status, s)
}

func recordThreatFeedFail(ctx context.Context, db *sql.DB, msg string) {
	const maxErr = 2000
	if len(msg) > maxErr {
		msg = msg[:maxErr] + "…"
	}
	msg = strings.TrimSpace(msg)
	_, _ = db.ExecContext(ctx, `
UPDATE threat_feed_sync_state SET last_error = $1 WHERE singleton = 'global'
`, msg)
}
