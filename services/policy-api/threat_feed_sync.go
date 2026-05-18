package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"fence/pkg/threatfeed"
)

var errThreatFeedSkipped = errors.New("threat feed disabled or missing feed_url")
var errThreatFeedMissingURL = errors.New("threat feed missing feed_url")

const (
	threatFeedMaxPageBytes      = 64 << 20
	threatFeedQFeedsPageSize    = 4000
	threatFeedQFeedsMaxPages    = 999
	threatFeedQFeedsPagePause   = 150 * time.Millisecond
	threatFeedHTTPMaxAttempts   = 4
)

var threatFeedHTTPClient = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          8,
		IdleConnTimeout:       60 * time.Second,
	},
}

// syncThreatFeedFromConfig downloads the feed, applies source filtering, replaces indicators.
func syncThreatFeedFromConfig(ctx context.Context, db *sql.DB, cfg threatfeed.Config) error {
	urlStr := strings.TrimSpace(cfg.FeedURL)
	if urlStr == "" {
		return errThreatFeedMissingURL
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
	_, err = ingestThreatFeedBody(ctx, db, body, cfg, now)
	return err
}

// ingestThreatFeedTXT replaces indicators from a plain-text list (one IP or CIDR per line).
func ingestThreatFeedTXT(ctx context.Context, db *sql.DB, body []byte) (int, error) {
	now := time.Now().UTC()
	_, _ = db.ExecContext(ctx, `
UPDATE threat_feed_sync_state SET last_attempt_at = $1 WHERE singleton = 'global'
`, now)
	cfg := threatfeed.Config{Format: "plain"}
	return ingestThreatFeedBody(ctx, db, body, cfg, now)
}

func ingestThreatFeedBody(ctx context.Context, db *sql.DB, body []byte, cfg threatfeed.Config, now time.Time) (int, error) {
	rows, err := threatfeed.ParseFeedBody(body, cfg.Format, cfg.CSVIndicatorCol, cfg.CSVSourceCol)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return 0, err
	}
	allow := cfg.SourcesAllowlist()
	filtered := threatfeed.FilterBySources(rows, allow)
	rawInd := threatfeed.UniqueIndicators(filtered)
	inds := threatfeed.ValidIPCIDR(rawInd)
	if len(inds) == 0 {
		detail := fmt.Sprintf(
			"no valid IP/CIDR after pipeline: parsed_rows=%d after_source_filter=%d unique=%d (plain feeds like Q-Feeds have no source column — leave «sources» empty; use full IP feed not diff-only)",
			len(rows), len(filtered), len(rawInd),
		)
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

	if _, err := tx.ExecContext(ctx, `
UPDATE threat_feed_sync_state SET
  last_success_at = $1,
  last_error = '',
  rows_ingested = $2
WHERE singleton = 'global'
`, now, len(inds)); err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return 0, err
	}
	return len(inds), nil
}

// normalizeAPIQFeedsURL fixes common portal typos/mirrors so sync works against the real endpoint.
//
//	api.qfeeds.com/, /feeds → /api.php (documented integrations use api.php; /feeds often returns HTML 404).
//	Query typo "limit100000" instead of limit=100000 → limit=100000.
//	cfg.api_key → api_token query parameter when the URL does not already contain api_token.
func normalizeAPIQFeedsURL(urlStr string, apiKey string) string {
	urlStr = strings.TrimSpace(urlStr)
	u, err := url.Parse(urlStr)
	if err != nil || u.Hostname() == "" {
		return urlStr
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host != "api.qfeeds.com" {
		return urlStr
	}
	pathTrim := strings.Trim(strings.ToLower(u.Path), "/")
	if pathTrim == "" || pathTrim == "feeds" {
		u.Path = "/api.php"
	}
	q := u.Query()
	if strings.TrimSpace(q.Get("api_token")) == "" && strings.TrimSpace(apiKey) != "" {
		q.Set("api_token", strings.TrimSpace(apiKey))
	}
	if strings.TrimSpace(q.Get("feed_type")) == "" {
		q.Set("feed_type", "malware_ip")
	}
	if strings.TrimSpace(q.Get("type")) == "" {
		q.Set("type", "text")
	}
	if strings.TrimSpace(q.Get("ipv6")) == "" {
		q.Set("ipv6", "0")
	}
	hasExplicitLimit := strings.TrimSpace(q.Get("limit")) != ""
	var badLimitKeys []string
	var typoLimitDigits string
	for k := range q {
		kl := strings.ToLower(strings.TrimSpace(k))
		if kl == "limit" {
			continue
		}
		if !strings.HasPrefix(kl, "limit") {
			continue
		}
		digits := kl[len("limit"):]
		if digits == "" {
			continue
		}
		if _, err := strconv.Atoi(digits); err != nil {
			continue
		}
		badLimitKeys = append(badLimitKeys, k)
		if typoLimitDigits == "" {
			typoLimitDigits = digits
		}
	}
	for _, k := range badLimitKeys {
		q.Del(k)
	}
	if !hasExplicitLimit && typoLimitDigits != "" {
		q.Set("limit", typoLimitDigits)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func fetchThreatFeedHTTP(ctx context.Context, urlStr string, cfg threatfeed.Config, reqTimeout time.Duration) ([]byte, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	urlStr = normalizeAPIQFeedsURL(urlStr, apiKey)
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	hdr := strings.TrimSpace(cfg.APIKeyHeader)
	if isQFeedsAPIPHP(u) {
		return fetchQFeedsPaginated(ctx, urlStr, qFeedsHeaderAPIKey(apiKey, hdr), qFeedsHeaderName(apiKey, hdr), reqTimeout)
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

func qFeedsHeaderName(apiKey, apiKeyHeader string) string {
	if strings.TrimSpace(apiKey) == "" {
		return ""
	}
	// Q-Feeds official integrations authenticate with api_token query parameter.
	// Avoid sending a raw token as Authorization (the default UI header), which some CDNs/APIs reject.
	if strings.EqualFold(strings.TrimSpace(apiKeyHeader), "Authorization") {
		return ""
	}
	return strings.TrimSpace(apiKeyHeader)
}

func qFeedsHeaderAPIKey(apiKey, apiKeyHeader string) string {
	if qFeedsHeaderName(apiKey, apiKeyHeader) == "" {
		return ""
	}
	return strings.TrimSpace(apiKey)
}

// fetchQFeedsPaginated mirrors the official integrations (page + limit, up to thousands of IOCs).
func fetchQFeedsPaginated(ctx context.Context, baseURLStr string, apiKey, apiKeyHeader string, reqTimeout time.Duration) ([]byte, error) {
	u, err := url.Parse(baseURLStr)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	// Official Q-Feeds integrations paginate with page+limit only; download=1 can trigger a single huge response and RST from CDN.
	q.Del("download")
	var combined [][]byte
	var total int
	for page := 1; page <= threatFeedQFeedsMaxPages; page++ {
		if page > 1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(threatFeedQFeedsPagePause):
			}
		}
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
	var lastErr error
	for attempt := 1; attempt <= threatFeedHTTPMaxAttempts; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(backoff):
			}
		}
		body, status, err := threatFeedHTTPGetOnce(ctx, urlStr, apiKey, apiKeyHeader, reqTimeout)
		if err != nil {
			lastErr = err
			if attempt < threatFeedHTTPMaxAttempts && threatFeedHTTPRetryable(err) {
				continue
			}
			return nil, 0, err
		}
		if attempt < threatFeedHTTPMaxAttempts && threatFeedHTTPRetryStatus(status) {
			lastErr = fmt.Errorf("feed http %d", status)
			continue
		}
		return body, status, nil
	}
	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, errors.New("feed: request failed after retries")
}

func threatFeedHTTPGetOnce(ctx context.Context, urlStr string, apiKey string, apiKeyHeader string, reqTimeout time.Duration) ([]byte, int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, reqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Fence-ThreatFeed/1.0")
	req.Header.Set("Accept", "text/plain, text/csv, application/json;q=0.9, */*;q=0.8")
	req.Header.Set("Connection", "close")
	if apiKey != "" && apiKeyHeader != "" {
		req.Header.Set(apiKeyHeader, apiKey)
	}
	resp, err := threatFeedHTTPClient.Do(req)
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

func threatFeedHTTPRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "eof") ||
		strings.Contains(s, "timeout") ||
		strings.Contains(s, "tls handshake")
}

func threatFeedHTTPRetryStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
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
	if status == http.StatusNotFound {
		return fmt.Errorf("feed HTTP 404: %s", s)
	}
	return fmt.Errorf("feed http %d: %s", status, s)
}

func recordThreatFeedFail(ctx context.Context, db *sql.DB, msg string) {
	const maxErr = 2000
	msg = sanitizeThreatFeedError(msg)
	if len(msg) > maxErr {
		msg = msg[:maxErr] + "…"
	}
	msg = strings.TrimSpace(msg)
	_, _ = db.ExecContext(ctx, `
UPDATE threat_feed_sync_state SET last_error = $1 WHERE singleton = 'global'
`, msg)
}

var threatFeedAPITokenRe = regexp.MustCompile(`(?i)(api_token=)[^&\s"']+`)

func sanitizeThreatFeedError(msg string) string {
	return threatFeedAPITokenRe.ReplaceAllString(msg, `${1}***`)
}
