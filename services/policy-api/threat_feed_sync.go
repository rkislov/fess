package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"fence/pkg/threatfeed"
)

var errThreatFeedSkipped = errors.New("threat feed disabled or missing feed_url")

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
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(to)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, urlStr, nil)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	apiKey := strings.TrimSpace(cfg.APIKey)
	hdr := strings.TrimSpace(cfg.APIKeyHeader)
	if apiKey != "" && hdr != "" {
		req.Header.Set(hdr, apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("feed http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
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
